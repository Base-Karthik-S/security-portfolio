# Step 5 — Ship Windows + Sysmon logs into Elastic via Fleet

**Goal:** Add a **Fleet Server** to the ELK01 stack and enroll an **Elastic Agent** on
DC01 so Windows Security events and Sysmon operational logs flow into Elasticsearch.

**Result:** DC01 telemetry (incl. logon `4624` and Sysmon EID 1/10) searchable in Kibana,
setting up Step 6 (find your own logon event).

> This runbook reflects the **working** build order after debugging. The key lesson:
> **provision Fleet in Kibana first, then start the Fleet Server container** — starting
> the container against a stack where Fleet hasn't initialized causes a 2-minute
> enrollment timeout. See the **Gotchas** section at the end; those failure modes are
> exactly what an interviewer will ask you to explain.

---

## Architecture (who talks to whom)

```
 DC01 (192.168.64.10, Windows)                 ELK01 (192.168.64.20, Ubuntu + Docker)
 +---------------------------+                 +---------------------------------------+
 | Elastic Agent             |  enroll+comms   | fleet-server  (container, :8220)       |
 |  - System integration     | ---8220 TLS---> |   +- control plane: manages agents     |
 |  - Windows integration     |                 |                                        |
 |    (incl. Sysmon)          |  ship data      | es01  (container, :9200 TLS)           |
 |                            | ---9200 TLS---> | kibana (container, :5601 HTTP)         |
 +---------------------------+                 +---------------------------------------+
```

Two **separate** connections from every agent: **8220** to Fleet Server (control plane)
and **9200** to Elasticsearch (data plane). Both target ELK01's LAN IP `192.168.64.20`,
so both server certs must be valid for that IP — handled in the compose `setup` step.

The Fleet Server container is **itself an Elastic Agent**, so it also uses the 9200 data
plane to ship its own monitoring data. That detail matters — see Gotcha #4.

---

## 0. Pre-flight

- **Bump ELK01 RAM to 5-6 GB.** Power the VM OFF in VMware, raise memory, power on.
  Fleet Server + agent add ~500 MB-1 GB; 4 GB gets tight. Heap stays `ES_HEAP=1500m`.
- Confirm es01 + kibana healthy: `docker compose ps`.
- Confirm DC01 <-> ELK01 reachability from DC01 PowerShell:
  `Test-NetConnection 192.168.64.20 -Port 5601` should succeed.

---

## 1. Update `.env`

Append (see `.env.example` for placement). Generate the three encryption keys with
`openssl rand -hex 32` (run it three times):

```dotenv
# Port to expose Fleet Server on the ELK01 host
FLEET_PORT=8220

# Service token for Fleet Server -> Elasticsearch. Generated in step 3; paste here.
FLEET_SERVER_SERVICE_TOKEN=

# How the host browser reaches Kibana (also used by Fleet). ELK01's IP.
KIBANA_PUBLIC_URL=http://192.168.64.20:5601

# Kibana encryption keys - REQUIRED for Fleet. Each = `openssl rand -hex 32`.
XPACK_ENCRYPTEDSAVEDOBJECTS_KEY=<32-byte hex>
XPACK_SECURITY_ENCRYPTIONKEY=<32-byte hex>
XPACK_REPORTING_ENCRYPTIONKEY=<32-byte hex>
```

> `.env` is git-ignored. Never commit the token or the encryption keys.

---

## 2. Regenerate certs so they cover ELK01's IP

The compose `setup` step adds `192.168.64.20` as a SAN to the **es01** cert and adds a
new **fleet-server** cert. `setup` only generates certs when they don't already exist,
so clear the old ones. The lab holds only test/marker data at this point:

```bash
docker compose down -v          # drops indices + certs (test data only)
docker compose up -d            # regenerates CA + es01 + fleet-server certs; starts es01 + kibana
docker compose ps               # wait for es01 AND kibana = healthy
```

---

## 3. Generate the Fleet Server service token

With es01 healthy, create a token for the built-in `elastic/fleet-server` service
account (run on ELK01, `elk/` dir). Use a **fresh token name** each attempt - a name can
only be created once:

```bash
source .env
curl -s -X POST --cacert <(docker compose exec -T es01 cat config/certs/ca/ca.crt) \
  -u "elastic:${ELASTIC_PASSWORD}" \
  "https://192.168.64.20:9200/_security/service/elastic/fleet-server/credential/token/fleet-token-1?pretty"
```

Copy the `value` field into `.env` as `FLEET_SERVER_SERVICE_TOKEN=...`.

**Do not start fleet-server yet** - provision Fleet in Kibana first (next step).

---

## 4. Provision Fleet in Kibana FIRST

Browse to `http://192.168.64.20:5601` -> **Management -> Fleet**.

1. **Settings -> Fleet Server hosts** -> ensure/add `https://192.168.64.20:8220`.
2. **Settings -> Outputs** -> edit the **default** Elasticsearch output:
   - Host: `https://192.168.64.20:9200`
   - **Advanced YAML** -> make the output trust the lab CA so agents (including the
     Fleet Server's own monitoring) validate ES over TLS. Paste the CA:
     ```yaml
     ssl:
       certificate_authorities:
         - |
           -----BEGIN CERTIFICATE-----
           <contents of ca/ca.crt>
           -----END CERTIFICATE-----
     ```
     Get the CA text with: `docker compose exec es01 cat config/certs/ca/ca.crt`.
   - **Lab shortcut** (equivalent, less fiddly): instead of the CA block, use
     `ssl.verification_mode: none`. Fine on the private NAT; same trade-off the lab
     already accepts for HTTP-to-Kibana.
3. **Agents tab -> Add Fleet Server** flow -> this creates the `fleet-server-policy`
   (with the Fleet Server integration) that the container will bind to. You can ignore
   the install snippet it shows - the container does the enrollment.

Confirm **Fleet -> Agent policies** now lists a policy containing the Fleet Server
integration.

---

## 5. Start the Fleet Server container

```bash
docker compose up -d --no-deps fleet-server
docker compose logs -f fleet-server | grep -v "Non-zero metrics"
```

Healthy looks like: `Running on policy with Fleet Server integration: fleet-server-policy`
and `state: HEALTHY`, with **no** repeating `x509` errors. In Kibana -> Fleet -> Agents the
Fleet Server agent should show **Healthy**.

> If it parks in `Created` on `docker compose up -d fleet-server`, that's the one-shot
> `setup` dependency gate - use `--no-deps` (above) to start just this service.

---

## 6. Create the DC01 agent policy + integrations

1. **Fleet -> Agent policies -> Create agent policy** -> name `dc01-windows`. Save.
2. Add integrations to it. Cleanest via **Integrations** catalog -> search -> **Add**, and
   on the "Where to add this integration?" screen choose **Existing hosts ->
   `dc01-windows`** (the default often creates a NEW policy - watch for that):
   - **System** - carries the Windows Security event log, incl. logon `4624`.
   - **Windows** - enable the **`sysmon_operational`** dataset to ingest
     `Microsoft-Windows-Sysmon/Operational` (your SwiftOnSecurity Sysmon events).

Reopen `dc01-windows` and confirm both integrations are listed under it. (No data flows
yet - there's no agent on DC01 until the next step.)

---

## 7. Install + enroll the Elastic Agent on DC01

**Fleet -> Agents -> Add agent** -> select `dc01-windows` -> **Windows**. Note the Fleet URL
(`https://192.168.64.20:8220`) and the **enrollment token** (Base64 - a trailing `==` is
normal; copy it whole).

Choose ONE trust method:

**Option A - `--insecure` (simplest).** Skips Fleet Server cert verification on the
private NAT.

**Option B - trust the CA (portfolio-clean).** Copy `ca/ca.crt` to DC01 and pass
`--certificate-authorities`. The IP SAN from step 2 makes this validate cleanly.

Copy the CA onto DC01 (Option B). Easiest robust way, in elevated PowerShell, pasting the
CA text from `docker compose exec es01 cat config/certs/ca/ca.crt`:

```powershell
New-Item -ItemType Directory -Force -Path C:\Elastic | Out-Null
@'
-----BEGIN CERTIFICATE-----
<paste full ca.crt contents>
-----END CERTIFICATE-----
'@ | Set-Content -Path C:\Elastic\ca.crt -Encoding ascii
Get-Content C:\Elastic\ca.crt   # verify clean BEGIN/END block
```

Then, elevated PowerShell on DC01 (version MUST match the stack = 9.4.3):

```powershell
Test-NetConnection 192.168.64.20 -Port 8220   # expect TcpTestSucceeded : True

$ver = "9.4.3"
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$ver-windows-x86_64.zip" -OutFile "elastic-agent.zip"
Expand-Archive .\elastic-agent.zip -DestinationPath .
cd ".\elastic-agent-$ver-windows-x86_64"

# Option B (CA trust):
.\elastic-agent.exe install `
  --url=https://192.168.64.20:8220 `
  --enrollment-token="<PASTE_TOKEN>" `
  --certificate-authorities=C:\Elastic\ca.crt

# Option A alternative: replace the last line with  --insecure
```

Accept the `[Y/n]` prompt (installs the `Elastic Agent` service). It enrolls and checks
in within seconds. In **Fleet -> Agents**, DC01 appears and goes **Healthy**.

---

## 8. Verify (Step 7 marker -> Step 6 milestone)

On DC01, generate markers:

```powershell
ping sysmonmarker-step7.invalid      # Sysmon EID 1 (process create), unique cmdline
```

Generate a logon `4624` - lock/unlock the console (Win+L -> sign back in), or:

```powershell
Start-Process cmd -Credential (Get-Credential)   # enter LAB\Administrator
```

In Kibana -> **Discover** (`logs-*` data view), wait ~30-60s, then search:

- `process.command_line : *sysmonmarker-step7*`  -> the Sysmon EID 1 event
- `event.code : "4624"` (narrow time to last 15 min) -> **your logon = Step 6 milestone**

---

## 9. Snapshot + commit

- VMware: snapshot DC01 `dc01-agent-enrolled`, ELK01 `elk-fleet-healthy`.
- Repo: commit this doc + a redacted Fleet **Agents** screenshot. Keep `.env`, token,
  keys, and certs git-ignored.

---

## Gotchas & the "why" (interview-ready notes)

These are the failure modes hit while standing this up. Being able to explain *why*
each one happens is a strong signal in an interview - it shows you understand the
control-plane / data-plane split and Elastic's security model, not just the happy path.

**1. Fleet needs a Kibana encryption key.**
*Symptom:* Kibana shows "Unable to initialize Fleet - Agent binary source needs
encrypted saved object api key to be set"; the Fleet Server container then times out
enrolling.
*Why:* Fleet stores enrollment tokens, agent policies, and output credentials as
**encrypted saved objects** in Kibana. Encryption requires a persistent key
(`xpack.encryptedSavedObjects.encryptionKey`). The base ES+Kibana stack runs fine
without it - Fleet is what makes it mandatory. Keys must be stable across restarts, or
previously-encrypted objects become unreadable.

**2. TLS certs must be valid for the IP agents actually connect to.**
*Symptom:* agent enrollment or data shipping fails with
`x509: certificate is valid for es01, localhost, not 192.168.64.20`.
*Why:* the containers talk to each other as `es01` / `fleet-server` on the Docker
network, but DC01 connects to `192.168.64.20`. A cert is only valid for the names/IPs in
its Subject Alternative Names. Adding `192.168.64.20` as a SAN to both es01 and
fleet-server certs is what lets an external agent validate them.

**3. The agent requires ABSOLUTE cert paths.**
*Symptom:* `Error: --certificate-authorities must be provided as an absolute path`
(container), or `open C:\Elastic\ca.crt: The system cannot find the file specified`
(Windows).
*Why:* the Elastic Agent resolves CA/cert paths strictly. Relative paths like
`certs/ca/ca.crt` are rejected; use the full container path
(`/usr/share/elastic-agent/certs/ca/ca.crt`) or the full Windows path. On Windows, also
watch for Notepad silently appending `.txt`.

**4. Control-plane healthy != data-plane healthy.**
*Symptom:* `docker compose ps` shows fleet-server **healthy**, but Kibana shows the agent
**Unhealthy** with repeating `x509: certificate signed by unknown authority`.
*Why:* the container healthcheck only pings Fleet Server's `/api/status` (the control
plane). But the Fleet Server container is also an Elastic Agent shipping its own
monitoring data to ES (the data plane) via the **Fleet default output**. If that output
doesn't trust the lab CA, every flush fails x509 and the agent rolls up to Unhealthy -
even though Fleet Server itself is fine. Fix is on the **output**, not the container:
trust the CA (or `ssl.verification_mode: none` for the lab).

**5. Build order matters: provision Fleet before starting the Fleet Server container.**
*Symptom:* fleet-server logs loop `Waiting on policy with Fleet Server integration` then
`timed out waiting for Fleet Server to start after 2m0s`.
*Why:* the container binds to `fleet-server-policy`. If Fleet hasn't been initialized in
Kibana and that policy doesn't exist yet, the container waits and times out. Provision
Fleet (or let Kibana create the policy) first, then start the container.

**6. `docker compose up -d` after a one-shot `setup` container.**
*Symptom:* fleet-server stuck in `Created`; `up` reports
`dependency setup failed to start: container elk-setup-1 exited (0)`.
*Why:* `setup` is a one-shot that exits 0 when done, but other services `depend_on` it
with `condition: service_healthy`. On a later `up`, that condition can't be satisfied.
Use `docker compose up -d --no-deps fleet-server` to start just the service.

---

### State after Step 5

- **DC01** - Elastic Agent enrolled (policy `dc01-windows`), shipping Security + Sysmon.
- **ELK01** - es01 + kibana + fleet-server, all TLS, certs valid for `192.168.64.20`,
  Kibana encryption keys set, Fleet default output trusts the lab CA.
- **Next:** Step 6 - find your own `4624` logon event in Kibana; commit README + network
  diagram + screenshot to close the Weeks 1-2 milestone.
