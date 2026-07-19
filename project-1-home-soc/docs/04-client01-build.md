# 04 — Add CLIENT01: a domain-joined Windows 11 endpoint

**Goal:** Add a Windows 11 Enterprise client to the lab, join it to `lab.local`, and
give it the same telemetry stack as DC01 (Sysmon + Elastic Agent) so it can serve as a
**realistic attack target** for Atomic Red Team and the first detections.

**Step in roadmap:** Project 1, **Week 3** — build the attack target first, then run
atomics against it. Follows Fleet enrolment on DC01 (`03-fleet-dc01.md`); precedes the
first detections + incident reports.

> **Why a client, and why phased.** A domain-joined endpoint is what a real intrusion
> lands on, so it's a better attack surface than the DC — and Weeks 4–5 AD tradecraft
> (Kerberoasting, spraying) needs a client anyway. This build is done **one phase per
> working session**. On a 16 GB host the discipline is to run VMs **in pairs**, never all
> three for long; the phases are ordered so DC01 and ELK01 are each needed at *different*
> moments (see the RAM plan).

> **Restructured to 4 phases.** The original seven-phase plan (create VM → install Win11 →
> static net → join → Sysmon → agent → verify) is now **four**: old phases 1–4 are merged
> into **Phase 1 — Build & join**, and Sysmon / Elastic Agent / Verify become **Phases 2 /
> 3 / 4**. Rationale: the heaviest moment in the build is the domain join, which needs only
> **DC01 (4 GB) + CLIENT01 (4 GB) = 8 GB** — comfortably under the 16 GB floor — so there was
> no RAM reason to split the build from the join.

---

## Architecture (where CLIENT01 fits)

```
 DC01 (192.168.64.10)            CLIENT01 (192.168.64.30)          ELK01 (192.168.64.20)
 Win Server 2025 / DC            Win 11 Enterprise                 Ubuntu + Docker
 lab.local, DNS                  Elastic Agent  --8220 TLS-->      fleet-server (:8220)
        ^                          - System (Security 4624)        es01 (:9200 TLS)
        |  auth / DNS              - Windows (sysmon_operational)   kibana (:5601)
        +---- domain join ---------+           --9200 TLS-->  ships data
                       all on VMware VMnet8 NAT  (192.168.64.0/24, gw .2)
```

CLIENT01 uses DC01 for DNS + domain auth, and ships telemetry to ELK01 exactly like DC01
does: control plane to Fleet on **8220**, data plane to Elasticsearch on **9200**, both TLS.

---

## Environment (locked)

| Attribute | Value |
|---|---|
| Hostname | `CLIENT01` |
| OS | Windows 11 Enterprise (eval, 90-day) |
| vCPU / RAM / Disk | 2 / 4 GB / 60 GB thin |
| Network (VMnet8) | IP `192.168.64.30` /24 · gateway `192.168.64.2` · DNS `192.168.64.10` (DC01) then `1.1.1.1` |
| Domain | `lab.local` (NetBIOS `LAB`); join as `LAB\Administrator` |
| Fleet policy | `client01-windows` — **System** (Windows Security incl. `4624`) + **Windows** (`sysmon_operational`) |
| Sysmon config | SwiftOnSecurity `sysmonconfig-export.xml` (same as DC01) |
| Agent / stack version | **9.4.3** — the agent version MUST match the stack |
| ECS host name | `host.name : "client01"` (lowercase in Kibana) |

---

## RAM plan (16 GB discipline)

The two things CLIENT01 depends on (the DC, the SIEM) are needed at different moments, so you
never need all three VMs running for long:

| Phase | VMs powered on | Why |
|---|---|---|
| **1 — Build & join** | CLIENT01 only; **+ DC01** for the join sub-step (ELK01 off) | Install + local config need nothing external; the join needs DNS + Kerberos from the DC (8 GB together) |
| **2 — Sysmon** | CLIENT01 only (DC01 + ELK01 off) | Purely local install — needs neither the DC nor the SIEM |
| **3 — Agent enrol** | **ELK01 + CLIENT01** (DC01 off) | Needs Fleet on ELK01; cached domain creds cover login |
| **4 — Verify** | ELK01 + CLIENT01 (**+ DC01** for a clean domain `4624`) | Confirm telemetry end-to-end |

Power the idle VM off before booting the third.

---

## Phase 1 — Build & join CLIENT01  ✓ complete

> Merged from the original phases 1–4. Ends with a verified domain member and a clean
> snapshot. Full session log with every gotcha: `04-client01-build-phase1.md`.

### 1.1 Create the VM (VMware Workstation Pro)

1. `File → New Virtual Machine` → **Typical** → **"I will install the operating system
   later."** (Skips Easy Install, which is flaky with Win11.)
2. Guest OS **Microsoft Windows**, Version **Windows 11 x64** — *this selection is what makes
   VMware provision UEFI + Secure Boot + TPM and prompt for encryption.*
3. Name **`CLIENT01`**. **Encryption page:** choose **"Only the files needed to support a TPM
   are encrypted,"** set a password, tick **Remember … in Credential Manager**, and store the
   password **out-of-band** (never in the repo).
4. Disk **60 GB**, thin (**do not** allocate all space now). **Customize Hardware:** Memory
   **4096 MB**, Processors **2**, Network Adapter **NAT** (= VMnet8), CD/DVD → **Use ISO** →
   Win11 Ent ISO, **Connect at power on** ticked.
5. Confirm `Options → Advanced` = **UEFI + Secure Boot** and a **TPM** device is present.

> **Normal, not a failure:** on first power-on you may see VMware's UEFI **boot manager** menu
> — the disk is empty and nothing bootable took over. It's the firmware asking what to boot.

### 1.2 Install Windows 11 Enterprise

1. At **"Press any key to boot from CD or DVD…"** press a key promptly (miss it → UEFI boot
   menu; pick the SATA CDROM entry there).
2. Region/keyboard **US** (matches the physical layout; avoids `\ | @ " #` mismatches).
   Product key → **"I don't have a product key"** → **Windows 11 Enterprise**.
3. **Custom: Install Windows only** → the 60 GB unallocated disk → let it partition and reboot.
4. **OOBE — create a LOCAL admin** (`labadmin`, password out-of-band), in order of preference:
   - **"Set up for work or school" → "Sign-in options" → "Domain join instead."**
   - If hidden on 24H2/25H2: **Shift+F10** → `start ms-cxh:localonly` (most reliable on current
     builds).
   - Last resort: disconnect the NIC to surface *"Continue with limited setup."*
5. First desktop → **VM → Install VMware Tools** → reboot (display scaling, clipboard, drivers,
   time-sync).

### 1.3 Static network + rename (DC01 can stay off)

Elevated PowerShell — adapter is usually `Ethernet0` (`Get-NetAdapter` to confirm):

```powershell
$if = "Ethernet0"
New-NetIPAddress -InterfaceAlias $if -IPAddress 192.168.64.30 -PrefixLength 24 -DefaultGateway 192.168.64.2
Set-DnsClientServerAddress -InterfaceAlias $if -ServerAddresses 192.168.64.10,1.1.1.1
```

> **DNS must point at the DC.** `192.168.64.10` has to be the first resolver or the join can't
> find `lab.local`'s SRV records.

Verify, then rename + reboot:

```powershell
Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength,AddressState
# want: 192.168.64.30 / 24 / Preferred
ipconfig /all          # IP .30, gw .2, DNS .10 then 1.1.1.1
ping 192.168.64.2      # gateway replies
Rename-Computer -NewName CLIENT01 -Restart
```

### 1.4 Domain join (DC01 ON; ELK01 stays off)

1. With DC01 up, confirm the client can resolve + reach the domain (the #1 join blocker):

   ```powershell
   ping 192.168.64.10                              # DC replies
   nslookup lab.local                              # returns 192.168.64.10
   Test-NetConnection 192.168.64.10 -Port 389      # LDAP reachable = True
   ```
2. Join (PowerShell gives clearer errors than the Settings GUI). At the prompt enter the
   username as **`LAB\Administrator`** (or `Administrator@lab.local`) — **never bare
   `Administrator`**, which resolves to CLIENT01's *local* account:

   ```powershell
   Add-Computer -DomainName lab.local -Credential (Get-Credential) -Restart
   ```
3. After reboot, log in as the domain user to prove the trust: **"Other user"** →
   `LAB\Administrator` + domain password (first domain login is slow while the profile builds).

### Phase-1 exit criteria (verified)

```powershell
whoami                                         # lab\administrator
(Get-CimInstance Win32_ComputerSystem).Domain  # lab.local
Test-ComputerSecureChannel                      # True   <- gold-standard check
```

`Test-ComputerSecureChannel → True` confirms a healthy secure channel to the domain, not
merely that a computer object exists.

→ **Snapshot: `client01-domainjoined`**, then power DC01 back off to free its 4 GB.

---

## Phase 2 — Sysmon (SwiftOnSecurity)  ✓ complete   *(mirrors `02-sysmon-dc01.md`)*

**RAM:** CLIENT01 **on**; DC01 and ELK01 **off** — Sysmon is a purely local install.

Both artifacts are pulled **directly on CLIENT01** (no host staging). CLIENT01 still reaches
the internet via the VMnet8 NAT gateway (`192.168.64.2`) with DC01 off. Elevated PowerShell
(Sysmon loads a kernel driver, so elevation is mandatory):

```powershell
$ProgressPreference = 'SilentlyContinue'   # IWR progress bar otherwise crawls
New-Item -ItemType Directory -Path C:\Sysmon -Force | Out-Null
Set-Location C:\Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig-export.xml"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Sysmon" -Force
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Verify:

```powershell
Get-Service Sysmon64        # Running
sc.exe query SysmonDrv      # STATE : RUNNING
.\Sysmon64.exe -c           # prints the active SwiftOnSecurity ruleset (schema version <record yours>)
ping -n 1 sysmonmarker-client01.invalid    # unique EID 1 to find later
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
  Where-Object { $_.Message -like "*sysmonmarker-client01*" } |
  Format-List TimeCreated, Id
```

**Result:** `Sysmon64` service + `SysmonDrv` driver both **Running**; `-c` confirmed the
SwiftOnSecurity config active; the marker landed as **Event ID 1** (process create) in
`Microsoft-Windows-Sysmon/Operational`. Telemetry is **local only** at this stage — it does
not reach Kibana until the Elastic Agent ships this channel in Phase 3.

→ **Snapshot (interim): `client01-sysmon`** (the labelled clean baseline
`clean-baseline-client01` comes after the Phase 4 verify).

---

## Phase 3 — Install + enrol the Elastic Agent  ✓ complete   (ELK01 on, DC01 off)

> **Login account:** log into CLIENT01 as `LAB\Administrator` (works with DC01 off — the
> domain creds are **cached** from the Phase 1 interactive login) *or* the local `labadmin`.
> Either is fine: the install only needs an **elevated** shell + network reach to ELK01, and
> it authenticates to Fleet with the **enrollment token**, not your Windows identity. Once
> installed, the agent runs as a service under **SYSTEM**, so the install account is
> irrelevant afterward.

**In Kibana** (`http://192.168.64.20:5601` → Fleet):

1. **Agent policies → Create agent policy** → `client01-windows`. Save.
2. Add integrations via the **Integrations** catalog → **Add**, and on *"Where to add this
   integration?"* choose **Existing hosts → `client01-windows`**:
   - **System** (Windows Security, incl. `4624`)
   - **Windows** → enable the **`sysmon_operational`** dataset.

> **Watch the policy target.** The default on the integration screen often creates a *new*
> policy — explicitly pick **Existing hosts → client01-windows** or your integrations land
> on the wrong policy. (Same gotcha as DC01, Step 5.)

### Get the lab CA onto CLIENT01

`ca.crt` is the **public** CA cert (the secret is the CA *private key*, which never leaves
ELK01), so it doesn't need a secure transfer. **ELK01 is headless Ubuntu Server — no VMware
drag-and-drop/clipboard** — so move it over the network. Both VMs are up in this phase and on
the same VMnet8 subnet. From CLIENT01 (elevated PowerShell), `scp` is cleanest (Win11 ships
the OpenSSH client):

```powershell
New-Item -ItemType Directory -Force -Path C:\Elastic | Out-Null
scp analyst_ks@192.168.64.20:ca.crt C:\Elastic\ca.crt     # accept host key (yes) + password
Get-Content C:\Elastic\ca.crt -TotalCount 1               # -----BEGIN CERTIFICATE-----
```

> **Fallback if SSH isn't up:** on ELK01 run `cd ~ && python3 -m http.server 8000`, then on
> CLIENT01 `Invoke-WebRequest -Uri "http://192.168.64.20:8000/ca.crt" -OutFile C:\Elastic\ca.crt`,
> then `Ctrl+C` the server. Plain HTTP is fine — the cert is public.

### Download + enrol (agent version MUST be 9.4.3)

```powershell
Test-NetConnection 192.168.64.20 -Port 8220   # TcpTestSucceeded : True

$ProgressPreference = 'SilentlyContinue'   # REQUIRED — IWR's progress bar throttles this ~0.5–1 GB download to a crawl
$ver = "9.4.3"
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$ver-windows-x86_64.zip" -OutFile "elastic-agent.zip"
Expand-Archive .\elastic-agent.zip -DestinationPath .
cd ".\elastic-agent-$ver-windows-x86_64"
```

> Run these from a folder you chose deliberately (e.g. `C:\Elastic`) — the relative `-OutFile`
> and `-DestinationPath .` land the download and unzipped folder right there. Prefer a live
> progress meter? Swap the download line for
> `curl.exe -L -o elastic-agent.zip "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.3-windows-x86_64.zip"`.

Enrol — **one line**, paste the `client01-windows` token from Kibana (Fleet → Agents → Add
agent, or Fleet → Enrollment tokens) between the quotes:

```powershell
.\elastic-agent.exe install --url=https://192.168.64.20:8220 --enrollment-token="PASTE_TOKEN_HERE" --certificate-authorities=C:\Elastic\ca.crt
```

Accept the `[Y/n]` prompt. In **Fleet → Agents**, CLIENT01 appears and goes **Healthy**
(Healthy — not just enrolled — confirms both the control plane and the agent's own monitoring
output to `:9200` validate against the CA). The agent installs itself into
`C:\Program Files\Elastic\Agent`; the `elastic-agent-9.4.3-windows-x86_64` download folder is
then just leftover material (safe to delete — keep `C:\Elastic\ca.crt`).

---

## Phase 4 — Verify telemetry + snapshot  ✓ complete

On CLIENT01, generate a logon `4624` and a Sysmon marker:

```powershell
runas /user:lab\administrator cmd            # produces a 4624 logon
ping -n 1 verify-client01.invalid            # Sysmon EID 1
```

In Kibana → **Discover** (`logs-*`), after ~30–60 s:

- `event.code : "4624" and host.name : "client01"`  → your logon
- `event.code : "1" and host.name : "client01" and process.command_line : *verify-client01*`  → the Sysmon EID 1

Both returning docs = CLIENT01 is fully wired in.

> **LogonType with DC01 off = 11 (CachedInteractive), not 2.** The verify `4624` for a *domain*
> account (`lab\administrator`) via `runas` while DC01 is powered off authenticates against
> **cached credentials** — Windows logs that as **Type 11**, not the Type 2 you'd get from a
> local account or from a domain logon with the DC reachable. Both are valid successful logons;
> Type 11 is simply the tell that no DC was contacted. (Good interview detail: it demonstrates
> you can read a logon event and infer whether the DC was involved.)

→ **Snapshot: `clean-baseline-client01`**

### Verification evidence
- Fleet status: **CLIENT01 Healthy** on `client01-windows` (rev.2, v9.4.3, ~267 MB) — `healthy-fleet-client01-elk01.png`
- `4624` for `host.name:"client01"` → **1 doc**, `user.name` Administrator, `winlog.event_data.LogonType` **11** (cached, DC01 off) — `4624-kibana-discover-Client01.png`
- Sysmon **EID 1** for `host.name:"client01"` → **1 doc**, `windows.sysmon_operational`, `process.command_line` = `"C:\WINDOWS\system32\PING.EXE" -n 1 verify-client01.invalid` — `Sysmon-EID1-Client01.png`
- Event generation on CLIENT01 (`ping` + `runas`) — `cmd-runas_ping-client01.png`

---

## Gotchas (interview-ready)

**Build & join (Phase 1)**

- **UEFI boot-manager menu on first power-on is normal** — empty disk, nothing bootable yet.
- **vTPM requires VM encryption first.** VMware won't attach a TPM 2.0 device to an
  unencrypted VM; selecting the *Windows 11 x64* guest OS triggers the encryption prompt
  automatically. Without TPM + Secure Boot, Win11 setup refuses to install.
- **Win11 local-account OOBE bypass is a moving target.** Clean path is *"Domain join
  instead."* When newer builds hide it, `start ms-cxh:localonly` (Shift+F10) is the current
  reliable method; `OOBE\BYPASSNRO` + network-disconnect still works on release builds. The
  fake-email trick is dead as of 24H2.
- **DNS must point at the DC** (`192.168.64.10`) *before* the join, or `lab.local`'s SRV
  records don't resolve and the join fails.
- **Clock skew silently breaks the join as a fake "wrong password."** DC01 was ~7 h behind
  CLIENT01; Kerberos rejects auth when clocks differ by >5 min, and `Add-Computer`
  authenticates via Kerberos — but the error read *"user name or password is incorrect,"* not
  a time error. Tell: the same password logs into DC01 fine. Diagnose with `Get-Date` on both
  VMs. Isolate Kerberos vs credential with `net use \\192.168.64.10\IPC$ /user:LAB\Administrator`
  (NTLM, time-insensitive) — if that succeeds but the join fails, it's the clock. Fix the time,
  and re-check after any snapshot/pause since **VMware Tools time-sync can drag the guest clock
  back to the host's**.
- **Credential / keyboard confusion produces the identical "wrong password" error.** Bare
  `Administrator` resolves against CLIENT01's *local* SAM — always prefix **`LAB\`**. And a
  GB/US keyboard mismatch mistypes special characters (`\ | @ " #`) invisibly under
  `Get-Credential`; diagnose by typing the password into **Notepad in plain view**.
- **`New-NetIPAddress` prints `Tentative` then `Invalid` — both benign.** ActiveStore shows
  `Tentative` during Duplicate Address Detection then flips to `Preferred`; PersistentStore
  reports `Invalid` by design (it doesn't track live DAD). Confirm with
  `Get-NetIPAddress … | Select AddressState` → want `Preferred`. Re-running on the same
  interface throws "instance already exists" — use `Set-`/`Remove-NetIPAddress` to change it.

**Sysmon (Phase 2)**

- **Two-file, command-line install — not a double-click setup.** You need `Sysmon64.exe` *and*
  the config XML together; `-i` installs the service + driver and applies the config atomically.
- **Direct pull with DC01 off → DNS fail-over.** CLIENT01's primary DNS (`192.168.64.10`, the
  DC) is unreachable while DC01 is off, so first-lookup resolution fails over to `1.1.1.1`.
  Downloads still succeed after a short pause — a clean demo that NAT egress and resolver
  fallback are independent of the domain.

**Agent / verify (Phases 3–4)**

- **Agent version must equal the stack version (9.4.3)** or enrolment/ingest breaks. Pin
  `$ver = "9.4.3"` — never let it grab "latest".
- **The agent zip is big (~0.5–1 GB).** Set `$ProgressPreference = 'SilentlyContinue'` before
  `Invoke-WebRequest` (its progress bar throttles large downloads to a crawl — the file will
  seem to hang for many minutes), or use `curl.exe -L -o` for a real progress meter. Sanity-check
  progress from a second shell with `(Get-Item elastic-agent.zip).Length / 1MB`.
- **ELK01 is headless Ubuntu Server — no drag-and-drop/clipboard.** Move `ca.crt` over the
  network (`scp` from CLIENT01, or a throwaway `python3 -m http.server`). It's the *public* CA
  cert, so plain HTTP/scp is fine — the CA private key never leaves ELK01.
- **Login with DC01 off works via cached creds.** `LAB\Administrator` re-authenticates from the
  credential cache (populated at the Phase 1 interactive login), so no DC is needed; local
  `labadmin` works too. The agent runs as **SYSTEM** regardless of who installs it.
- **Integration policy target:** pick *Existing hosts → client01-windows* or Fleet spawns a
  new, empty policy.
- **CA trust:** `C:\Elastic\ca.crt` must be the exact lab CA that signed ELK01's certs, or the
  agent enrolls but sits **Unhealthy** with x509 errors on its monitoring data.
- **Verify `4624` LogonType depends on DC reachability.** A domain `runas` with DC01 **off**
  logs **Type 11 (CachedInteractive)** — cached creds, DC never contacted — not Type 2. Don't
  filter the verify query on `LogonType : "2"` or you'll miss your own event. Type 2 is a local
  account or a domain logon with the DC up.

**Throughout**

- **16 GB discipline:** run VMs in pairs (see RAM plan); never all three for long.

---

## Result

- CLIENT01: domain-joined Windows 11 endpoint on `192.168.64.30`, Sysmon (SwiftOnSecurity)
  installed, Elastic Agent on policy `client01-windows`, **Healthy** in Fleet, shipping
  Windows Security + Sysmon for `host.name:"client01"`.
- Snapshots: `client01-domainjoined`, `client01-sysmon`, `clean-baseline-client01`.
- **Phase status:** Phase 1 ✓ · Phase 2 ✓ · Phase 3 ✓ · Phase 4 ✓ — **CLIENT01 build complete.**

## Next

- Snapshot `pre-atomics-week3` on CLIENT01, then install **Atomic Red Team** and run
  **T1059.001**, **T1136.001**, **T1053.005** against CLIENT01.
- Hunt each in Discover with `host.name : "client01"`, validate the three Sigma rules
  already drafted in `detections/`, and write the first incident report(s) into
  `incident-reports/`. Commit + update the top-level README's ATT&CK coverage.

## Reproduce

| Item | Source / command |
|---|---|
| Windows 11 Enterprise (eval) | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise |
| VMware Win11 VM | Guest OS = Windows 11 x64 → TPM-files-only encryption; UEFI + Secure Boot |
| Sysmon | https://download.sysinternals.com/files/Sysmon.zip |
| Sysmon config | https://github.com/SwiftOnSecurity/sysmon-config — `sysmonconfig-export.xml` |
| Elastic Agent | `https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.4.3-windows-x86_64.zip` |
| Enrol | `elastic-agent.exe install --url=https://192.168.64.20:8220 --enrollment-token=<...> --certificate-authorities=C:\Elastic\ca.crt` |
