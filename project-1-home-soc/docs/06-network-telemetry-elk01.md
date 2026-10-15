# 06 — Network telemetry: Zeek + Suricata on ELK01 (Project 4)

**Goal:** close the gap I found in *The Silent Transfer* (strong host telemetry, no network telemetry). Install Zeek and Suricata on ELK01, ship their logs through Fleet, then detect a simulated beacon and a toy DNS-tunnelling case.

**Deliverables:** `detections/T1071-beaconing.yml`, `detections/T1071.004-dns-tunnelling.yml`, `incident-reports/IR-2026-004`, updated `network-diagram.svg`, Navigator additions (T1071, T1071.004).

> Status: **runbook drafted 14 Oct 2026 (late). Nothing below has been run yet.** Tick phases as you go and record *observed*, not predicted, results.

---

## 0. Pre-flight (10 min)

- [ ] Power off DC01. Run **ELK01 + CLIENT01 only**.
- [ ] `free -h` on ELK01 with the stack up. If available memory is under ~1 GB, shut ELK01 down and raise it to **6 GB** in VMware (Zeek + Suricata + a host Elastic Agent all add load).
- [ ] Snapshot ELK01 as `pre-network-sensors` (rollback point; `elk-fleet-healthy` already exists).
- [ ] CLIENT01 is on `clean-baseline-client01` (no ART). That is fine — the beacon needs no tooling.
- [ ] Note the ELK01 NIC name: `ip -br a` (expect something like `ens33`; use whatever you see).

## 1. Placement (read before building)

VMnet8 is a NAT segment. ELK01 only sees traffic **to or from ELK01**. It will not see CLIENT01↔DC01.

- **HTTP beacon:** CLIENT01 → listener on ELK01 (`:8080`). ELK01 sees the flows.
- **DNS tunnelling:** CLIENT01 normally resolves via DC01, which ELK01 cannot see. For the test, send queries **directly to ELK01** (`-Server 192.168.64.20`). Nothing answers on UDP 53 there (systemd-resolved listens on 127.0.0.53 only); Zeek and Suricata still log the unanswered query. Expect no reply fields in the log.
- Do not attempt promiscuous capture on VMnet8.

## 2. Install Suricata (ELK01)

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install -y suricata
sudo suricata-update            # pulls the ET Open ruleset
```

Edit `/etc/suricata/suricata.yaml`:

- `af-packet:` → `interface:` = your NIC name
- confirm `eve-log` is enabled with `filename: eve.json` (default `/var/log/suricata/eve.json`)
- `HOME_NET` default (private ranges) is fine for the lab

Add the custom rule (file `/var/lib/suricata/rules/local.rules`, then add `local.rules` under `rule-files:` in `suricata.yaml`):

```
alert http $HOME_NET any -> any 8080 (msg:"LAB T1071 beacon - custom user agent"; http.user_agent; content:"LabBeacon/1.0"; sid:1000001; rev:1;)
```

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml    # config test: must pass
sudo systemctl enable --now suricata
sudo tail -f /var/log/suricata/eve.json            # should start producing events
```

## 3. Install Zeek (ELK01)

Ubuntu's own repo does not carry a current Zeek. Use the official packages — **check https://zeek.org/get-zeek/ for the current Ubuntu 24.04 instructions** (the openSUSE Build Service `security:zeek` repo is the usual route, installing to `/opt/zeek`).

After install:

```bash
# /opt/zeek/etc/node.cfg  -> standalone node, interface=<your NIC>
echo '@load policy/tuning/json-logs' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
sudo /opt/zeek/bin/zeekctl deploy
ls /opt/zeek/logs/current/      # conn.log, dns.log, http.log ...
```

JSON output is what the Elastic Zeek integration expects.

## 4. Fleet: new policy + host agent

1. Kibana → Fleet → Agent policies → create **`elk01-network`**.
2. Add integrations: **Zeek** (set log paths to `/opt/zeek/logs/current/*.log` per dataset — connection, dns, http at minimum) and **Suricata** (`/var/log/suricata/eve.json`).
3. Enrol an **Elastic Agent on the ELK01 host** (this is separate from the Fleet Server container). Use the Fleet "Add agent" command, pointing at `https://192.168.64.20:8220` with `--certificate-authorities=<path to lab CA>`. Run as root so it can read both log locations.
4. Verify **Healthy** in Fleet, then in Discover (`logs-*`) check `event.dataset : "zeek.connection"` and `event.dataset : "suricata.eve"`.

Gotcha candidates to record if hit: cert SAN/CA path on the host agent, file permissions on `/opt/zeek/logs`, Zeek log path globs, duplicate ingestion of rotated logs.

## 5. Listener and beacon

ELK01 (confirm port 8080 is free first: `ss -ltn | grep 8080`):

```bash
mkdir -p ~/listener && cd ~/listener && python3 -m http.server 8080
```

CLIENT01 (PowerShell; 30 beats, 60 s ± 5 s jitter; record the start time with `Get-Date -Format o`):

```powershell
$ProgressPreference='SilentlyContinue'
1..30 | ForEach-Object {
  Invoke-WebRequest -UseBasicParsing -Uri http://192.168.64.20:8080/beacon -UserAgent "LabBeacon/1.0" | Out-Null
  Start-Sleep -Seconds (60 + (Get-Random -Minimum -5 -Maximum 6))
}
```

Capture before cleanup: Suricata alert in Discover, `zeek.connection` rows, CLIENT01 Sysmon EID 3 (network connect) for the same flows if enabled by the config (check; do not assume).

## 6. Detection 1 — beaconing, two ways

- **Signature:** the Suricata rule above (fires on the user agent). Note the weakness: attackers change the UA. This is the *naive version* — say what it misses.
- **Behaviour:** `conn.log` interval regularity. Kibana to pull candidate pairs (source, destination, port, count over the window); then compute the standard deviation of inter-arrival times per pair. EQL/ES|QL alone is awkward for this, so state honestly if you use a small Python script over an export. Low standard deviation relative to the mean + enough samples (say ≥ 10) = beacon candidate. Check what jitter does to the threshold, and what legitimate periodic traffic (NTP, Windows telemetry, agent check-ins) looks like — that is the false-positive section.

Convert any Sigma rule with `-t eql -p ecs_windows`-style conversion **appropriate to network fields**, and **test the converted query in Kibana before writing the IR.** A clean conversion has already proven not to mean a working query.

## 7. Detection 2 — DNS tunnelling (toy)

CLIENT01:

```powershell
1..40 | ForEach-Object {
  $label = -join ((48..57)+(97..122) | Get-Random -Count 52 | ForEach-Object {[char]$_})
  Resolve-DnsName "$label.t.lab-tunnel.test" -Server 192.168.64.20 -ErrorAction SilentlyContinue | Out-Null
}
```

Hunt `zeek.dns` / Suricata DNS events: query length, label count, volume to one parent domain. Compute entropy offline if the stack cannot. Baseline against normal queries first so the threshold is justified, not guessed.

## 8. Write-up checklist

- [ ] `detections/T1071-beaconing.yml` (signature + behaviour logic, FP notes)
- [ ] `detections/T1071.004-dns-tunnelling.yml`
- [ ] IR-2026-004 (UTC timeline; say Kibana shows BST)
- [ ] Screenshots named up front: `T1071-suricata-alert.png`, `T1071-zeek-conn.png`, `T1071-interval-stddev.png`, `T1071.004-dns-long-labels.png`, `fleet-elk01-network-healthy.png`
- [ ] Update `network-diagram.svg` (sensor on ELK01, listener `:8080`)
- [ ] Add T1071 and T1071.004 to `attack-navigator.json`
- [ ] README coverage table + this doc linked
- [ ] Snapshot ELK01 `elk-network-sensors-healthy`

**Interview line:** *"I had host telemetry only, saw that gap in an investigation, and closed it — and I know the sensor only sees what's routed past it."*
