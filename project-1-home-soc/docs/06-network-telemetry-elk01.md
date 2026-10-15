# 06 — Network telemetry: Zeek + Suricata on ELK01 (Project 4)

**Goal:** close the gap I found in *The Silent Transfer* (strong host telemetry, no network telemetry). Install Zeek and Suricata on ELK01, ship their logs through Fleet, then detect a simulated beacon and a toy DNS-tunnelling case.

**Deliverables:** `detections/T1071-beaconing.yml`, `detections/T1071.004-dns-tunnelling.yml`, `incident-reports/IR-2026-004`, updated `network-diagram.svg`, Navigator additions (T1071, T1071.004).

> Status (16 Oct 2026, ~00:30 BST): **Phases 0-7 DONE.** Suricata + Zeek installed and shipping through Fleet on `elk01-network`; 30-request beacon run detected 30/30 by Suricata, Zeek conn and Zeek http. DNS tunnelling: two runs of 40 queries, both sensors logged every query; a 40-character label rule was written, tested in ES|QL and found to match a benign TPM-attestation family, so it carries an exclusion; a fan-out hunt is the companion. **Still untested:** the Sigma-to-Elastic conversion of both network rules, the exclusion, and the fan-out hunt over the full window. Observed results and corrections to the original plan are marked **[observed]** below; everything else is as originally written.

---

## 0. Pre-flight (10 min)

- [ ] Power off DC01. Run **ELK01 + CLIENT01 only**.
- [ ] `free -h` on ELK01 with the stack up. If available memory is under ~1 GB, shut ELK01 down and raise it to **6 GB** in VMware (Zeek + Suricata + a host Elastic Agent all add load).
- [ ] Snapshot ELK01 as `pre-network-sensors` (rollback point; `elk-fleet-healthy` already exists).
- [ ] CLIENT01 is on `clean-baseline-client01` (no ART). That is fine — the beacon needs no tooling.
- [ ] Note the ELK01 NIC name: `ip -br a` (expect something like `ens33`; use whatever you see).

## 1. Placement (read before building)

**[observed - corrects the original plan]** The original plan assumed ELK01 would only see traffic to or from ELK01. In practice `tcpdump -ni ens33 host 192.168.64.30 and not host 192.168.64.20` captured CLIENT01's traffic to `173.46.83.203:80` and Suricata logged CLIENT01 to `1.1.1.1:53` DNS, so VMnet8 delivers other VMs' traffic to ELK01. **CLIENT01 to DC01 traffic was NOT tested** (DC01 was off). The listener design below still works and is reproducible without relying on that behaviour, so keep it.

Original assumption (kept for the record): VMnet8 is a NAT segment, so ELK01 only sees traffic to or from ELK01.

- **HTTP beacon:** CLIENT01 → listener on ELK01 (`:8080`). ELK01 sees the flows.
- **DNS tunnelling:** CLIENT01 normally resolves via DC01 (and falls back to 1.1.1.1 when DC01 is off). For a reproducible test, send queries **directly to ELK01** (`-Server 192.168.64.20`). Nothing answers on UDP 53 there (systemd-resolved listens on 127.0.0.53 only); Zeek and Suricata still log the unanswered query. Expect no reply fields in the log.
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
# [observed] edit as root: sudo nano /etc/suricata/suricata.yaml. Under af-packet set `interface: ens33`;
# under rule-files add `- local.rules`. The rules dir is root-only: use sudo for every read.
sudo suricata -T -c /etc/suricata/suricata.yaml    # config test: must pass
sudo systemctl enable --now suricata
sudo tail -f /var/log/suricata/eve.json            # should start producing events
```

**[observed]** `suricata-update` + the custom file loaded 53,159 rules with 0 failed. An earlier log line "1 rule files specified, but no rules were loaded" pre-dated `suricata-update` and is harmless. Verify the custom rule with `sudo grep 1000001 /var/log/suricata/fast.log`. The alert shows `Classification: (null)` because the rule has no `classtype` (cosmetic).

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

**[observed] Zeek install gotchas**
- Repo: openSUSE Build Service `security:zeek/xUbuntu_24.04` (add the `.list` and the dearmored key, then `apt update && apt install zeek`).
- `apt` can wait on `unattended-upgrades` holding the dpkg lock (179 packages were upgradable). Do not kill it or delete lock files; wait with `while pgrep -f unattended-upgrade >/dev/null; do sleep 10; done; sudo apt install -y zeek`.
- The package pulls in Postfix, which prompts for a mail configuration type. Choose **Local only** (no network exposure). System mail name: accept the default.
- Set `interface=ens33` in `/opt/zeek/etc/node.cfg`.
- **Checksum offload:** flows originating on ELK01 were logged with `conn_state` `SH`/`OTH`, 1 reply packet, `resp_bytes: 0`, and a lowercase/uppercase `c` in `history`. Fix: `echo 'redef ignore_checksums = T;' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek && sudo /opt/zeek/bin/zeekctl deploy`. After: `SF`, `resp_bytes: 202`, 5 packets each way. A `grep bad_checksum` on `weird.log` returned 0 because Zeek names these weirds by protocol; the before/after rows are the evidence, and the `weird.log` entries were not captured. Deliberate lab trade-off.
- Zeek rotates `conn.log` hourly into `/opt/zeek/logs/<date>/conn.*.log.gz`; any analysis spanning the hour must read both.

## 4. Fleet: new policy + host agent

1. Kibana → Fleet → Agent policies → create **`elk01-network`**.
2. Add integrations: **Zeek** (set log paths to `/opt/zeek/logs/current/*.log` per dataset — connection, dns, http at minimum) and **Suricata** (`/var/log/suricata/eve.json`).
3. Enrol an **Elastic Agent on the ELK01 host** (this is separate from the Fleet Server container). Use the Fleet "Add agent" command, pointing at `https://192.168.64.20:8220` with `--certificate-authorities=<path to lab CA>`. Run as root so it can read both log locations.
4. Verify **Healthy** in Fleet, then in Discover (`logs-*`) check `event.dataset : "zeek.connection"` and `event.dataset : "suricata.eve"`.

**[observed]** Host agent enrolled and **Healthy** on `elk01-network` (screenshot `fleet-elk01-network-healthy.png`; crop the enrollment token). Datasets that arrived: `zeek.connection`, `zeek.http`, `suricata.eve`. Gotchas actually hit:
- **Wrong architecture and version:** the first download was `elastic-agent-9.4.8-linux-arm64` (the Fleet "Add agent" snippet's tarball, wrong for an x86-64 VM and newer than the 9.4.3 stack). The binary failed with `Syntax error: word unexpected` (the shell was reading a foreign-architecture binary as a script). Use `elastic-agent-9.4.3-linux-x86_64.tar.gz`. Confirm with `uname -m`.
- **CA path:** a copy of the lab CA lives at `/etc/elastic-agent-ca/ca.crt` (source: the Docker volume `elk_certs`), used with `--certificate-authorities`. The Docker volume path can vanish after `docker compose down -v`.
- **Token hygiene:** the enrollment token was pasted into a chat. It is low-risk (private lab, one policy) but **revoke it in Fleet -> Enrollment tokens** (not confirmed done).
- Fleet shows "Upgrade available"; ignore it (agents newer than Fleet Server are unsupported). A stale **Offline** Fleet Server record (`ea51522d3b6f`) from a recreated container can be removed to tidy screenshots.
- **RAM:** ELK01 (5.7 GiB total) had 1.1 GiB available and ~430 MiB swap in use with everything running. If it drops below ~500 MiB or the kernel kills a process, raise ELK01 to 7 GB. Check `sudo dmesg -T | grep -i "out of memory\|killed process"`.

## 5. Listener and beacon

ELK01 (confirm port 8080 is free first: `ss -ltn | grep 8080`):

```bash
mkdir -p ~/listener && cd ~/listener && python3 -m http.server 8080
```

CLIENT01 (PowerShell; 30 beats, 60 s ± 5 s jitter; record the start time with `Get-Date -Format o`):

```powershell
$ProgressPreference='SilentlyContinue'
1..30 | ForEach-Object {
  curl.exe -s -A "LabBeacon/1.0" http://192.168.64.20:8080/beacon | Out-Null
  Start-Sleep -Seconds (60 + (Get-Random -Minimum -5 -Maximum 6))
}
```

**[observed]** `curl.exe` (not the PowerShell `curl` alias) was used. The Python listener only runs while its terminal stays open; `echo ok > ~/listener/beacon` makes it return 200 instead of 404. Run on 15 Oct: start 15:57:26 UTC, end 16:27:33 UTC; **30 Suricata alerts, 30 `zeek.connection` rows, 30 `zeek.http` rows**. Not checked: Sysmon EID 3 on CLIENT01.

Capture before cleanup: Suricata alert in Discover, `zeek.connection` rows, CLIENT01 Sysmon EID 3 (network connect) for the same flows if enabled by the config (check; do not assume).

## 6. Detection 1 — beaconing, two ways

- **Signature:** the Suricata rule above (fires on the user agent). Note the weakness: attackers change the UA. This is the *naive version* — say what it misses.
- **Behaviour:** `conn.log` interval regularity. Kibana to pull candidate pairs (source, destination, port, count over the window); then compute the standard deviation of inter-arrival times per pair. EQL/ES|QL alone is awkward for this, so state honestly if you use a small Python script over an export. Low standard deviation relative to the mean + enough samples (say ≥ 10) = beacon candidate. Check what jitter does to the threshold, and what legitimate periodic traffic (NTP, Windows telemetry, agent check-ins) looks like — that is the false-positive section.

**[observed]** The interval check was done with a small Python hunt script over Zeek `conn.log` (committed as `detections/hunts/T1071-beacon-interval.py`), not in the SIEM; Sigma and the KQL used here cannot compute a standard deviation. Results (cv = sd / mean): beacon 30 connections, mean 60.4 s, sd 3.5 s, **cv 0.06**; SSDP multicast `192.168.64.1 -> 239.255.255.250:1900` cv 0.00 (more regular than the beacon, so a multicast exclusion is required); Elastic Agent `:9200` cv 0.61; DNS to 1.1.1.1 cv 1.42 and 2.96; one unidentified `34.95.113.255:443` cv 0.88. Threshold `n >= 10`, `cv < 0.2`, multicast excluded, supported by one beacon and five baseline pairs, not proven. The script's flag column is a later addition and has **not been re-run**.

**[observed]** Kibana queries tested (window 16:57-17:27 BST, 30 results each): `event.dataset : "suricata.eve" and destination.port : 8080 and event.kind : "alert"`; `event.dataset : "zeek.connection" and destination.port : 8080`; `event.dataset : "zeek.http" and user_agent.original : "LabBeacon/1.0"`. The Zeek HTTP user agent field in Elastic is `user_agent.original`. A Sigma-to-Elastic conversion of the rule has **not** been run. A KQL query with a quoted wildcard (`user_agent* : "LabBeacon*"`) also returned 30, which contradicts the earlier "quoted wildcard is literal" note; unexplained, so cite only the exact-value form.

Convert any Sigma rule with `-t eql -p ecs_windows`-style conversion **appropriate to network fields**, and **test the converted query in Kibana before writing the IR.** A clean conversion has already proven not to mean a working query.

## 7. Detection 2 — DNS tunnelling (toy) — DONE (15-16 Oct)

**Test design.** Record `Get-Date -Format o` before and after each run. Send 40 queries per run to `<random label>.t.lab-tunnel.test` directly at ELK01 (`-Server 192.168.64.20`); nothing answers on UDP 53 there, so there are no reply fields, and both sensors still log the query. Add `-DnsOnly -QuickTimeout`.

**[observed - corrects the original command]** The first version used `Get-Random -Count 52` on the 36-character pool `(48..57)+(97..122)`. Without replacement that returns at most 36 values, so run 1 produced 36-character labels (54 characters in total, each label the whole alphabet shuffled), not the 52 and 70 intended. The fixed command samples with replacement:

```powershell
$chars = (48..57)+(97..122) | ForEach-Object {[char]$_}
Get-Date -Format o
1..40 | ForEach-Object {
  $label = -join (1..52 | ForEach-Object { $chars | Get-Random })
  Resolve-DnsName "$label.t.lab-tunnel.test" -Server 192.168.64.20 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
}
Get-Date -Format o
```

**[observed] Results** (full detail in IR-2026-004 section 9; Kibana and CLIENT01 times are BST):

| Run | CLIENT01 start to end (BST) | Label | Zeek rows | Distinct | Suricata |
|---|---|---|---|---|---|
| 1 | 22:30:57.95 to 22:35:57.13 | 36 chars (bug) | 240 | 40 | 240 rows, 40 distinct |
| 2 | 23:22:29.73 to 23:27:12.03 | 52 chars, total 70 | 240 | 40 | not queried |
| unexplained | first seen about 23:19 | 40+ chars | 36 | 6 | not queried |

- **Field names:** Zeek `zeek.dns.query` (not `dns.question.name`); Suricata `suricata.eve.dns.queries.rrname`.
- **Six rows per name on both sensors** (240 for 40 names), unchanged by widening the window. Timing fits Windows retries (about t, t+1 s, t+3 s, two rows per send). A and AAAA split not checked.
- **`-QuickTimeout` made no difference:** about 7 s per name.
- **The unexplained six names** (36 rows) were first seen about three minutes before run 2 started. Cause not established.
- **Not explained:** Suricata's unfiltered port-53 count of 313 was never broken down by event type.

**[observed] Baseline, and what it did to the rule.** The first baseline (the 5-minute run-2 window) had 89 rows and 49 distinct names, with a longest total query of 72 (a DC-locator GUID name), so **total query length cannot separate the tunnel**. I then wrote a rule on a single label of 40 or more characters. Run over the whole window (22:30:57 to 23:27:13 BST) it matched six **benign** names: `vmw-keyid-<40 hex>[-v2].microsoftaik.azure.net`, which look like Windows TPM attestation (AIK certificate) lookups (matches the pattern described at call4cloud.nl; `vmw` meaning VMware's vTPM is my inference). They are 50 and 53 characters per label, against the tunnel's 52, so **no single-label length threshold separates them**. Benign set: 627 rows, 158 distinct names; 6 of 158 distinct names (about 4%) matched before tuning. The first baseline slice missed them because they arrived about 25 s before its window opened.

- **Rule:** `detections/T1071.004-dns-tunnelling.yml`: a label of 40 or more characters, excluding the exact parent `.microsoftaik.azure.net` (never widen to `*.azure.net`).
- **Companion hunt:** fan-out per source and parent (30 or more distinct names in 5 minutes). Tunnel 40; TPM family 6; benign maximum 17 in the 5-minute slice (not re-checked over the full window).
- **Entropy was not used:** both generators produce uniform-random labels, so a threshold would be tuned on an artefact.
- **Regex tests (ES|QL `RLIKE`):** run 2 matched, run 1 did not (36-char labels, as expected), the TPM family matched (the false positive).

**Gotchas hit**
- **ES|QL `RLIKE` rejects a trailing hyphen in a character class.** `[A-Za-z0-9_-]` gives "invalid range: from (95) cannot be > to (93)". Put the hyphen first (`[-A-Za-z0-9_]`) or escape it in a triple-quoted string; both behaved the same. A Python regex test passes the broken form, so test in the target engine.
- **A short baseline slice is not a baseline.** Test the rule over a wider window before writing a threshold.
- **Count arithmetic:** the matched group is separate from the 621 / 152 non-matching group, so the benign total is 627 rows and 158 distinct names (I first wrote 6 of 152).
- **Parse the YAML after writing it:** a colon inside an unquoted list item broke the first rewrite.
- **`DISSECT "%{label}.%{parent}"` splits at the first dot**, so `max_label` measured the first label only, and "parent" is not the registered domain.
- **Kibana's ES|QL results table can collapse rows into group headers;** expand them or turn off "Group by" to see the values.
- **Observed placement again:** CLIENT01's DNS fell back to `1.1.1.1` with DC01 off and the sensor still logged those queries. CLIENT01 to DC01 remains untested.

**Not tested:** the Sigma-to-Elastic conversion of either network rule (`T1071-beaconing.yml`, `T1071.004-dns-tunnelling.yml`), the `endswith` exclusion, and the fan-out hunt over the full window.

## 8. Write-up checklist

- [x] `detections/T1071-beaconing.yml` (signature + behaviour logic, FP notes) — delivered; Sigma conversion untested
- [x] `detections/suricata/T1071-beaconing.rules` and `detections/hunts/T1071-beacon-interval.py`
- [x] `detections/T1071.004-dns-tunnelling.yml` — delivered; regex tested in ES|QL, exclusion and conversion untested
- [x] IR-2026-004 beacon half and DNS section (UTC timeline)
- [ ] Screenshots: `T1071-suricata-alert.png` and `T1071-zeek-conn.png` (30-result versions, taken), `T1071-suricata-alert-first-test.png` (rename the 4-result one), `T1071-zeek-http.png` (still to take), `T1071-interval-stddev.png` (script output, taken), `fleet-elk01-network-healthy.png` (taken), and six DNS screenshots that exist but still need saving under these names: `T1071.004-dns-long-labels.png`, `T1071.004-suricata-dns.png`, `T1071.004-dns-baseline.png`, `T1071.004-run2-label-lengths.png`, `T1071.004-regex-test.png`, `T1071.004-benign-tpm-lookups.png`; confirm every filename and extension before linking
- [x] Update `network-diagram.svg` (sensors and host agent on ELK01, listener `:8080`, beacon and DNS test flows) — updated 16 Oct; check it renders in your browser
- [x] T1071.001 and T1071.004 in `attack-navigator.json` (T1071.004 marked as partially validated)
- [ ] README coverage table + this doc linked
- [ ] Re-run the fan-out hunt over the full window; test the exclusion; run `sigma convert` on both network rules
- [x] Snapshot ELK01 `elk-network-sensors-healthy` (taken; `pre-network-sensors` also exists)

**Interview line:** *"I had host telemetry only, saw that gap in an investigation, and closed it. My first DNS rule fired on Windows TPM lookups whose labels were longer than my tunnel's, so I wrote down why a length threshold can't work, tuned it with a narrow exclusion and added a fan-out check. I also know the sensor only sees what's routed past it."*
