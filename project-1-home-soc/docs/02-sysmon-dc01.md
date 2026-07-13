# 02 — Endpoint Telemetry: Sysmon on DC01

**Goal:** Install Sysmon on the domain controller (`DC01`) with a tuned community
configuration, and prove it is generating rich endpoint telemetry into the
`Microsoft-Windows-Sysmon/Operational` event log — the channel the Elastic Agent
will ship in the next step.

**Step in roadmap:** Project 1, Weeks 1–2, Step 4 (follows the ELK01 build in
`01-lab-build-elk01.md`; precedes Fleet enrolment in Step 5).

---

## Why Sysmon

Windows' built-in Security log is necessary but coarse. Sysmon (System Monitor,
a Sysinternals driver + service) adds high-fidelity endpoint events the SOC
world actually hunts on: process creation with full command line, parent
process, and image hashes (EID 1); network connections (EID 3); file creation
(EID 11); registry activity (EID 12/13); and DNS queries (EID 22), among others.
The process lineage and hashing alone make it worth deploying over raw Security
auditing.

The configuration is **SwiftOnSecurity's `sysmonconfig-export.xml`** — a widely
used, well-commented baseline that logs the security-relevant events while
excluding common noise. Using a tuned config from day one (rather than Sysmon's
sparse defaults) is the realistic choice and keeps SIEM volume sane.

---

## Environment

| Attribute | Value |
|---|---|
| Host | `DC01` — Windows Server 2025, Desktop Experience |
| Role | `lab.local` domain controller (`192.168.64.10`) |
| Architecture | x86-64 → use `Sysmon64.exe` |
| Sysmon config | SwiftOnSecurity `sysmonconfig-export.xml` |
| Network | VMware VMnet8 NAT — has outbound internet for the download |

> A production DC would not browse the web. In a snapshot-protected lab this is
> the pragmatic choice; the alternative is to download on the host and copy the
> two files in via a shared folder.

---

## 1. Acquire Sysmon and the config

Run **PowerShell as Administrator** on `DC01`:

```powershell
New-Item -ItemType Directory -Path C:\Sysmon -Force | Out-Null
Set-Location C:\Sysmon

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig-export.xml"

Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Sysmon" -Force
```

## 2. Install with the tuned config

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

This installs the `SysmonDrv` kernel driver, registers and starts the `Sysmon64`
service, and applies the SwiftOnSecurity ruleset. If the config's schema version
predates the Sysmon binary, Sysmon accepts it (it is backward-compatible); such a
notice is informational, not an error.

## 3. Verify the service, driver, and active config

```powershell
Get-Service Sysmon64          # Status → Running
sc.exe query SysmonDrv        # STATE   → RUNNING (kernel driver)
.\Sysmon64.exe -c             # Prints the ACTIVE ruleset (confirms config applied)
```

The `-c` output should list rule groups (ProcessCreate, NetworkConnect,
DnsQuery, etc.). Seeing those confirms Sysmon is running with the SwiftOnSecurity
config rather than defaults.

## 4. Verify events reach the Operational log

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
  Format-Table TimeCreated, Id, LevelDisplayName -AutoSize
```

Rows returned = the channel is live. This is the exact log the Elastic Agent
Windows integration reads in Step 5, so a populated channel now reduces Step 5 to
a transport task.

## 5. Sanity-check Event IDs with a marker

A single `ping` to a guaranteed-dead name produces both a process-create (EID 1)
and a DNS query (EID 22), tagged with a unique string that is easy to find:

```powershell
ping -n 1 sysmontest.invalid
```

**EID 1 — Process Create** (guaranteed):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 20 |
  Where-Object { $_.Message -match 'sysmontest.invalid' } |
  Format-List TimeCreated, Id, Message
```

Expected fields include `Image`, `CommandLine` (carrying the marker), `User`,
`ParentImage`, `Hashes`, and `ProcessGuid` — the process lineage that makes
Sysmon valuable.

**EID 22 — DNS Query** (bonus):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -MaxEvents 20 |
  Where-Object { $_.Message -match 'sysmontest.invalid' } |
  Format-List TimeCreated, Id, Message
```

> The SwiftOnSecurity config intentionally excludes noisy DNS destinations, so
> test EID 22 with a novel name (as above). If EID 1 fires and the Operational
> log is populating, Step 4 is functionally complete even without EID 22.

---

## 6. Re-baseline

Sysmon is now part of `DC01`'s known-good state, so the pre-Sysmon snapshot is
stale. Take a fresh VMware snapshot of `DC01`:

```
clean-baseline-dc01-sysmon
```

Future roll-backs then land on a Sysmon-enabled baseline instead of requiring a
reinstall.

---

## Result

- Sysmon installed on `DC01` with the SwiftOnSecurity config.
- `Sysmon64` service and `SysmonDrv` driver both running.
- `Microsoft-Windows-Sysmon/Operational` populating; EID 1 confirmed via marker.
- New clean snapshot taken.

## Next

**Step 5 — Fleet:** add a Fleet Server service to the `elk/` compose stack, set
`KIBANA_PUBLIC_URL=http://192.168.64.20:5601`, and enrol an Elastic Agent on
`DC01` to ship Windows Security + Sysmon logs. Bump `ELK01` to 5–6 GB (powered
off) beforehand — Fleet Server makes 4 GB tight.

## Reproduce

| Item | Source |
|---|---|
| Sysmon | https://download.sysinternals.com/files/Sysmon.zip (Sysinternals) |
| Config | https://github.com/SwiftOnSecurity/sysmon-config — `sysmonconfig-export.xml` |
| Install | `Sysmon64.exe -accepteula -i sysmonconfig-export.xml` |
