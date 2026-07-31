# Network Forensics Investigation: The Silent Transfer

## Incident Overview

This project documents a full network forensic investigation conducted as part of the TryHackMe "The Silent Transfer" challenge.

The scenario involved Helios Software Group, where the security team detected suspicious encrypted outbound traffic originating from a developer workstation. A Snort alert identified potential command-and-control (C2) communication, while firewall telemetry showed follow-up connections inconsistent with normal development activity.

The objective of the investigation was to determine:

* Whether the detected activity represented genuine C2 communication.
* Which internal workstation was compromised.
* What external infrastructure was involved.
* How the attacker gained initial access.
* Whether the attacker performed internal reconnaissance or lateral movement.
* Whether data was transferred outside the organisation.

The investigation was performed using network evidence including:

* Snort IDS alerts
* Zeek network telemetry
* Firewall logs
* Packet capture (`investigation.pcap`)
* Wireshark and TShark analysis

---

# Investigation Approach

The investigation followed a threat-hunting workflow:

1. Validate the initial alert.
2. Identify the compromised host.
3. Trace activity backwards to determine initial compromise.
4. Analyse C2 communication.
5. Investigate internal discovery and lateral movement.
6. Identify possible data exfiltration.
7. Reconstruct the complete attack timeline.

Rather than relying only on the Snort detection name, each activity was validated through multiple independent sources.

---

# Phase 1: Initial Detection and C2 Identification

## Snort Alert Analysis

The investigation began by reviewing the Snort detection around the reported timeframe.

The alert highlighted suspicious encrypted outbound traffic occurring around **03:47 UTC**, suggesting possible command-and-control communication.

The alert was correlated against Zeek connection logs:

* `conn.log`
* `ssl.log`

This allowed identification of:

* The internal source system generating the traffic.
* The external destination infrastructure.
* The communication pattern between both systems.

The affected workstation was identified as the source of repeated outbound connections to an external C2 server.

---

# Phase 2: Identifying the Initial Access Vector

After identifying the compromised workstation, the investigation moved backwards in time to determine how the infection started.

## DNS and HTTP Analysis

Zeek DNS and HTTP logs were analysed to identify suspicious activity before C2 establishment.

Commands used included:

```bash
zeek-cut ts id.orig_h query answers < zeek_logs/dns.log
```

and:

```bash
zeek-cut ts id.orig_h host uri < zeek_logs/http.log
```

The analysis revealed a suspicious domain used to deliver the initial payload.

The downloaded file was identified through Zeek's file analysis logs:

```bash
zeek-cut ts id.orig_h id.resp_h filename mime_type sha256 < zeek_logs/files.log
```

This provided:

* The transferred file.
* File metadata.
* SHA256 hash for verification.

This established the initial infection pathway:

```
User workstation
        |
        |
Suspicious domain
        |
        |
Malicious payload download
        |
        |
Execution
        |
        |
C2 communication established
```

---

# Phase 3: C2 Communication Analysis

Following execution, the malware established communication with external infrastructure.

## Connection Analysis

The workstation's outbound connections were analysed using Zeek connection logs.

The investigation focused on:

* Destination IP addresses.
* Connection frequency.
* Destination ports.
* Timing patterns.

Repeated communication with the same external infrastructure indicated beaconing behaviour consistent with C2 activity.

The first connection was analysed to identify:

* Source port used by the compromised workstation.
* Destination C2 server.
* Communication timing.

---

## TLS Fingerprint Analysis

The encrypted communication was investigated using Zeek TLS metadata.

The SSL logs were analysed to identify:

* TLS communication details.
* Client fingerprinting information.
* JA4 fingerprint associated with the C2 client.

This demonstrated how encrypted traffic can still provide valuable intelligence through metadata analysis, even when packet contents cannot be directly inspected.

---

# Phase 4: Internal Discovery Activity

After establishing C2, the attacker performed internal reconnaissance.

The investigation identified SMB activity originating from the compromised workstation.

SMB traffic was analysed using:

```bash
grep "445" zeek_logs/conn.log
```

The results showed the workstation communicating with multiple internal systems over SMB.

This indicated network discovery activity, likely attempting to identify:

* Available hosts.
* Internal resources.
* Potential targets for lateral movement.

The number of unique internal destinations contacted was calculated to determine the scope of discovery activity.

---

# Phase 5: Lateral Movement via RDP

Following SMB reconnaissance, the attacker moved laterally within the environment.

RDP activity was identified by analysing connections over:

```
TCP/3389
```

The RDP destination was identified as an internal server accessed from the compromised workstation.

This represented a progression from:

```
Initial Compromise
        ↓
C2 Establishment
        ↓
Internal Reconnaissance
        ↓
Lateral Movement
```

The attacker had successfully expanded activity beyond the original infected workstation.

---

# Phase 6: Data Exfiltration Investigation

After the RDP connection, the investigation pivoted to the internal server involved in lateral movement.

## DNS Correlation

DNS activity originating from the RDP destination was analysed.

The objective was to identify the domain resolved immediately before suspicious outbound communication.

The DNS event was correlated with firewall and Zeek connection logs to identify the infrastructure used for outbound transfer.

---

## File Transfer Analysis

Zeek file logs were examined to identify transferred objects.

The archive involved in the transfer was identified through:

```bash
zeek-cut ts id.orig_h id.resp_h filename mime_type sha256 < zeek_logs/files.log
```

The archive's SHA256 hash was extracted to provide a verifiable indicator of compromise.

The timing matched the large outbound transfer observed in network telemetry, confirming suspicious data movement.

---

# Phase 7: C2 Command Analysis

The final stage involved inspecting the application-layer contents of the C2 communication.

Wireshark was used to inspect packet streams and follow TCP conversations.

The analysis focused on identifying attacker-issued commands sent to the compromised workstation.

The command observed confirmed attacker interaction with the host.

This demonstrated that the connection was not normal development traffic but an active remote control channel.

---

# Complete Attack Timeline

```
03:47 UTC
|
|-- Snort detects suspicious encrypted outbound traffic
|
|-- Compromised workstation identified
|
|-- Malware delivery domain discovered
|
|-- Payload download confirmed
|
|-- C2 communication established
|
|-- TLS metadata analysed
|
|-- SMB reconnaissance begins
|
|-- Multiple internal hosts contacted
|
|-- RDP connection established to internal server
|
|-- Internal server performs DNS lookup
|
|-- Archive created/transferred externally
|
|-- Data exfiltration confirmed
|
|-- C2 commands identified
```

---

# Tools Used

## Wireshark

Used for:

* Packet-level validation.
* TCP stream analysis.
* Application-layer inspection.
* C2 traffic investigation.

## Zeek

Used for:

* Connection analysis.
* DNS investigation.
* TLS metadata analysis.
* File extraction metadata.
* Network timeline reconstruction.

Logs analysed:

* `conn.log`
* `dns.log`
* `ssl.log`
* `files.log`
* `http.log`

## Snort

Used for:

* Initial detection validation.
* Identifying suspicious network behaviour.

## TShark

Used for:

* Command-line packet inspection.
* Filtering and extracting specific traffic.

---

# Key Lessons Learned

## 1. Alerts are only the starting point

The Snort alert provided an entry point, but the complete incident could only be understood through correlation across multiple data sources.

A single alert does not explain:

* Initial access.
* Attacker objectives.
* Internal movement.
* Data exposure.

---

## 2. Encrypted traffic still provides intelligence

Although the C2 communication was encrypted, useful information could still be extracted through:

* Connection patterns.
* TLS fingerprints.
* Timing behaviour.
* Destination infrastructure.

Encrypted does not mean invisible.

---

## 3. Timeline reconstruction is critical

The investigation required connecting individual events into a sequence:

* Malware delivery.
* Execution.
* C2.
* Discovery.
* Lateral movement.
* Exfiltration.

Understanding the order of events transformed isolated logs into an attacker narrative.

---

## 4. Network visibility is essential for blue teams

Effective detection and response requires visibility across:

* Endpoints.
* Network traffic.
* DNS.
* Authentication activity.
* File transfers.

The investigation demonstrated how defenders can reconstruct attacker behaviour using network evidence alone.

---

# Final Takeaway

This investigation provided practical experience in network threat hunting and incident response.

By combining IDS alerts, Zeek telemetry, and packet-level analysis, it was possible to reconstruct the complete attack lifecycle — from initial compromise to C2 communication, lateral movement, and data exfiltration.

The biggest lesson was that effective detection is not just about finding malicious traffic; it is about understanding the story behind the traffic.
