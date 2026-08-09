# Management Wants a Word — TryHackMe Write-up

**Room:** Management Wants a Word
**Difficulty:** Hard
**Points:** 120
**Categories:** Forensics · Windows · Cryptography

## 🛎️ Concierge Briefing

A guest's laptop was left behind after an early checkout. The device belonged to **Vera**, and IT performed a full triage before the machine was due to be wiped.

The objective was to investigate the artifacts left across the system, uncover a password Vera had unintentionally exposed, and use it to access something she was trying to keep hidden.

The room's hint was particularly useful:

> "a browser will remember things for you that you never told anyone else 💀"

It also mentioned the version number **1.26.29**, which provided another potential clue during the investigation.

---

# 1. Initial Triage

After downloading the challenge files, I moved into the extracted KAPE directory:

```bash
cd /Downloads/management-wants-a-word-forensics-hh-day-14/KAPE
```

The first interesting artifact was:

```text
C/Users/vera/Documents/backup
```

I checked what type of file it was:

```bash
file C/Users/vera/Documents/backup
```

and examined its header:

```bash
xxd -l 64 C/Users/vera/Documents/backup
```

The file turned out to be a **VeraCrypt container**, which immediately suggested that the investigation would eventually involve decrypting and mounting it.

However, the challenge was clearly pointing towards a password, so rather than attempting to crack the container, I started looking for credentials and other useful artifacts belonging to Vera.

---

# 2. Hunting for Browser Artifacts

Chrome stores several useful databases inside the user's profile.

I searched Vera's profile for the key browser artifacts:

```bash
find C/Users/vera -type f \
  \( -iname 'Login Data' \
  -o -iname 'Local State' \
  -o -iname 'Web Data' \
  -o -iname 'History' \) -print
```

The important files were:

| Artifact      | What it contains                        |
| ------------- | --------------------------------------- |
| `History`     | Browser history and searches            |
| `Login Data`  | Saved usernames and encrypted passwords |
| `Web Data`    | Autofill information                    |
| `Local State` | Chrome's encrypted key material         |

The `Login Data` and `Web Data` databases were particularly interesting.

---

# 3. Examining Saved Browser Credentials

The Chrome `Login Data` database is SQLite.

I opened it with:

```bash
sqlite3 'path/to/Login Data'
```

Then enabled readable output:

```sql
.headers on
.mode column
```

I queried the saved credentials:

```sql
SELECT
    origin_url,
    action_url,
    username_value,
    hex(password_value) AS encrypted_password
FROM logins;
```

The passwords were encrypted, but the database confirmed that Chrome had stored credentials belonging to Vera.

This was significant because the challenge hint specifically suggested that the browser had "remembered" something Vera hadn't intended to reveal.

---

# 4. Investigating Autofill Data

Next, I examined Chrome's `Web Data` database:

```bash
sqlite3 'path/to/Web Data'
```

I queried the autofill entries:

```sql
SELECT name, value, date_created, date_last_used
FROM autofill
ORDER BY date_last_used DESC;
```

Autofill data can contain useful information such as names, addresses, usernames and other values that a user has entered into websites.

This reinforced the importance of looking at browser artifacts rather than immediately attempting password cracking.

---

# 5. Locating Vera's Windows DPAPI Master Key

Chrome's saved credentials ultimately depend on Windows **DPAPI** (Data Protection API).

I searched Vera's DPAPI directory:

```bash
find C/Users/vera/AppData/Roaming/Microsoft/Protect \
  -type f -printf '%f %p\n'
```

This revealed Vera's SID:

```text
S-1-5-21-2529683458-431225740-1723070931-1000
```

and the relevant master-key GUID:

```text
c90719ef-5b98-474e-b934-136d606a702a
```

At this point, I needed Vera's Windows credentials to decrypt the DPAPI material.

---

# 6. Extracting the Windows Password

The Windows registry hives were included in the forensic image:

```text
C/Windows/System32/config/SAM
C/Windows/System32/config/SYSTEM
C/Windows/System32/config/SECURITY
```

I used Impacket's `secretsdump` to inspect the local account secrets:

```bash
impacket.secretsdump \
  -sam C/Windows/System32/config/SAM \
  -system C/Windows/System32/config/SYSTEM \
  -security C/Windows/System32/config/SECURITY \
  LOCAL
```

Among the output was:

```text
[*] DefaultPassword
(Unknown User):minivera
```

This gave me the password:

```text
minivera
```

This was the key breakthrough.

Rather than brute-forcing Chrome or the VeraCrypt container, the Windows password could be used to recover the DPAPI-protected key material.

---

# 7. Decrypting Vera's DPAPI Master Key

I used the recovered password together with Vera's SID and master-key file:

```bash
impacket.dpapi masterkey \
  -file 'C/Users/vera/AppData/Roaming/Microsoft/Protect/S-1-5-21-2529683458-431225740-1723070931-1000/c90719ef-5b98-474e-b934-136d606a702a' \
  -sid 'S-1-5-21-2529683458-431225740-1723070931-1000' \
  -password 'minivera'
```

The master key was successfully decrypted:

```text
Decrypted key with User Key (SHA1)
Decrypted key: 0x5e5715ec9b6df5a86e97902692a66d28e691f05d5bc1e04d0159cfe960e94c978c07e5004a0179d3a96df2468885a28175b0b02cc064445f116a752d2b3e9d40
```

I stored the resulting key for the next stage:

```bash
MASTERKEY='5e5715ec9b6df5a86e97902692a66d28e691f05d5bc1e04d0159cfe960e94c978c07e5004a0179d3a96df2468885a28175b0b02cc064445f116a752d2b3e9d40'
```

---

# 8. Extracting Chrome's AES Key

Chrome's `Local State` file contains the DPAPI-protected encryption key used for stored credentials.

I located it with:

```bash
LOCAL_STATE="$(find "$PWD/C/Users/vera" \
  -type f -iname 'Local State' -print -quit)"

printf '%s\n' "$LOCAL_STATE"
```

The encrypted key is stored as Base64.

I decoded it:

```bash
jq -r '.os_crypt.encrypted_key' "$LOCAL_STATE" |
base64 -d |
xxd
```

The resulting data begins with the five-byte `DPAPI` prefix.

I removed that prefix:

```bash
jq -r '.os_crypt.encrypted_key' "$LOCAL_STATE" |
base64 -d |
tail -c +6 > chrome-key.dpapi
```

I could now decrypt this blob using the DPAPI master key recovered earlier.

---

# 9. Recovering Chrome's AES Key

I used Python with Impacket's DPAPI implementation:

```python
import sys
from impacket.dpapi import DPAPI_BLOB

masterkey = bytes.fromhex(sys.argv[1])

with open("chrome-key.dpapi", "rb") as f:
    blob = DPAPI_BLOB(f.read())

decrypted = blob.decrypt(masterkey)

if decrypted is None:
    raise SystemExit("DPAPI decryption failed")

with open("chrome-aes.key", "wb") as f:
    f.write(decrypted)

print(f"Wrote {len(decrypted)} bytes")
print(f"Chrome AES key: {decrypted.hex()}")
```

The resulting key was written to:

```text
chrome-aes.key
```

I verified its size:

```bash
wc -c chrome-aes.key
```

The result was **32 bytes**, consistent with the AES key required to decrypt the Chrome credential.

---

# 10. Decrypting Vera's Saved Chrome Password

I located the `Login Data` database:

```bash
LOGIN_DATA="$(find "$PWD/C/Users/vera" \
  -type f -iname 'Login Data' -print -quit)"

printf '%s\n' "$LOGIN_DATA"
```

Chrome's modern stored credentials use formats such as `v10` and `v11`.

The encrypted password can therefore be parsed into:

* Version prefix
* 12-byte AES-GCM nonce
* Ciphertext
* Authentication tag

I used Python and `cryptography`'s `AESGCM` implementation:

```python
import sqlite3
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

database = Path(sys.argv[1]).resolve()
keyfile = Path(sys.argv[2]).resolve()

key = keyfile.read_bytes()

if len(key) != 32:
    raise SystemExit(f"Unexpected AES key length: {len(key)}")

db = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)

for url, username, encrypted in db.execute("""
    SELECT origin_url, username_value, password_value
    FROM logins
"""):
    blob = bytes(encrypted)

    if not blob.startswith((b"v10", b"v11")):
        print(f"Unsupported format: {blob[:10]!r}")
        continue

    nonce = blob[3:15]
    ciphertext_and_tag = blob[15:]

    password = AESGCM(key).decrypt(
        nonce,
        ciphertext_and_tag,
        None
    ).decode("utf-8", errors="replace")

    print(f"URL:      {url}")
    print(f"Username: {username}")
    print(f"Password: {password}")
```

The decrypted credential was:

```text
Username: VeraSecretVault
Password: Wh4t1sV3raD0inG0nTh1sH0st
```

This looked much more interesting than a normal website credential.

The username itself — `VeraSecretVault` — strongly suggested that this password was intended to unlock the hidden VeraCrypt container found earlier.

---

# 11. Opening the VeraCrypt Container

The initial file identified during triage was:

```text
C/Users/vera/Documents/backup
```

Rather than installing VeraCrypt, Linux's `cryptsetup` can work with VeraCrypt containers.

I opened the container using:

```bash
sudo cryptsetup tcryptOpen \
  --veracrypt \
  'C/Users/vera/Documents/backup' \
  vera_backup
```

I then mounted the decrypted volume read-only:

```bash
sudo mkdir -p /mnt/vera
sudo mount -o ro /dev/mapper/vera_backup /mnt/vera
```

Mounting it read-only was appropriate for a forensic investigation because it minimises the risk of modifying evidence.

---

# 12. Finding the Hidden Documents

The mounted volume contained:

```bash
ls /mnt/vera/
```

Output:

```text
'$RECYCLE.BIN'
'System Volume Information'
secret_financial_documents
```

The interesting directory was:

```bash
ls /mnt/vera/secret_financial_documents/
```

which contained:

```text
important_invoice_byte_lotus.pdf
transactions_q3.csv
```

The PDF was the final lead.

I opened:

```bash
xdg-open /mnt/vera/secret_financial_documents/important_invoice_byte_lotus.pdf
```

The document contained the hidden flag.

---

# 🚩 Flag

```text
THM{Redacted}
```

---

# 🧠 Investigation Chain

The entire challenge can be summarised as a chain of artifacts:

```text
Forensic Image
      │
      ├── VeraCrypt container
      │       └── C/Users/vera/Documents/backup
      │
      ├── Windows Registry Hives
      │       └── Vera's password → minivera
      │
      ├── Windows DPAPI
      │       └── Master Key
      │
      ├── Chrome Local State
      │       └── DPAPI-protected AES key
      │
      ├── Chrome Login Data
      │       └── Encrypted credential
      │
      ├── AES-GCM decryption
      │       └── VeraSecretVault
      │           └── Wh4t1sV3raD0inG0nTh1sH0st
      │
      ├── VeraCrypt container
      │       └── secret_financial_documents
      │
      └── important_invoice_byte_lotus.pdf
              └── 🚩 Flag
```

## 🔍 Key Takeaways

This room was a great demonstration of how different Windows artifacts can be chained together during forensic analysis.

The important lesson wasn't simply "find the password." It was understanding **how the artifacts relate to each other**:

1. Identify interesting files during initial triage.
2. Recognise the VeraCrypt container but don't immediately try to crack it.
3. Investigate Chrome artifacts for potentially recoverable credentials.
4. Understand that Chrome's credentials are protected using Windows DPAPI.
5. Recover the Windows password from the registry hives.
6. Use the password to decrypt Vera's DPAPI master key.
7. Use the DPAPI master key to recover Chrome's AES key.
8. Decrypt the saved Chrome credential.
9. Recognise that credential as the password for the VeraCrypt container.
10. Mount the container read-only and investigate its contents.
11. Locate the final document containing the flag.

The challenge was a good reminder that **forensic investigations are often about connecting seemingly unrelated artifacts rather than attacking the final target directly.**

---

## 🛠️ Tools Used

* KAPE forensic image
* `file`
* `xxd`
* `find`
* SQLite / `sqlite3`
* `jq`
* `base64`
* Impacket

  * `secretsdump`
  * `dpapi`
* Python
* `cryptography`
* AES-GCM
* `cryptsetup`
* Linux mounting utilities
* Chrome forensic artifacts
* Windows Registry hives
* Windows DPAPI

---

## Conclusion

`Management Wants a Word` was a challenging but rewarding forensic investigation involving **Windows credential recovery, DPAPI, Chrome encryption, AES-GCM, and VeraCrypt**.

What initially appeared to be an inaccessible encrypted backup turned out to be reachable through a chain of artifacts that Vera had unknowingly left behind.

The browser remembered the credential.

The credential unlocked the container.

And the container led to the flag.
