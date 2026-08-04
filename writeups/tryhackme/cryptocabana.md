# TryHackMe – CryptoCabana Write-up (Cloud)

**Category:** Cloud
**Difficulty:** Medium
**Platform:** TryHackMe
**Flag:** `THM{Redacted}`

---

# Objective

The challenge revolves around an Azure-hosted web application advertising a cryptocurrency seed phrase backup service. The goal is to identify what the application implicitly trusts, pivot through exposed Azure resources, and recover the complete flag.

The challenge focuses on several Azure services:

* Azure Storage
* Shared Access Signatures (SAS)
* Azure Blob Storage
* Azure Key Vault
* Azure Service Principals

---

# Initial Enumeration

The supplied web application consisted of a single page allowing users to "back up" a seed phrase.

Inspecting the page source revealed a linked JavaScript file (`app.js`).

Reviewing the JavaScript exposed several interesting constants:

```javascript
const STORAGE_ACCOUNT = "cryptocabanaf5scjagc";
const BACKUPS_CONTAINER = "backups";
const BACKUP_SAS = "?sv=2022-11-02&ss=b&srt=sco&sp=rl&..."
```

Immediately, several valuable pieces of information became available:

* Storage Account name
* Blob container name
* Long-lived Azure SAS token

---

# Analysing the SAS Token

Breaking down the SAS token showed:

| Parameter | Meaning                              |
| --------- | ------------------------------------ |
| ss=b      | Blob service                         |
| srt=sco   | Service, Container and Object access |
| sp=rl     | Read + List permissions              |
| se=2099   | Extremely long expiry                |

The JavaScript attempted to upload files using an HTTP PUT request.

However, the SAS only granted **Read** and **List** permissions.

As expected, attempting to upload resulted in a failure.

This suggested that uploading was merely a distraction while the leaked SAS token was the actual attack vector.

---

# Enumerating Azure Storage

Using the Azure Storage REST API with the exposed Account SAS:

```text
https://cryptocabanaf5scjagc.blob.core.windows.net/?comp=list&<SAS>
```

returned:

* `$web`
* `backups`
* `vault`

The **vault** container had never been referenced anywhere within the application.

This matched the challenge hint:

> "Follow that trust somewhere the kiosk's own page never once points you."

---

# Enumerating the Hidden Container

Listing the blobs inside the `vault` container produced:

* `backup-service-account.json`
* `seed_phrase.txt`

The next step was downloading these blobs.

Using Azure CLI:

```bash
az storage blob download \
    --account-name cryptocabanaf5scjagc \
    --container-name vault \
    --name backup-service-account.json \
    --file backup-service-account.json \
    --sas-token "<SAS>"
```

The same process was repeated for `seed_phrase.txt`.

---

# Sensitive Information Disclosure

Viewing the downloaded JSON file revealed:

* Client ID
* Client Secret
* Tenant ID
* Key Vault name
* Key Vault URI

Example structure:

```json
{
    "client_id": "...",
    "client_secret": "...",
    "tenant_id": "...",
    "key_vault_name": "...",
    "key_vault_uri": "..."
}
```

This represented a complete Azure Service Principal.

The accompanying note:

> "Rotate this if it ever leaves the vault."

served as an obvious hint that the credential itself should never have been exposed.

---

# Azure Authentication

Using the leaked Service Principal credentials:

```bash
az login \
    --service-principal \
    --username <client-id> \
    --password <client-secret> \
    --tenant <tenant-id>
```

Authentication succeeded, providing access to the Azure subscription associated with the application.

---

# Key Vault Enumeration

With access established, the next objective was Azure Key Vault.

Listing available secrets:

```bash
az keyvault secret list \
    --vault-name ccabana-kv-f5scjagc
```

revealed three secrets:

* key-shard-1
* key-shard-2
* key-shard-3

At first glance it appeared that each contained one portion of the final flag.

---

# Secret Versioning

The challenge description contained an important clue:

> "if a value looks freshly rotated, ask yourself what it looked like five minutes before that"

This suggested Azure Key Vault secret versioning.

Checking versions for **key-shard-2**:

```bash
az keyvault secret list-versions \
    --vault-name ccabana-kv-f5scjagc \
    --name key-shard-2
```

returned two versions.

Retrieving each version individually:

```bash
az keyvault secret show \
    --vault-name ccabana-kv-f5scjagc \
    --name key-shard-2 \
    --version <version-id>
```

revealed that the **older version** contained the correct shard, while the current version had been rotated.

The remaining secrets (`key-shard-1` and `key-shard-3`) only required reading their latest values.

---

# Reconstructing the Flag

The final flag was reconstructed by combining:

* key-shard-1 (current)
* key-shard-2 (previous version)
* key-shard-3 (current)

Result:

```
THM{Redacted}
```

---

# Attack Path Summary

```
Web Application
        │
        ▼
Client-side JavaScript
        │
        ▼
Leaked Azure Account SAS
        │
        ▼
Storage Account Enumeration
        │
        ▼
Hidden "vault" Container
        │
        ▼
Service Principal Credentials
        │
        ▼
Azure CLI Authentication
        │
        ▼
Azure Key Vault
        │
        ▼
Enumerate Secrets
        │
        ▼
Inspect Secret Versions
        │
        ▼
Recover Previous Secret Value
        │
        ▼
Assemble Flag
```

---

# Key Takeaways

This challenge demonstrates several common Azure security pitfalls:

* Sensitive credentials should never be embedded in client-accessible resources.
* SAS tokens should follow the principle of least privilege and have appropriate expiry times.
* Blob Storage enumeration can expose unintended resources when overly permissive SAS tokens are leaked.
* Service Principal credentials must be treated as highly sensitive and should never be stored in publicly accessible storage.
* Azure Key Vault secret versioning preserves historical values; rotating a secret without managing previous versions can still expose sensitive information.
* Small cloud misconfigurations can chain together into a complete compromise, highlighting the importance of defense in depth.

---

# Final Flag

```
THM{Redacted}
```
