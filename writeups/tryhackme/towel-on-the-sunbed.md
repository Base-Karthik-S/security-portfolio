# Towel on the Sunbed (Web) - Write-up

**Platform:** TryHackMe  
**Category:** Web Exploitation  
**Difficulty:** Medium  
**Techniques:** Business Logic Abuse, Race Condition (TOCTOU), Burp Suite

---

# Challenge Description

The application, **Ponzi – Wellness Rewards**, allows authenticated users to claim a daily cryptocurrency reward. Once a user's balance reaches **150 PONZI**, they are eligible to access the **Whale Vault**, which contains the challenge flag.

Several hints in the challenge description point towards a flaw in the reward system:

> "...claimed his daily reward..."

> "...came back to find the sunbed had been claimed three times..."

> "...between his request and the server's clock, there's a gap..."

The challenge tags also include:

- Web Exploitation
- Business Logic
- Burp Suite
- API Abuse

These strongly suggest a business logic vulnerability rather than a traditional web vulnerability such as SQL Injection or XSS.

---

# Reconnaissance

After registering a new account and logging into the dashboard, the application displayed:

- Current PONZI balance
- Reward claim button
- Countdown timer until the next claim
- Whale Vault button (disabled until 150 PONZI)

Inspecting the frontend JavaScript (`dashboard.js`) revealed the reward mechanism.

The reward is claimed using a simple POST request:

```http
POST /claim HTTP/1.1
Host: <target>

Cookie: connect.sid=<session>
```

No request body or client-side parameters are required.

The server determines everything from the authenticated session.

---

# Analysing the Frontend

The reward button simply performs:

```javascript
await fetch('/claim', {
    method: 'POST'
});
```

After a successful response, the dashboard reloads the user's information.

The Whale Vault button is enabled only if:

```javascript
vaultBtn.disabled = data.balance < 150;
```

However, this is **only a client-side restriction**.

The actual authorization must occur on the server.

---

# Initial Testing

Claiming the reward once returned:

```json
{
    "message": "Staking reward claimed successfully.",
    "reward": 50,
    "newBalance": 50,
    "tier": "Shrimp",
    "priceSnapshot": 4.2
}
```

Immediately replaying the request produced an error indicating the reward could only be claimed once every 24 hours.

At first glance, the cooldown appeared to be enforced correctly.

---

# Identifying the Vulnerability

The challenge description repeatedly references:

- claiming multiple times
- a gap between the request and the server
- business logic

These clues strongly suggest a **Race Condition**, specifically a **Time-of-Check to Time-of-Use (TOCTOU)** vulnerability.

A vulnerable implementation typically resembles:

```text
Check whether user can claim
        │
        ▼
Reward user
        │
        ▼
Update lastClaim timestamp
```

If multiple requests reach the server simultaneously, each request may perform the "check" before any request updates the claim timestamp.

This allows multiple rewards to be issued.

---

# Exploitation

The `/claim` request was intercepted in Burp Suite and sent to **Repeater**.

The request was duplicated multiple times.

Using **Send Group (Parallel)**, twenty identical requests were sent simultaneously.

```
POST /claim
POST /claim
POST /claim
POST /claim
...
```

Because the requests were processed concurrently, several of them passed the cooldown check before the server updated the user's last claim timestamp.

The balance increased far beyond the intended **50 PONZI** reward.

---

# Accessing the Whale Vault

Once the balance exceeded **150 PONZI**, the protected endpoint became accessible.

Navigating to:

```
/vault
```

returned:

```json
{
    "flag": "THM{REDACTED}"
}
```

The challenge was successfully completed.

---

# Root Cause

The application suffers from a classic **TOCTOU (Time-of-Check to Time-of-Use)** race condition.

Instead of performing the eligibility check and reward update atomically, the server likely performs:

```text
if (canClaim)
{
    addReward();
    updateLastClaim();
}
```

When many requests arrive simultaneously:

```
Request 1 → canClaim == true
Request 2 → canClaim == true
Request 3 → canClaim == true
```

Each request observes the same state before any request updates it.

As a result, multiple rewards are issued.

A secure implementation would:

- perform the check and update inside a database transaction,
- use row-level locking,
- or implement an atomic update preventing concurrent claims.

---

# Lessons Learned

This challenge demonstrates that business logic flaws can be just as impactful as traditional injection vulnerabilities.

Important indicators that suggest a race-condition challenge include:

- Daily reward systems
- Cooldown timers
- Financial balances
- Coupon redemption
- Inventory reservation
- Challenge hints referencing "multiple claims" or "timing"

Whenever a web application allows a limited action (claiming rewards, redeeming coupons, purchasing limited stock), it is worth testing whether concurrent requests can bypass the intended restriction.

---

# Tools Used

- Burp Suite
    - Proxy
    - Repeater
    - Send Group (Parallel)
- Firefox
- Developer Tools

---

# Key Takeaways

- Identified a business logic vulnerability from challenge hints.
- Analysed the frontend JavaScript to understand the application workflow.
- Confirmed the reward endpoint (`POST /claim`).
- Exploited a TOCTOU race condition by sending concurrent requests.
- Increased the account balance beyond the Whale Vault threshold.
- Retrieved the flag from `/vault`.

---

**Vulnerability:** Race Condition (TOCTOU)

**OWASP Category:** Business Logic / Race Condition

**Difficulty:** Medium
