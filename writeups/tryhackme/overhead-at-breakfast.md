# TryHackMe Write-up – Overheard at Breakfast

## Room Objective

The objectives for this room were:

* Analyse the provided conversation.
* Extract identifying information.
* Locate the hidden online account.
* Recover the encoded flag.

---

# Initial Enumeration

The challenge provides a screenshot of a conversation between two individuals at the Byte Lotus Resort. Rather than immediately searching for usernames, I first extracted every potentially useful identifier from the conversation.

Interesting observations included:

* Nickname: **Lambo**
* Email address:
  ```
  lambobytelotushotel@gmail.com
  ```
* Mention of a free profile-hosting service.
* Hint that the service **started with the letter "G"**.

The room description also included an important hint:

> *"Read what they said, not just skim it."*

This suggested that the wording of the conversation itself would provide the intended investigative pivot.

---

# Investigating the Email Address

My initial approach was to investigate the email address:

```text
lambobytelotushotel@gmail.com
```

I performed several standard OSINT checks, including searching for publicly indexed accounts associated with the address.

These searches did not reveal any useful information.

Since the email produced no meaningful results, I revisited the conversation to identify alternative pivots.

---

# Identifying the OSINT Pivot

One sentence stood out during a second reading:

> "I used to use this free tool that let me upload my profile and link other media accounts... Started with a G if I remember correctly."

Rather than being casual conversation, this was the key clue provided by the room.

The description closely matches **Gravatar**, a free profile service that allows users to:

* Upload a profile picture
* Create a public profile
* Link social media accounts
* Associate the profile with an email address

This became the next investigative step.

---

# Investigating the Gravatar Profile

Using a Gravatar email lookup tool with the recovered email address successfully located a public profile.

The profile contained:

* Public profile information
* Associated metadata
* An encoded value embedded within the profile

Although the account itself was the intended discovery, the encoded value represented the final stage of the challenge.

---

# Decoding the Flag

The recovered value was Base64 encoded.

To decode it, I used **CyberChef** with the following recipe:

```text
From Base64
```

The decoded output revealed the final TryHackMe flag.

---

# Investigation Workflow

```text
Conversation Screenshot
        │
        ▼
Extract identifiers
        │
        ├── Nickname
        ├── Email address
        └── Conversation clues
                │
                ▼
Investigate email
                │
          No useful results
                │
                ▼
Re-read conversation
                │
                ▼
Identify "G" profile service
                │
                ▼
Investigate Gravatar
                │
                ▼
Locate encoded value
                │
                ▼
Decode using CyberChef
                │
                ▼
Recover the flag
```

---

# Key Takeaways

* Careful reading is often more valuable than immediately using automated tools.
* Conversations frequently contain subtle OSINT pivots hidden in natural language.
* Public profile aggregation services such as Gravatar can expose valuable information linked to an email address.
* When an initial lead produces no results, reassessing the available evidence can reveal the intended investigation path.
* CyberChef remains an invaluable tool for decoding common encodings encountered during OSINT investigations.

---

# MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1589 | Gather Victim Identity Information |
| T1593 | Search Open Websites/Domains |
| T1596 | Search Open Technical Databases |

---

# Blue Team Perspective

From a defensive standpoint, this challenge highlights how seemingly harmless public information can be combined to reveal additional details about an individual.

Defensive recommendations include:

* Minimise publicly available profile information.
* Regularly audit linked online accounts.
* Avoid exposing unnecessary personal details through profile aggregation services.
* Periodically review your digital footprint using OSINT techniques.

---

# Skills Practiced

* Open Source Intelligence (OSINT)
* Information gathering
* Email investigation
* Digital footprint analysis
* Public profile enumeration
* Evidence correlation
* Base64 decoding
* CyberChef
* Analytical problem solving
