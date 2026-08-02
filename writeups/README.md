# Writeups

CTF and lab writeups documenting my hands-on security work — enumeration, exploitation, privilege escalation, and the reasoning behind each step.

The goal here isn't a walkthrough you can copy-paste. It's a record of *how* I approached each box: what I tried, what failed, and why the working path worked.

---

## Index

| Room | Platform | Date | Difficulty | Focus | Writeup |
|------|----------|------|------------|-------|---------|
| Room 404 | TryHackMe | 2026-07-28 | Easy | Web / Enumeration | [Read](./tryhackme/room-404.md) |
| Complimentary | TryHackMe | 2026-07-29 | Easy | Cloud (AWS) / Web | [Read](./tryhackme/complimentary.md) |
| Packed Light | TryHackMe | 2026-07-30 | Easy | Forensics / Cryptography | [Read](./tryhackme/packed-light.md) |
| Beach Bar | TryHackMe | 2026-07-31 | Easy | Web / Boot2Root | [Read](./tryhackme/beach-bar.md) |
| The Silent Transfer | TryHackMe | 2026-07-31 | Medium | Blue Team / Forensics | [Read](./tryhackme/the-silent-transfer.md) |
| Overhead at Breakfast | TryHackMe | 2026-08-01 | Easy | OSINT | [Read](./tryhackme/overhead-at-breakfast.md) |
| Do Not Disturb | TryHackMe | 2026-08-02 | Medium | Web / Boot2Root | [Read](./tryhackme/do-not-disturb.md) |

---

## Structure

```
writeups/
├── README.md            # this file
├── tryhackme/
│   └── room-404.md
|   └── complimentary.md
|   └── packed-light.md
|   └── beach-bar.md
|   └── the-silent-transfer.md
|   └── overhead-at-breakfast.md
|   └── do-not-disturb.md
├── hackthebox/
└── assets/              # screenshots, diagrams
```

Each platform gets its own directory. Images live in `assets/<room-name>/` and are referenced with relative paths so they render correctly on GitHub.

---

## Writeup Format

Every writeup follows the same skeleton so they stay comparable and easy to skim:

1. **Overview** — room name, platform, difficulty, date completed, one-line summary
2. **Reconnaissance** — port scans, service versions, initial surface mapping
3. **Enumeration** — directory busting, subdomain discovery, source review, whatever the surface calls for
4. **Exploitation** — the vulnerability, why it exists, and how it was leveraged
5. **Privilege Escalation** — local enumeration and the path to root/SYSTEM
6. **Remediation** — how a defender would fix or detect this
7. **Key Takeaways** — what I learned, tools added to the kit, mistakes worth not repeating

---

## Tooling

Common across most writeups: `nmap`, `ffuf`/`gobuster`, `Burp Suite`, `netcat`, `linpeas`/`winPEAS`, `John the Ripper`, `hashcat`.

Room-specific tooling is called out inline where it appears.

---

## Notes on Disclosure

- Flags are **redacted** — you'll see `THM{REDACTED}` rather than the real value. The point is the methodology, not the answer key.
- Writeups are only published for rooms where the platform permits it. TryHackMe allows writeups for free rooms; anything under an active competition, subscriber-only restriction, or non-disclosure expectation stays unpublished.
- Everything documented here was performed in authorised lab environments against machines I was explicitly permitted to attack. None of this is intended for use against systems you don't own or have written permission to test.

---

## Contact

Questions, corrections, or a better path through a box than the one I took — issues and PRs welcome.
