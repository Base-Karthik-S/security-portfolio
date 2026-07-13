# Security Portfolio

A hands-on, operator-focused security portfolio: realistic infrastructure, adversary tradecraft, detection engineering, triage, and reporting.

## Projects

### [Project 1 — Attack & Defend: a purple-team home SOC](./project-1-home-soc/)
A small Active Directory lab, attacked with real ATT&CK tradecraft and defended with custom detections. Produces a growing library of Sigma detections, each paired with the attack that triggered it and a one-page incident report.

### [Project 2 — Live threat-intel honeypot](./project-2-honeypot/) *(later)*
Internet-facing honeypots feeding a Python enrichment pipeline, a live dashboard, and monthly CTI reports.

## ATT&CK coverage

_A coloured ATT&CK Navigator layer will live here once the first detections land._

## Repo hygiene

Credentials, TLS material, and stack data are **git-ignored** (see `.gitignore`). Nothing sensitive is ever committed — a deliberate OpSec choice, not an afterthought.
