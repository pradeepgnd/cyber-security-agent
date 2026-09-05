---
id: rb-harden-ssh
title: Harden SSH and logging
source: internal IR
type: runbooks
tags:
- harden
- ssh
severity: medium
---

PasswordAuthentication no, PermitRootLogin no, MaxAuthTries 3, allow-list admin IPs, install fail2ban, ship auth.log to the SIEM with a brute-force correlation rule. Enable MFA for break-glass.
