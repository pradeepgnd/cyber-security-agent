---
id: AC-7
title: AC-7 Unsuccessful Logon Attempts
source: NIST 800-53
type: controls
tags:
- nist
- auth
severity: high
---

Enforce a limit of consecutive unsuccessful logon attempts and automatically lock or delay the account/source. Absence of fail2ban, sshd MaxAuthTries hardening, or lockout after repeated failed password events is a FAIL for brute-force incidents.
