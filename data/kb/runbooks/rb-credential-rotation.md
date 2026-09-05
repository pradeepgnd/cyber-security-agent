---
id: rb-credential-rotation
title: Credential rotation after suspected password compromise
source: internal IR
type: runbooks
tags:
- creds
severity: high
---

Rotate passwords and SSH keys for every account that saw a successful login from the attacker IP, plus root and any service account touched by sudo. Invalidate agent tokens. Check authorized_keys for implants. Force password expiry.
