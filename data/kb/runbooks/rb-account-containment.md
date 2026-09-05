---
id: rb-account-containment
title: Contain attacker-created local accounts
source: internal IR
type: runbooks
tags:
- account
severity: high
---

Lock or delete accounts created post-compromise (`useradd`). Review crontab, systemd user units, and ~/.ssh for those UIDs. Preserve the passwd/shadow copies for forensics before deletion.
