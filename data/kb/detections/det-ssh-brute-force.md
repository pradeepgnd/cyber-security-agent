---
id: det-ssh-brute-force
title: SSH repeated failed password
source: Sigma-style
type: detections
tags:
- ssh
- T1110
severity: high
---

Detect repeated failed password events from a single source IP against sshd.
Condition: count(Failed password OR Invalid user) by src_ip >= 8 within 10 minutes.
This is the primary brute-force rule. Tuning: ignore jump-hosts that naturally fail once.
