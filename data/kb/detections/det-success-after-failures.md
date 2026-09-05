---
id: det-success-after-failures
title: SSH success after failures
source: Sigma-style
type: detections
tags:
- ssh
- T1078
severity: critical
---

Accepted password for a user from an IP that generated repeated failed password lines in the prior window. High confidence compromise of a valid account. Alert immediately; do not wait for user add.
