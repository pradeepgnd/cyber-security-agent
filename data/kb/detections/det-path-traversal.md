---
id: det-path-traversal
title: HTTP path traversal
source: Sigma-style
type: detections
tags:
- T1190
severity: medium
---

Request path contains `../` or `%2e%2e`. Common scanner noise; escalate when paired with 200s on /etc/passwd or similar.
