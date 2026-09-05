---
id: det-outbound-ldap
title: Outbound LDAP after HTTP 200
source: Sigma-style
type: detections
tags:
- c2
- log4shell
severity: critical
---

App host opens TCP/389 or TCP/1389 shortly after serving a request with a JNDI payload. Confirms the lookup fired — treat as successful RCE until proven otherwise.
