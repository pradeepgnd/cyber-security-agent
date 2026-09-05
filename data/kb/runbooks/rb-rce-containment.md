---
id: rb-rce-containment
title: Contain a public-facing RCE
source: internal IR
type: runbooks
tags:
- rce
severity: critical
---

Take the vulnerable endpoint out of the load balancer or WAF-block the exploit pattern (`jndi`, `${`, OGNL). Isolate the compute instance. Capture memory and container filesystem. Assume the process spawned a child — hunt outbound LDAP/RMI/DNS.
