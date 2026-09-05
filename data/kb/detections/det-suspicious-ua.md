---
id: det-suspicious-ua
title: Exploit-kit user agent
source: Sigma-style
type: detections
tags:
- recon
severity: low
---

User-Agent contains `${jndi` or known scanner tokens (`masscan`, `nikto`). Low severity alone; raises confidence of a JNDI finding.
