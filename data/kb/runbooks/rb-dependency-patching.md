---
id: rb-dependency-patching
title: Emergency dependency patching
source: internal IR
type: runbooks
tags:
- patch
severity: high
---

Pin the fixed version in requirements.txt / pom.xml / the image. Rebuild, scan again, deploy. Record the CVE and fixed version in the change ticket. Do not leave a vulnerable JAR on disk even if unused.
