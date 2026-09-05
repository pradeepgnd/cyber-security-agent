---
id: rb-log4shell-eradication
title: Eradicate Log4Shell
source: internal IR
type: runbooks
tags:
- log4j
- rce
severity: critical
---

Remove JndiLookup.class or upgrade log4j-core to 2.17.1+. Grep images and hosts for `JndiLookup` and `log4j-core-2.1`. Rotate any secrets the app could read. Rebuild rather than hot-patch when the classloader already loaded the gadget.
