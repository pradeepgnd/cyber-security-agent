---
id: rb-ssh-brute-force
title: SSH brute-force containment
source: internal IR
type: runbooks
tags:
- ssh
- brute
severity: high
---

Contain first: block the source IP at the edge and in hosts.allow/iptables. Disable password authentication if key auth is already in use. Snapshot auth.log and lastlog. Do not reboot yet — preserve volatile sshd state. Then move to credential rotation.
