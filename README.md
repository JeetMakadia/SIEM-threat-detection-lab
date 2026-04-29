# SIEM Threat Detection Home Lab

A fully functional Security Operations Center (SOC) home lab built from scratch using **Splunk Enterprise**, **Sysmon**, and **VirtualBox**. This lab simulates real-world attack scenarios and detects them using custom SPL detection rules, covering four MITRE ATT&CK techniques.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 VirtualBox Host-Only Network                 │
│                      192.168.57.0/24                        │
│                                                              │
│  ┌─────────────────┐         ┌─────────────────┐            │
│  │  WIN-ENDPOINT   │         │  Linux-Endpoint  │            │
│  │  192.168.57.20  │         │  192.168.57.30   │            │
│  │                 │         │                  │            │
│  │  • Sysmon       │         │  • HEC Forwarder │            │
│  │  • Splunk UF    │         │  • auth.log      │            │
│  │  • Windows 10   │         │  • Ubuntu 24.04  │            │
│  └────────┬────────┘         └────────┬─────────┘            │
│           │  port 9997                │  port 8088 (HEC)     │
│           └──────────────┬────────────┘                      │
│                          │                                   │
│                 ┌────────▼────────┐                          │
│                 │   SIEM VM       │                          │
│                 │ 192.168.57.10   │                          │
│                 │                 │                          │
│                 │ Splunk          │                          │
│                 │ Enterprise      │                          │
│                 │ :8000 Web UI    │                          │
│                 └─────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Tools & Technologies

| Tool | Version | Purpose |
|------|---------|---------|
| Splunk Enterprise | 10.2.2 | SIEM — log indexing, searching, alerting |
| Splunk Universal Forwarder | 10.2.2 | Windows log shipping agent |
| Sysmon | v15.20 | Windows endpoint telemetry |
| SwiftOnSecurity Config | Latest | Community Sysmon ruleset |
| VirtualBox | 7.x | Hypervisor |
| Ubuntu Server | 24.04 LTS | SIEM VM + Linux endpoint |
| Windows 10 | Business | Target endpoint |

---

## Detections Built

### 1. Windows Brute Force Login
**MITRE:** T1110 | **Severity:** High | **Event ID:** 4625

Detects 5+ failed logon attempts within a 5-minute window on the same machine. Fires on automated credential stuffing and password spraying attacks.

```spl
index=wineventlog EventCode=4625
| bucket _time span=5m
| stats count by _time, ComputerName
| where count > 5
```

---

### 2. Encoded PowerShell Execution
**MITRE:** T1059.001 | **Severity:** High | **Source:** Sysmon Event ID 1

Detects PowerShell launched with -EncodedCommand flag. Attackers use Base64 encoding to evade command-line logging and AV detection.

```spl
index=sysmon source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| search _raw="*EncodedCommand*"
| rex field=_raw "CommandLine>(?P<CommandLine>[^&]+)"
| rex field=_raw "User>(?P<User>[^&]+)"
| table _time, host, User, CommandLine
```

---

### 3. Unauthorized Admin Account Creation
**MITRE:** T1136.001 + T1078.003 | **Severity:** Critical | **Event IDs:** 4720, 4732

Detects new local user account creation combined with addition to the Administrators group. Classic attacker persistence technique.

```spl
index=wineventlog EventCode=4720 OR EventCode=4732
| table _time, ComputerName, Account_Name
```

---

### 4. Linux SSH Brute Force
**MITRE:** T1110 + T1021.004 | **Severity:** High | **Source:** auth.log via HEC

Detects repeated SSH authentication failures from the same source IP. Captures both valid and invalid username attacks.

```spl
index="linux-logs" "Failed password"
| rex field=_raw "Failed password for (?:invalid user )?(?P<username>\w+) from (?P<src_ip>[\w:\.]+)"
| stats count by src_ip, username
| where count > 5
```

---

## SOC Dashboard

9-panel real-time monitoring dashboard covering:

- Failed logon attempts over time (line chart)
- Top targeted accounts (bar chart)
- Encoded PowerShell executions (events viewer)
- New admin account activity (events viewer)
- Total Windows events (single value)
- Top Event IDs (pie chart)
- SSH attack sources (bar chart)
- SSH failures over time (line chart)
- Total Linux events (single value)

---

## Lab Statistics

| Metric | Value |
|--------|-------|
| Total events collected | 1,900+ |
| Sysmon events | 424+ |
| Windows Security events | 1,476+ |
| Linux auth events | Active |
| Detection alerts | 4 |
| Dashboard panels | 9 |
| MITRE techniques covered | 5 |

---

## Repository Structure

```
siem-threat-detection-lab/
│
├── README.md
│
├── detections/
│   ├── 01_brute_force_detection.spl
│   ├── 02_encoded_powershell.spl
│   ├── 03_new_admin_account.spl
│   └── 04_linux_ssh_brute_force.spl
│
├── configs/
│   ├── splunk_config_reference.txt
│   ├── sysmon_config_reference.txt
│   └── network_config.txt
│
├── docs/
│   ├── SIEM_Lab_Complete_Setup_Guide.docx
│   └── SIEM_Lab_Full_Documentation.docx
│
└── screenshots/
    ├── splunk_dashboard.png
    ├── brute_force_detection.png
    ├── powershell_detection.png
    ├── admin_account_detection.png
    └── linux_ssh_detection.png
```

---

## Setup Guide

Full step-by-step setup guide available in `docs/SIEM_Lab_Complete_Setup_Guide.docx`. Covers:

- VirtualBox and VM provisioning
- Ubuntu 24.04 netplan static IP configuration
- Splunk Enterprise installation and web interface binding fix
- Sysmon installation with SwiftOnSecurity config
- Splunk Universal Forwarder configuration
- Linux HEC log forwarding setup
- All four attack simulations
- Dashboard creation

---

## Key Lessons Learned

| Problem | Solution |
|---------|----------|
| Splunk web UI not accessible | Add server.socket_host=0.0.0.0 to web.conf |
| Netplan IP not applying | Check for duplicate files with ls -la /etc/netplan/ |
| rsyslog data not reaching Splunk | Use HEC instead of UDP/TCP syslog on Ubuntu 24.04 |
| HEC Incorrect Index error | Remove index from JSON body, let token handle it |
| SplunkForwarder stops after install | Set-Service -StartupType Automatic |
| Lab machine lagging | Reduce Linux-Endpoint RAM to 512MB |

---

## Skills Demonstrated

- **SIEM deployment and configuration** (Splunk Enterprise)
- **Endpoint telemetry** (Sysmon with MITRE ATT&CK-aligned rules)
- **Log pipeline engineering** (Forwarder → Receiver → Index)
- **Detection engineering** (SPL correlation rules)
- **Alert configuration** (scheduled searches, severity levels)
- **Dashboard development** (multi-panel SOC view)
- **Attack simulation** (brute force, PowerShell, privilege escalation)
- **Linux log forwarding** (HEC via curl and systemd service)
- **Network configuration** (VirtualBox host-only, static IPs, UFW)

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Detection |
|-------------|------|-----------|
| T1110 | Brute Force | Windows + Linux |
| T1059.001 | PowerShell | Sysmon Event ID 1 |
| T1136.001 | Create Local Account | Event ID 4720 |
| T1078.003 | Valid Accounts: Local | Event ID 4732 |
| T1021.004 | SSH | Linux auth.log |

---

## References

- [Splunk Documentation](https://docs.splunk.com)
- [Sysmon - Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)

---

*Built from scratch — April 2026*
