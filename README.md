```markdown
# Windows Endpoint Telemetry & Threat Detection Lab (Splunk Enterprise)

![Splunk](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-black?style=for-the-badge&logo=splunk)
![Linux](https://img.shields.io/badge/Platform-Nobara%20Linux-blue?style=for-the-badge&logo=linux)
![Windows](https://img.shields.io/badge/Target-Windows%2011-0078D6?style=for-the-badge&logo=windows)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=for-the-badge)

An end-to-end security engineering and threat detection laboratory demonstrating the deployment of a custom SIEM pipeline, endpoint audit policy tuning, and behavioral adversary emulation over an isolated virtual network bridge.

---

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Pipeline Configuration & Validation](#pipeline-configuration--validation)
- [Adversary Emulation & Detection Engineering](#adversary-emulation--detection-engineering)
  - [Scenario 1: Ingress Tool Transfer & Encoded Execution](#scenario-1-ingress-tool-transfer--encoded-execution)
  - [Scenario 2: Phantom Privilege Escalation & Defense Evasion](#scenario-2-phantom-privilege-escalation--defense-evasion)
- [Engineering Challenges & Root-Cause Analysis](#engineering-challenges--root-cause-analysis)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Architecture Overview

The detection environment isolates the Windows 11 guest from the corporate network while routing endpoint telemetry across a dedicated `libvirt` virtual bridge (`virbr0`) to Splunk Enterprise running natively on Nobara Linux.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                     Isolated Lab Subnet (virbr0)                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────┐             ┌───────────────────────────┐  │
│  │    Windows 11 Target    │             │     Nobara Linux Host     │  │
│  │ ─────────────────────── │             │ ───────────────────────── │  │
│  │ • Universal Forwarder   │             │ • Splunk Enterprise       │  │
│  │ • Process Tracking 4688 │  TCP/9997   │   (Indexer + Search Head) │  │
│  │ • Command-Line Auditing ├────────────►│ • Forwarding Port: 9997   │  │
│  │ • Static IP:            │  (libvirt)  │ • Splunk Web: 8000        │  │
│  │   192.168.122.x         │             │ • Python Drop: Port 8080  │  │
│  └─────────────────────────┘             └───────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

```

---

## Pipeline Configuration & Validation

### 1. Ingestion Definitions (`inputs.conf`)

Located on the Windows endpoint at `%SPLUNK_HOME%\etc\system\local\inputs.conf`:

```ini
[WinEventLog://Security]
index = main
sourcetype = WinEventLog:Security
disabled = false

[WinEventLog://System]
index = main
sourcetype = WinEventLog:System
disabled = false

[WinEventLog://Application]
index = main
sourcetype = WinEventLog:Application
disabled = false

```

### 2. Forwarding Routing (`outputs.conf`)

Located at `%SPLUNK_HOME%\etc\system\local\outputs.conf`:

```ini
[tcpout]
defaultGroup = splunk_indexer

[tcpout:splunk_indexer]
server = 192.168.122.1:9997

```

### 3. Pipeline Connectivity Validation

Prior to threat emulation, layer-4 reachability was validated from the target across the hypervisor bridge using PowerShell:

```powershell
Test-NetConnection -ComputerName 192.168.122.1 -Port 9997

```

---

## Adversary Emulation & Detection Engineering

### Scenario 1: Ingress Tool Transfer & Encoded Execution

Adversaries routinely stage external payloads on temporary staging servers and pull them into the environment using living-off-the-land techniques (LotL) and Base64 encoding to bypass static perimeter checks.

#### 1. Payload Staging (Linux Host)

To simulate an ingress transfer without host-clipboard dependencies, an isolated directory was allocated to serve payload strings:

```bash
mkdir ~/payload_drop && cd ~/payload_drop
echo "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAUwBwAGwAdQBuAGsAIQAiAA==" > command-payload.txt
python3 -m http.server 8080

```

#### 2. Execution (Windows Target)

The payload was retrieved and executed via Windows Command Prompt. It leveraged execution policy bypass flags and obfuscated script blocks:

```cmd
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAUwBwAGwAdQBuAGsAIQAiAA==

```

#### 3. SIEM Detection & Telemetry Analysis

Process Creation logging (Event ID 4688) with command-line extraction captured the parent-child relationship and the raw encoded string:

```spl
index="main" sourcetype="WinEventLog:Security" EventCode=4688 "powershell.exe" "*EncodedCommand*"
| table _time, host, Creator_Process_Name, New_Process_Name, Process_Command_Line

```

---

### Scenario 2: Phantom Privilege Escalation & Defense Evasion

Attackers frequently create temporary local administrative accounts to perform privileged operations, followed immediately by deletion to evade standard endpoint triage checks.

#### 1. Adversary Simulation Script

Executed in an elevated terminal session on the Windows target:

```powershell
net user Service_Backup P@ssw0rd123! /add
net localgroup administrators Service_Backup /add
net user Service_Backup /delete

```

#### 2. The Visibility Gap: Endpoint Triage vs. SIEM

A live incident responder executing standard endpoint queries discovers no active administrative anomaly:

```cmd
net user

```

#### 3. Behavioral Log Correlation (Splunk)

While the local Security Accounts Manager (SAM) database retains no post-incident state, centralized log forwarding preserved the sub-second event cluster:

```spl
index="main" sourcetype="WinEventLog:Security" EventCode IN (4720, 4732, 4726)
| table _time, host, EventCode, TargetUserName, TargetDomainName, Message

```

| Event Code | Category | Operational Impact |
| --- | --- | --- |
| **4720** | User Management | Account `Service_Backup` provisioned |
| **4732** | Group Management | Member injected into privileged `Administrators` group |
| **4726** | User Management | Account `Service_Backup` decommissioned to erase forensic artifacts |

---

## Engineering Challenges & Root-Cause Analysis

### Challenge 1: Virtual Bridge Boundary Filtering (`firewalld`)

* **Problem**: The Windows 11 target failed to establish layer-4 handshakes over ports `9997` and `8080` despite standard local firewall exceptions on Linux.
* **Root Cause**: Nobara Linux assigns hypervisor bridge interfaces (`virbr0`) to the `libvirt` zone rather than `FedoraWorkstation`. Standard host rules do not apply to virtual guest networks.
* **Resolution**: Bound the ingest and staging ports directly to the `libvirt` operational zone:
```bash
sudo firewall-cmd --zone=libvirt --add-port=9997/tcp --permanent
sudo firewall-cmd --zone=libvirt --add-port=8080/tcp
sudo firewall-cmd --reload

```



### Challenge 2: Silent UTF-8 Byte Order Mark (BOM) Corruption

* **Problem**: The Splunk Universal Forwarder service ran without throwing exceptions, but zero events were indexed in Splunk Enterprise.
* **Root Cause**: Modifying `inputs.conf` with Windows Notepad introduced an invisible UTF-8 Byte Order Mark (`0xEF, 0xBB, 0xBF`), corrupting the stanza headers for the parser.
* **Diagnosis & Fix**: Used the Splunk command-line tool `btool` to identify configuration syntax failures:
```cmd
.\splunk.exe btool inputs list --debug

```


The stanzas failed to register. The file was reconstructed under strict UTF-8 (no BOM) encoding, resolving the indexing bottleneck immediately after restarting `SplunkForwarder`.

### Challenge 3: Inactive Sub-Category Process Tracking

* **Problem**: Encoded PowerShell executions were generating zero Event ID 4688 logs.
* **Root Cause**: Default Windows installations suppress detailed command-line arguments to conserve local disk space.
* **Resolution**: Configured Local Group Policy (`gpedit.msc`):
* Enabled: `Security Settings > Local Policies > Audit Policy > Audit process tracking` (Success)
* Enabled: `Administrative Templates > System > Audit Process Creation > Include command line in process creation events`
* Applied changes instantly with `gpupdate /force`.



---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Artifact |
| --- | --- | --- | --- |
| **Command and Control** | Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Python HTTP transfer over TCP/8080 |
| **Execution** | PowerShell / Command-Line Interface | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Event ID 4688 (`-EncodedCommand`) |
| **Privilege Escalation** | Domain/Local Account Manipulation | [T1098](https://attack.mitre.org/techniques/T1098/) | Event ID 4732 (Local Administrators membership) |
| **Persistence** | Create Account: Local Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Event ID 4720 (`Service_Backup`) |
| **Defense Evasion** | Indicator Removal on Host | [T1070](https://attack.mitre.org/techniques/T1070/) | Event ID 4726 (Account deletion) |

```

```
