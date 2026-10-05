```markdown
# Windows Endpoint Telemetry & Threat Detection Lab (Splunk Enterprise)

An end-to-end security engineering and threat-hunting laboratory demonstrating the deployment of a custom SIEM pipeline, Windows audit policy engineering, and behavioral adversary detection on an isolated virtual network.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────┐
│                    Isolated Lab Subnet                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────┐          ┌────────────────────┐   │
│  │   Windows 11 VM      │          │  Nobara Linux Host │   │
│  │ ──────────────────── │          │ ────────────────── │   │
│  │ • Universal          │          │ • Splunk Enterprise│   │
│  │   Forwarder (UF)     │          │   (Indexer / SH)   │   │
│  │ • Audit Policies:    │ TCP/9997 │ • Web Port: 8000   │   │
│  │   Process & Command  │ (libvirt)│ • Python C2 Drop:  │   │
│  │   Line Logging (4688)├──────────┤   Port 8080        │   │
│  │ • Target Endpoint    │          │ • Forwarder Listen:│   │
│  │   (192.168.122.x)    │          │   Port 9997        │   │
│  └──────────────────────┘          └────────────────────┘   │
│             │                                 ▲             │
│             └─────── WinEventLog Pipeline ────┘             │
│                                                             │
└─────────────────────────────────────────────────────────────┘

```

The data pipeline collects Security, System, and Application logs from a Windows 11 virtual machine and ships them across an isolated `libvirt` virtual bridge (`virbr0`) to Splunk Enterprise hosted on Nobara Linux.

---

## Verification & Pipeline Health

Before staging adversary simulations, network socket availability and ingest paths were validated from the endpoint across the hypervisor bridge.

```powershell
# Validate connectivity to the Splunk Indexing Port
Test-NetConnection -ComputerName 192.168.122.1 -Port 9997

```

---

## Adversary Emulation & Hunting

### Simulation 1: Ingress Tool Transfer (T1105) & Encoded Execution (T1059.001)

#### 1. Payload Staging

To simulate adversary staging without host clipboard dependencies, a localized HTTP transfer station was established on the Linux host using an isolated staging folder to prevent directory traversal exposures:

```bash
mkdir ~/payload_drop && cd ~/payload_drop
echo "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAUwBwAGwAdQBuAGsAIQAiAA==" > command-payload.txt
python3 -m http.server 8080

```

#### 2. Execution & Defense Evasion

The payload was retrieved and executed via Windows Command Prompt. It utilizes `-ExecutionPolicy Bypass` and a Base64-encoded string to evade signature-based command scanning.

#### 3. SIEM Detection (Splunk SPL)

Detecting this requires Windows Group Policy tracking for Process Creation (Event Code 4688) and command-line auditing.

```spl
index="main" sourcetype="WinEventLog:Security" EventCode=4688 "powershell.exe" "*EncodedCommand*"
| table _time, host, New_Process_Name, Process_Command_Line, Creator_Process_Name

```

---

### Simulation 2: Phantom Privilege Escalation & Defense Evasion (T1078, T1098, T1070)

#### 1. Adversary Action

Simulating living-off-the-land techniques, an attacker creates an ephemeral administrative account to stage malicious persistence, executes tasks, and deletes the account rapidly to erase evidence.

```powershell
net user Service_Backup P@ssw0rd123! /add
net localgroup administrators Service_Backup /add
net user Service_Backup /delete

```

#### 2. The Visibility Gap (Endpoint vs. SIEM)

Standard live endpoint triage yields no trace of the account:

```cmd
net user

```

#### 3. SIEM Behavioral Correlation

While the endpoint file system and SAM database retain no active state, the centralized audit trail records the creation, elevation, and deletion sequence within milliseconds:

```spl
index="main" sourcetype="WinEventLog:Security" EventCode IN (4720, 4732, 4726)
| table _time, EventCode, TargetUserName, Account_Name, Message

```

* **EventCode 4720**: User Account Created (`Service_Backup`)
* **EventCode 4732**: Member Added to Local Administrator Group
* **EventCode 4726**: User Account Deleted

---

## Engineering Challenges & Troubleshooting

### 1. Libvirt Virtual Bridge Zone Firewall Drop

* **Symptom**: `Test-NetConnection` from Windows 11 to Linux on port `9997` and HTTP port `8080` timed out.
* **Root Cause**: Nobara Linux utilizes `firewalld`. Traffic originating from the virtual bridge (`virbr0`) belongs to the `libvirt` zone, not the default `FedoraWorkstation` zone. Adding ports globally did not expose them to guest VMs.
* **Resolution**: Explicitly bound the listening ports to the virtualization zone:
```bash
sudo firewall-cmd --zone=libvirt --add-port=9997/tcp --permanent
sudo firewall-cmd --zone=libvirt --add-port=8080/tcp
sudo firewall-cmd --reload

```



### 2. Silent UTF-8 BOM Corruption in `inputs.conf`

* **Symptom**: The Splunk Universal Forwarder service ran without throwing error prompts, but index searches returned `0 events`.
* **Root Cause**: Editing configuration files with standard Windows Notepad injected a hidden Byte Order Mark (UTF-8 BOM). Splunk's configuration parser failed to interpret the section headers `[WinEventLog://Security]`.
* **Diagnosis & Resolution**:
Executed `splunk btool` to inspect parsed stanzas:
```cmd
.\splunk.exe btool inputs list --debug

```


The stanza appeared mangled with leading control characters. The file was re-encoded to strict **UTF-8 (without BOM)** and the forwarder service restarted:
```powershell
Restart-Service SplunkForwarder

```



### 3. Missing Telemetry via Local Audit Policies

* **Symptom**: Base64 PowerShell execution failed to populate Event ID 4688 logs in Splunk.
* **Root Cause**: Modern Windows client editions do not audit detailed process creation or command-line parameters by default to conserve disk I/O.
* **Resolution**: Enabled local policies via `gpedit.msc`:
* `Computer Configuration > Windows Settings > Security Settings > Local Policies > Audit Policy > Audit process tracking` -> **Success**
* `Administrative Templates > System > Audit Process Creation > Include command line in process creation events` -> **Enabled**
* Enforced using `gpupdate /force`.



```

```
