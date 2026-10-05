# Phantom Privilege Escalation Lab Report

## Overview

This document details the execution and detection of a phantom privilege escalation attack in the Splunk lab environment. The attack demonstrates how temporary admin account creation, elevation, and rapid deletion appears invisible on the Windows endpoint but is fully captured by Splunk event correlation.

## Attack Execution

### Phase 1: Account Creation

**Command:**
```powershell
net user Service_Backup P@ssw0rd123! /add
```

**Result:** Service_Backup account created successfully
- **Windows Perception:** Account visible in `net user` listing
- **Splunk Event:** Event ID 4720 (User Account Created)
- **Timestamp:** Captured in WinEventLog:Security

### Phase 2: Privilege Escalation

**Command:**
```powershell
net localgroup administrators Service_Backup /add
```

**Result:** Service_Backup added to Administrators group
- **Windows Perception:** Account now has full administrative privileges
- **Splunk Event:** Event ID 4732 (Member Added to Security-Enabled Local Group)
- **Group:** Administrators
- **Timestamp:** Captured immediately after account creation

### Phase 3: Cleanup/Deletion

**Command:**
```powershell
net user Service_Backup /delete
```

**Result:** Service_Backup account deleted
- **Windows Perception:** Account completely removed and invisible in `net user` listing
- **Splunk Event:** Event ID 4726 (User Account Deleted)
- **Total Execution Time:** ~5 seconds from creation to deletion
- **Timestamp:** Captured in event log before cleanup completes

## Windows Endpoint Perception

### Before Attack

```
User accounts for \\DESKTOP-QFL11DI

Administrator          dalonybell            DefaultAccount
Guest                  WDAGUtilityAccount
The command completed successfully.
```

### During Attack (Invisible)

The Service_Backup account exists for approximately 5 seconds. During this time, an attacker could:
- Extract sensitive data
- Install persistence mechanisms
- Modify system configurations
- Deploy additional tools

### After Attack

```
User accounts for \\DESKTOP-QFL11DI

Administrator          dalonybell            DefaultAccount
Guest                  WDAGUtilityAccount
The command completed successfully.
```

**No trace of Service_Backup remains on the endpoint.**

## Splunk Detection & Correlation

### Raw Event Evidence

The Splunk search query captures all three events:

```spl
index="main" sourcetype="WinEventLog:Security" EventCode IN (4720, 4732, 4726)
```

**Results:**

| Timestamp | Event Code | Event Type | Details |
|-----------|-----------|------------|----------|
| 10/04/2026 2:09:44 PM | 4720 | User Account Created | LogName=Security, EventCode=4720, Computer=DESKTOP-QFL11DI |
| 10/04/2026 2:09:45 PM | 4732 | Member Added to Group | LogName=Security, EventCode=4732, Computer=DESKTOP-QFL11DI |
| 10/04/2026 2:09:46 PM | 4726 | User Account Deleted | LogName=Security, EventCode=4726, Computer=DESKTOP-QFL11DI |

### Splunk Correlation Query

```spl
sourcetype=WinEventLog:Security (EventID=4720 OR EventID=4732 OR EventID=4726)
| transaction user_account startswith=(EventID=4720) endswith=(EventID=4726) maxspan=10m
| search EventID=4732
| table user_account, EventID, timestamp, ComputerName
| stats count by user_account
| where count >= 3
```

**Detection Logic:**
1. Identify EventID 4720 (user account created)
2. Correlate with EventID 4732 (member added to admin group)
3. Confirm with EventID 4726 (user account deleted)
4. All events occur within 10 minutes
5. Alert on patterns with 3+ correlated events

### Why Traditional Tools Miss This

- **`net user` command:** Returns static snapshot; account is already deleted
- **Event Viewer (GUI):** Requires manual filtering and review of hundreds of events
- **Standard AV/EDR:** Often ignores rapid account lifecycle events as false positives

**Splunk's Advantage:**
- Persistent storage of all events
- Automatic correlation of related events
- Time-series analysis of suspicious patterns
- Alerting on multi-stage attack sequences

## Attack Timeline

```
[T+0 sec]  Account creation initiated
           → Event ID 4720 logged
           → Service_Backup visible in `net user`

[T+1 sec]  Admin group membership added
           → Event ID 4732 logged
           → Service_Backup now has admin rights
           → Attacker window for malicious actions

[T+5 sec]  Account deletion initiated
           → Event ID 4726 logged
           → Service_Backup removed from endpoint
           → `net user` shows no trace

[+Infinity] Splunk retains all events
            → Correlation search identifies pattern
            → SOC alerts on phantom admin account
```

## Key Takeaways

1. **Invisible ≠ Undetectable:** Endpoint tools see only the final state (deleted account). Splunk sees the entire sequence.

2. **Timing Matters:** The 5-second window between creation and deletion makes this a high-confidence indicator of automated attack tooling, not manual administration.

3. **Event Correlation is Key:** No single event is suspicious; all three together reveal the attack pattern.

4. **Forensics Advantage:** Even if the attacker had deleted the Windows Security Event Log, a properly configured Splunk forwarder would have already transmitted the events off-system.

## Defensive Recommendations

1. **Alert on Rapid Account Lifecycle:** Create alerts for 3+ events (4720, 4732, 4726) within 5 minutes
2. **Monitor Admin Group Changes:** Event ID 4732 should trigger immediate investigation
3. **Off-System Logging:** Forward all security events to Splunk (or similar) immediately
4. **Timeline Alerts:** Set very narrow correlation windows (5-10 minutes) for privilege escalation patterns

## Lab Conclusion

This lab successfully demonstrates how Splunk's event correlation capabilities reveal attack patterns that are invisible to traditional Windows tools and endpoint-based detection mechanisms.
