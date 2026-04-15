# Splunk SPL Detection Rules

## 1. Brute Force Detection
Detects multiple failed logons from same source IP
index=wineventlog EventCode=4625
| stats count by src_ip Account_Name
| where count > 10
| sort -count
**MITRE ATT&CK:** T1110 — Brute Force
**Event ID:** 4625 (Failed Logon)
**Alert threshold:** 10+ failures from same IP in 5 minutes

## 2. Successful Login After Failures (Brute Force Success)
index=wineventlog EventCode=4625
| stats count as failures by src_ip
| where failures > 5
| join src_ip
[search index=wineventlog EventCode=4624
| stats count as success by src_ip]
| where success > 0
**What this detects:** Attacker who successfully 
brute-forced credentials

## 3. Suspicious PowerShell Execution
index=sysmon EventCode=1
CommandLine="-EncodedCommand"
OR CommandLine="-WindowStyle Hidden"
| table _time, user, CommandLine, ParentCommandLine
**MITRE ATT&CK:** T1059.001 — PowerShell
**Event ID:** Sysmon Event 1 (Process Creation)

## 4. New Service Installation
index=wineventlog EventCode=7045
| table _time, host, ServiceName, ServiceFileName
| sort -_time
**MITRE ATT&CK:** T1543.003 — Windows Service
**Why it matters:** PsExec installs a temp service 
to execute lateral movement

## 5. LSASS Memory Access (Credential Dumping)
index=sysmon EventCode=10
TargetImage="*lsass.exe"
| table _time, SourceImage, TargetImage, GrantedAccess
| sort -_time
**MITRE ATT&CK:** T1003.001 — LSASS Memory
**Why it matters:** Mimikatz accesses lsass.exe 
to dump credentials
