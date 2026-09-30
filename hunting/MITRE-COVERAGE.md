# SOC-LAB Threat Hunting — MITRE ATT&CK Coverage

## Coverage Matrix

| Hunt | Behavior | Telemetry | Detection | MITRE ATT&CK | Status |
|---|---|---|---|---|---|
| HUNT-001 | Encoded PowerShell | Sysmon EID 1 | 100504 | T1059.001 | Validated |
| HUNT-002 | Repeated failed logons | Security EID 4625 | 100503 | T1110 | Validated |
| HUNT-003 | WinRM process execution | Sysmon EID 1 | 100502 | T1021.006 | Validated |
| HUNT-004 | Registry modification | Sysmon EID 13 | 100501 | T1112 | Validated |
| HUNT-004 | Registry Run Key persistence | Sysmon EID 13 | 100501 | T1547.001 | Validated |

## Technique Summary

### T1059.001 — PowerShell
Validated in HUNT-001 using Sysmon Event ID 1 and custom rule 100504.

### T1110 — Brute Force
Validated in HUNT-002 using repeated Windows Event ID 4625 failures and rule 100503.

### T1021.006 — Windows Remote Management
Validated in HUNT-003 using Sysmon Event ID 1 and ParentImage=wsmprovhost.exe.

### T1112 — Modify Registry
Validated in HUNT-004 using Sysmon Event ID 13.

### T1547.001 — Registry Run Keys / Startup Folder
Validated in HUNT-004 using HKCU\Software\Microsoft\Windows\CurrentVersion\Run.

## Evidence Mapping

- HUNT-001: hunting/evidence/HUNT-001/
- HUNT-002: hunting/evidence/HUNT-002/
- HUNT-003: hunting/evidence/HUNT-003/
- HUNT-004: hunting/evidence/HUNT-004/

## Current Gaps

- Scheduled Tasks
- Windows Services
- SMB lateral movement
- RDP activity
- Credential dumping / LSASS access
- Process injection
- DNS anomalies
- Malware execution

## Status

Phase 5 Threat Hunting: COMPLETED
