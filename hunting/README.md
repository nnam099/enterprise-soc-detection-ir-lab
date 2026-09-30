# Phase 5 — Threat Hunting

## Overview

Phase 5 extends SOC-LAB from rule-based detection into structured threat hunting.

Workflow: Hypothesis → Telemetry Search → Evidence → Finding → Detection Validation → Recommendation.

All suspicious activity in this phase was intentionally generated inside the controlled SOC-LAB environment.

## Completed Hunts

### HUNT-001 — PowerShell Detection
- Telemetry: Sysmon Event ID 1
- Detection: 92027, 92057, 100504
- MITRE: T1059.001 — PowerShell
- Report: hunting/HUNT-001-powershell.md
- Evidence: hunting/evidence/HUNT-001/

### HUNT-002 — Authentication Anomalies
- Telemetry: Windows Security Event ID 4625 / 4624
- Detection: 60122, 100503
- MITRE: T1110 — Brute Force
- Report: hunting/HUNT-002-authentication.md
- Evidence: hunting/evidence/HUNT-002/

### HUNT-003 — WinRM Remote Execution
- Telemetry: Sysmon Event ID 1
- Detection: 100502
- MITRE: T1021.006 — Windows Remote Management
- Key finding: rule 100502 originally depended on cmd.exe-specific rule 92052.
- Improvement: detect sysmon_event1 directly when ParentImage ends with wsmprovhost.exe.
- Report: hunting/HUNT-003-winrm.md
- Evidence: hunting/evidence/HUNT-003/

### HUNT-004 — Registry Run Key Persistence
- Telemetry: Sysmon Event ID 13
- Detection: 100501
- MITRE: T1112 / T1547.001
- Key finding: both legitimate Edge autostart and controlled persistence can trigger the detection.
- SOC lesson: Alert != Incident.
- Report: hunting/HUNT-004-persistence.md
- Evidence: hunting/evidence/HUNT-004/

## Detection Engineering Lessons

1. Detection logic should model the behavior being investigated.
2. Raw telemetry should be preserved alongside SIEM alerts.
3. Alerts require analyst context before escalation.
4. Independent lab validation events must not be combined into one attack chain without evidence.

## Phase Status

Phase 5 Threat Hunting: COMPLETED

Next: Phase 6 — DFIR Evidence Pipeline and AI-Assisted Detection.
