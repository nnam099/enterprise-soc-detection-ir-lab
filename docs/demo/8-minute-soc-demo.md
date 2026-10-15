# Enterprise SOC Lab — 8-Minute Demo Runbook

- **Purpose:** SOC Intern Portfolio and Network Security Project
- **Mode:** Evidence-first demonstration
- **Host:** Parrot OS, 8 GB RAM
- **VM Policy:** Maximum two concurrent VMs

## 00:00–00:45 — SOC Architecture

Evidence:
[Architecture Diagram](../../architecture/soc-architecture.svg)

Explain:
- Parrot OS QEMU/KVM Host
- SOC-DC01: Active Directory / DNS
- SOC-WIN10: Windows endpoint, Sysmon, Wazuh Agent
- SOC-WAZUH: SIEM Manager, Indexer and Dashboard
- Isolated 192.168.50.0/24 lab network
- Resource-aware VM rotation

## 00:45–01:40 — Telemetry Collection

Evidence:
[Windows Events in Wazuh](../../screenshots/phase2-wazuh/phase2-wazuh-win10-events.png)

Explain:
- Windows Security EventChannel and Sysmon logs
- Wazuh Agent sends telemetry to the Manager
- Event IDs and process metadata support investigation
- Detection depends on reliable log collection

## 01:40–02:40 — Detection Engineering

Evidence:
[PowerShell Detection Screenshot](../../screenshots/phase3-detection/phase3-wazuh-powershell-event-detail.png)

Explain:
- Custom Rule 100504 detects encoded PowerShell
- Built-in Rule 92057 also detected a scoped test
- MITRE ATT&CK T1059.001
- Detection must be validated, not merely configured

## 02:40–04:20 — INC-003 Triage

Evidence:
[INC-003 Incident Report](../../incidents/INC-003/incident-report.md)

Key observations:
- Authorized simulation: 2026-10-11
- Sysmon Event ID 1, Record ID 20779
- Wazuh Rule 92057, Level 12
- Process ID 4512
- PowerShell parent and child process
- ProcessGuid and command line correlated

Explain:
Alert severity does not establish actual compromise.
This was a controlled benign simulation.

## 04:20–05:20 — Containment and Verification

Evidence:
[INC-003 Timeline](../../incidents/INC-003/timeline.md)

Explain:
- Process identity checked before termination
- Targeted Stop-Process at 07:26:55 UTC+07
- Process absent in subsequent verification
- Sysmon64 and WazuhSvc still running
- No Sysmon Event ID 5 confirmed
- No claim of enterprise-wide recovery

## 05:20–06:20 — Detection Regression

Evidence:
[Regression Report](../../detections/regression-tests/INC-003-regression.md)

[Evidence Manifest](../../incidents/INC-003/evidence-manifest.md)

Results:
- POS-01: Rule 92057 observed — PASS
- POS-02: Rule 100504 observed — PASS
- NEG-01: No encoded-rule alerts observed — PASS
- Rule 92032 was still observed for NEG-01
- 7/7 SHA-256 checks documented

Explain:
Regression results apply only to these scoped test cases.
Original evidence is retained privately.

## 06:20–07:15 — Additional Response Case

Evidence:
[SOC-INC-001 Timeline Screenshot](../../screenshots/phase4-incident/60-soc-inc-001-alert-timeline.png)

[Recovery Monitoring Screenshot](../../screenshots/phase4-incident/63-soc-inc-001-recovery-monitoring.png)

Explain:
- Separate original simulation: 2026-09-29
- Correlated WinRM, encoded PowerShell and Run Key
- Independent response drills on 2026-10-07
- AD account disable and restore verified
- Run Key absence checked in sampled monitoring
- No claim that all actions occurred in one incident

## 07:15–08:00 — Performance Engineering

Evidence:
[Wazuh I/O Investigation](../performance/wazuh-io-optimization-2026-10-14.md)

Explain:
- Investigated excessive wazuh-modulesd Disk I/O
- Observed vulnerability feed update errors
- Backed up and validated the configuration
- Temporarily disabled Vulnerability Detection
- Guest I/O full PSI avg10: 60.13% to 0.00%
- This is an observed improvement, not a permanent fix
- Security trade-off is documented

## Demo Safety and Fallback

- Prefer screenshots and verified reports over live boot.
- Do not start a third VM.
- Avoid replaying attacks during the presentation.
- Do not publish private Windows transcripts or secrets.
- Explain observed evidence separately from conclusions.
- If Wazuh Dashboard is slow, continue with static evidence.

## Closing Statement

This project demonstrates an evidence-driven SOC workflow:
Telemetry, Detection, Triage, Investigation, Containment,
Verification, Regression Testing and Documentation.

The exercises were authorized and isolated.
No real enterprise compromise is claimed.
