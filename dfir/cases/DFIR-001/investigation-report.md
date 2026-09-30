# DFIR-001 — Suspicious Remote Execution and Persistence Investigation

## Case Information

- Case ID: DFIR-001
- Environment: SOC-LAB
- Target: WIN10-01 / SOC-WIN10
- Domain: SOC-LAB.LOCAL
- Investigation Type: Controlled DFIR Validation
- Status: Open
- Evidence Source: Existing SOC-LAB threat hunting telemetry

---

## Objective

Reconstruct a defensible investigation timeline from previously collected endpoint and SIEM evidence.

The investigation focuses on:

- PowerShell execution
- Authentication activity
- WinRM remote execution
- Registry Run Key modification
- Detection-layer correlation
- Evidence preservation

Independent controlled validation events are not assumed to belong to one real attack chain unless telemetry proves a relationship.

---

## Evidence Sources

### HUNT-001

PowerShell execution evidence.

Relevant techniques:

- T1059.001 — PowerShell

Relevant detections:

- 92027
- 92057
- 100504

---

### HUNT-002

Windows authentication telemetry.

Relevant events:

- Event ID 4624
- Event ID 4625

Relevant detections:

- 60122
- 100503

Technique:

- T1110 — Brute Force

---

### HUNT-003

WinRM process execution evidence.

Relevant event:

- Sysmon Event ID 1

Relevant detection:

- 100502

Technique:

- T1021.006 — Windows Remote Management

Observed relationship:

```text
wsmprovhost.exe
        |
        +-- cmd.exe
