# INC-003 — Verified Incident Timeline

## Case Information

- **Case ID:** INC-003
- **Type:** Authorized benign PowerShell simulation
- **Endpoint:** SOC-WIN10
- **SIEM:** SOC-WAZUH (Wazuh 4.14.8)
- **Date:** 2026-10-11
- **Timezone:** UTC+07:00 (Vietnam)
- **Disposition:** Successful controlled containment

## Chronological Timeline

| Time (UTC+07) | Phase | Verified Event | Evidence |
|---|---|---|---|
| 07:14:09 | Baseline | Encoded PowerShell test executed | Marker INC003-TLM-20261011071409 |
| 07:14:10 | Telemetry | Sysmon Event ID 1 recorded | Record 20704 |
| 07:14:11 | Detection | Wazuh generated Rule 92057, Level 12 | Wazuh alert 20704 |
| 07:24:37 | Simulation | Controlled encoded PowerShell process created | Record 20779 |
| 07:24:39 | Detection | Wazuh Rule 92057 triggered | Wazuh alert 20779 |
| 07:26:55 | Containment | Process identity verified and PID 4512 terminated | Containment transcript |
| 07:28:01 | Evidence | Containment transcript finalized | SHA-256 verified |
| 07:29:38 | Verification | PID absent; Sysmon64 and WazuhSvc running | Recovery transcript |
| 07:32:28 | Regression | POS-02: CMD launched encoded PowerShell | Record 20782 |
| 07:32:29 | Detection | Custom Rule 100504, Level 8 triggered | Wazuh alert 20782 |
| 07:34:08 | Regression | NEG-01: CMD launched normal PowerShell | Record 20785 |
| 07:34:10 | Detection review | Rule 92032 triggered; encoded-command rules did not | Alert and archive 20785 |

Timestamps are derived from endpoint event records,
Wazuh alerts, and analyst transcripts. Second-level
timestamps are rounded for readability.

## Primary Incident Correlation

**Simulation marker:**
`INC003-IR-20261011072437`

| Attribute | Value |
|---|---|
| Sysmon Event ID | 1 |
| Event Record ID | 20779 |
| Process ID | 4512 |
| Parent Process ID | 7180 |
| ProcessGuid | `{e12a69d9-d745-6aca-e801-000000002300}` |
| Image | powershell.exe |
| Parent Image | powershell.exe |
| Wazuh Rule | 92057 |
| Rule Level | 12 |
| MITRE ATT&CK | T1059.001 |

## Containment Verification

The analyst verified the target process name,
command line, and creation timestamp before
executing a targeted `Stop-Process`.

Verified results:

- `IDENTITY_VERIFIED: YES`
- `RESULT: CONTAINMENT_VERIFIED`
- `TARGET_PID_ABSENT`
- `Sysmon64: Running`
- `WazuhSvc: Running`

Elapsed time from process creation to containment:
approximately **2 minutes 18 seconds**.

This is an observed interval in a controlled lab
simulation, not a production SOC response metric.

## Detection Regression

| Test | Expected | Actual | Result |
|---|---|---|---|
| POS-01 | Encoded PowerShell detection | Rule 92057 | PASS |
| POS-02 | Encoded PowerShell detection | Rule 100504 | PASS |
| NEG-01 | No encoded PowerShell rule | Rule 92032 only | PASS |

## Evidence and Limitations

The associated evidence inventory and SHA-256
hashes are documented in [Evidence Manifest](evidence-manifest.md).

The full investigation is documented in
[Incident Report](incident-report.md).

Important limitations:

- No actual compromise occurred.
- Sysmon Event ID 5 was not found in the scoped search.
- The exercise did not involve network isolation.
- No detection rule was modified during this case.
- Original forensic evidence is retained privately.
