# DFIR-002 — Native Sysmon Correlation Report

## 1. Objective

Corroborate selected DFIR-001 historical hunting evidence using
Sysmon Operational.evtx exported directly from WIN10-01.

The two hunting exercises are independent. Their temporal proximity
does not demonstrate causation or one continuous attack chain.

## 2. HUNT-003 — WinRM-Related Process Creation

| Field | Native Sysmon evidence |
|---|---|
| Event ID | 1 |
| Event Record ID | 7366 |
| UTC | 2026-09-30T04:26:58.6941792Z |
| Image | `C:\Windows\System32\cmd.exe` |
| Parent image | `C:\Windows\System32\wsmprovhost.exe` |
| ProcessGuid | `{e12a69d9-8f92-6abc-6001-000000001500}` |
| Event ID match | PASS |
| ProcessGuid match | PASS |

**Finding:** A `cmd.exe` process was created with `wsmprovhost.exe`
as its parent. This supports the historical WinRM-related process
observation, without establishing malicious intent.

## 3. HUNT-004 — Registry Run Key Value Set

| Field | Native Sysmon evidence |
|---|---|
| Event ID | 13 |
| Event Record ID | 7380 |
| UTC | 2026-09-30T04:53:23.4169804Z |
| Image | `powershell.exe` |
| Registry location | User hive, `...\CurrentVersion\Run` |
| Validation value | `HUNT004-RUNKEY-VALIDATION` |
| ProcessGuid | `{e12a69d9-95ba-6abc-7101-000000001500}` |
| Event ID match | PASS |
| ProcessGuid match | PASS |

**Finding:** PowerShell set a controlled Run Key value containing
a lab validation command. This does not establish that the configured
command later executed.

## 4. Correlation Result

- Native events found: 2/2
- Expected Event IDs matched: 2/2
- Expected ProcessGuids matched: 2/2
- Historical UTC timestamps consistent with DFIR-001: YES

This demonstrates corroboration between preserved Wazuh evidence
and native endpoint event records.

## 5. Derived Analysis Artifact

Filename: `native-correlation.json`

SHA-256:
`A9C52CF34F81A5E6C6C784989578D987C1871ED907FB46ED0E1B3D97776C508B`

The analysis file is stored separately from the original acquisition
package. Its hash is not the raw EVTX hash.

## 6. Limitations

Only two selected events were corroborated.
No complete cross-source event-by-event reconciliation was performed.
No evidence establishes a real compromise, persistence execution,
or causal linkage between HUNT-003 and HUNT-004.
