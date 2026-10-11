# AD-003 — Offline Authentication Detection Validation

## Scope

- Lab: Enterprise SOC Detection & Incident Response Lab
- Test date: 2026-10-11
- SIEM: Wazuh 4.14.8
- Relevant custom rules: 100507, 100503
- Test engine: Python Reference Model
- Wazuh runtime regression: NOT VERIFIED

## Detection configuration

| Rule | Purpose |
|---|---|
| 100507 | Match Event 4625 with SubStatus 0xC000006A |
| 100503 | Correlate 5 matching failures in 60 seconds by targetUserName |

Configuration validation: 9/9 PASS.

## Behavioral validation

| Test | Expected behavior | Result |
|---|---|---|
| TC-01 | Single failure, no correlation | PASS |
| TC-02 | Five failures for same account within 60 seconds | PASS |
| TC-03 | Different accounts must not be grouped | PASS |
| TC-04 | Different SubStatus must not match | PASS |
| TC-05 | Different Event ID must not match | PASS |
| TC-06 | Failures outside 60-second window must not correlate | PASS |

Reported output:

- BEHAVIORAL_TESTS: 6/6
- AD003_OFFLINE_LOGIC_VALIDATION_PASS

## Evidence provenance

Windows Security events collected on SOC-DC01:

- Record 23791 — Event 4776 — NTLM failure
- Record 23792 — Event 4625 — failed network logon
- Record 23840 — Event 4776 — NTLM success
- Record 23841 — Event 4624 — successful network logon

Evidence was transferred from DC01 to Parrot using SCP.
Five evidence files passed destination SHA-256 verification.

Raw evidence storage:
`~/soc-evidence/AD-003/windows/`

Raw authentication evidence is not committed to this repository.

## SIEM validation limitations

- Historical Wazuh ingestion from Agent 002 was verified on 2026-10-09.
- AD-003 events from 2026-10-11 were not found in the examined Wazuh archives.
- Historical JSON replay through wazuh-logtest used decoder `json`, whereas the Windows base rules require `windows_eventchannel`.
- Python validation is a reference-model test, not Wazuh runtime rule validation.
- No brute-force attack or account compromise was established by the AD-003 simulation.

## Status

- Windows telemetry: VERIFIED
- Evidence integrity: VERIFIED
- Rule configuration: VERIFIED
- Python behavioral logic: PASS
- AD-003 Wazuh live ingestion: NOT VERIFIED
- Wazuh runtime correlation: NOT VERIFIED
