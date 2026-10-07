# Encoded PowerShell Live Detection Validation

## Outcome

Four controlled live tests validated the current manager configuration.
The repository copy of rule 100504 was then synchronized with the tested
manager rule. No manager rule was changed or service restarted during
this validation.

These results are a baseline for future regression testing, not a
before-and-after evaluation of a newly deployed tuning change.

## Environment

- Wazuh: v4.14.8, revision rc2
- Agent: 001 / SOC-WIN10
- Observed Windows hostname: WIN10-01
- Account: WIN10-01\localadmin
- Resource mode: SOC-WAZUH + SOC-WIN10
- Payloads: Write-Output markers and short Start-Sleep operations

## Test Results

Times below are UTC on 2026-10-07.

| Test | Behavior | PID | Actual rule / level | Result |
|---|---|---:|---|---|
| T01 | PowerShell parent, -EncodedCommand | 5968 | 92057 / 12 | PASS |
| T02 | CMD parent, -EncodedCommand | 4568 | 100504 / 8 | PASS |
| T03 | CMD parent, -enc | 5956 | 100504 / 8 | PASS |
| T04 | PowerShell parent, ordinary -Command | 1792 | 92027 / 4 | PASS for encoded negative control |

T04 was present in archives and alerts. Neither 100504 nor 92057 was
observed for its matching process event at collection time
2026-10-07T04:36:43.372094+00:00.

The authorized test payloads are not evidence of malicious compromise.
A rule match validates detection of the tested behavior, not malicious intent.

## Correlation and Evidence

Execution records contain unique markers, timestamps, command lines,
and PIDs. Positive encoded events were matched using agent ID, Sysmon
Event ID 1, PID, and the decoded marker.

ProcessGuid, parent process, and event time support correlation.
Archive and alert IDs are not assumed to be identical.

Each T01 through T04 folder contains exported archive and alert records.
T04 also contains its collection-time result summary.

## Configuration Drift Resolution

The Git copy of rule 100504 differed from the manager snapshot:

- Git used if_group=sysmon_event1; manager used if_sid=61603.
- Git matched -EncodedCommand only; manager also matched -enc.

Only rule 100504 was copied from the tested snapshot into the repository.
Other rule differences and ordering were retained for separate review.
The complete repository XML is not claimed to be identical to the manager.

## Test Tool Limitation

Feeding the archived full_log to wazuh-logtest, with and without
location EventChannel, produced decoder json and no Phase 3 result.
The live alert used windows_eventchannel.

Those offline attempts were not counted as rule PASS or FAIL.
Validation used live endpoint telemetry through the agent and manager.

## Integrity

SHA256SUMS.txt covers the 14 collected artifacts.
Windows execution record hashes matched the source after transfer.
The manager snapshot hash also matched its source.
Wazuh event export hashes were established after transfer; their
source-side hashes were not independently compared.

JSON event exports are reformatted records, not original log-line bytes.

## Limits and Next Work

This small test set does not establish an overall false-positive rate,
complete PowerShell argument coverage, or production readiness.
No new manager tuning was deployed.

Remaining work includes narrower Edge WebView2 exception conditions,
additional argument and negative tests, and before/after regression
when a new detection change is deployed.
