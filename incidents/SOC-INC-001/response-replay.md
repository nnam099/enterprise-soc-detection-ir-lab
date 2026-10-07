# SOC-INC-001 Process Containment Replay

## Summary

On 2026-10-07, a controlled encoded PowerShell process was detected
by Wazuh rule 92057 and terminated by the analyst. A subsequent
process query confirmed that the target PID was absent.

This replay is separate from the original 2026-09-29 simulation.
It validates process containment, not the complete original attack chain.

## Scope and Context

- VM and Wazuh agent name: SOC-WIN10
- Observed Windows hostname: WIN10-01
- Account and response operator: WIN10-01\localadmin
- Target PID: 7380
- Parent PID: 7576
- ProcessGuid: {e12a69d9-c229-6ac5-5f01-000000001e00}
- Environment: isolated lab; SOC-WAZUH and SOC-WIN10 running

The decoded payload printed a lab marker and slept for 900 seconds.
It did not perform a download, create persistence, or use WinRM.

## Timeline

All timestamps below are UTC on 2026-10-07.

| Time | Observation | Evidence |
|---|---|---|
| 03:53:13.158 | Replay PowerShell process created | Wazuh Sysmon Event 1, Record ID 16740 |
| 03:53:15.052 | Rule 92057 generated a level 12 alert | Alert ID 1791345195.365301 |
| 03:56:20.5616761 | Analyst requested process termination | process-after.json |
| 03:56:22.6866738 | Target PID was absent after termination | process-after.json |

## Response Decision and Action

The process was intentionally generated for this response exercise.
Its identity was checked against the saved PID, creation time, and
command line before executing Stop-Process.

The analyst retained the parent PowerShell console and terminated
only the replay process. Stop-Process completed without a reported error.
The subsequent query recorded ProcessAbsent as true.

Verdict: authorized controlled lab activity.
Process containment test: PASS.

## Evidence

Artifacts are stored in evidence/response-replay/:

- process-before.json
- process-after.json
- SOC-INC-001-replay-alert.json
- SHA256SUMS.txt

SHA-256 values matched the source values after transfer to Parrot.
The exported alert preserves its fields, but is a reformatted JSON
export rather than a byte-for-byte copy of the original log line.

## Limitations and Follow-up

- No matching Sysmon Event 5 was found among the latest 200 Event 5
  records queried. Termination telemetry remains unverified.
- Process absence was verified at one point in time; sustained
  monitoring for recurrence has not yet been documented.
- Endpoint isolation, account containment, eradication, and recovery
  were not performed in this replay.
- Rule 92057 detected this event. The absence of a 100504 alert does
  not establish a detection failure.
- Manager and Git copies of rule 100504 differ. Rule selection and
  configuration drift require testing before any rule change.

The overall incident response lifecycle remains open.
