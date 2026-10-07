# DFIR-001 — Controlled Hunting Evidence Investigation

## Assessment and Scope

This case reviews four independent SOC-LAB hunting exercises from
2026-09-30. The timeline contains 10 stored records, not necessarily
10 distinct activities or one attack chain.

Verdict: controlled lab validation; no real compromise established.
Status: controlled evidence review completed within the stated scope.
Timeline rebuild matched the existing manifest on 2026-10-07.

Endpoint VM / agent: SOC-WIN10.
Observed computer: WIN10-01.SOC-LAB.LOCAL where preserved.
This case is separate from SOC-INC-001 and its response exercises.

## Findings

| Hunt | Records | Observation |
|---|---:|---|
| HUNT-001 | 3 | PowerShell detections 92027, 92057, and 100504 |
| HUNT-002 | 3 | Authentication success and failed-logon detections |
| HUNT-003 | 2 | cmd.exe with wsmprovhost.exe parent |
| HUNT-004 | 2 | Registry Run Key modification |

### HUNT-001

The curated 100504 source records Event 1, PID 5552, parent PID 5584,
a cmd.exe parent, an encoded command, and a ProcessGuid under
WIN10-01/localadmin.

The normalizer previously omitted these fields because it only handled
data.win. It now also maps the curated event structure.
Source evidence bytes were unchanged.

Missing computer, endpoint timestamps, and Event Record ID remain null;
values from neighboring records were not substituted.

### HUNT-002

Event 4624 records nam.user with Logon Type 7.
Event 4625 records hunt002-test, including rule 100503, with source
address 127.0.0.1.

The successful and failed logons concern different target accounts.
They do not establish a failed-then-successful compromise.
ATT&CK rule metadata is retained without treating it as proof of intent.

### HUNT-003

The reviewed export records cmd.exe under a wsmprovhost.exe parent,
SOC-LAB/nam.user, and the HUNT003-RULE100502-VALIDATION marker.

Event Record ID: 7366. PID: 480.
ProcessGuid: {e12a69d9-8f92-6abc-6001-000000001500}.
Endpoint systemTime: 2026-09-30T04:26:58.6941792Z.
Wazuh timestamp: 2026-09-30T04:27:00.449+0000.

Differently named exports are not automatically independent evidence.

### HUNT-004

The reviewed export records Event 13 for HUNT004-RUNKEY-VALIDATION
under SOC-LAB/nam.user. Value data contains a controlled echo command.

Event Record ID: 7380. PID: 872.
ProcessGuid: {e12a69d9-95ba-6abc-7101-000000001500}.
Endpoint systemTime: 2026-09-30T04:53:23.4169804Z.
Wazuh timestamp: 2026-09-30T04:53:24.407+0000.

This demonstrates Run Key modification. It does not prove execution
at a later logon or verified cleanup.

## Correlation and Provenance

Ten records retain source traceability. Shared timestamps alone do not
establish distinct activities or independent corroboration.

The evidence does not establish that authentication tests caused WinRM
execution or that the WinRM process created the HUNT-004 Run Key.

All current records contain Wazuh rule metadata. The wazuh_alert label
does not prove whether an export came from alerts.json or archives.json.
A filename containing sysmon does not prove independent EVTX acquisition.

## Integrity and Validation

The SHA-256 manifest covers 10 sources and three derived timelines.
Source bytes matched the baseline saved before the current changes.
This is not proof of original acquisition-time hashing or complete
chain of custody.

Verification passed for artifact presence, manifest hashes, JSONL
structure, source types, JSON Schema, and hashed source references.

JSONL and CSV preserve available correlation fields. Markdown is a
shortened view. Wazuh and endpoint timestamps are retained separately.

## Limitations

- Independent EVTX, memory, or disk acquisition is not demonstrated.
- Timeline sorting uses the preserved Wazuh timestamp.
- Some source strings contain extra escaping or HTML entities.
- Missing fields are not reconstructed.
- Persistence execution, cleanup, and recovery are outside this evidence.
- Independent hunting tests are not represented as one attack chain.

## Evidence and Reproduction

- [Source evidence](../../../hunting/evidence/)
- [JSONL timeline](../../timelines/DFIR-001-timeline.jsonl)
- [CSV timeline](../../timelines/DFIR-001-timeline.csv)
- [Markdown timeline](../../timelines/DFIR-001-timeline.md)
- [SHA-256 manifest](../../evidence/DFIR-001/SHA256SUMS.txt)
- [Evidence manifest](evidence-manifest.md)

From the repository root, run build_timeline.py, export_timeline.py,
and verify_case.py in dfir/scripts/, in that order.
The verifier requires jsonschema.

Reproduction must match the existing manifest without rewriting its
hashes to conceal unexpected differences.
