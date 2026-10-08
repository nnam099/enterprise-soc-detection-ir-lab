# SOC-INC-001 Capstone Investigation and Response Report

## Executive Summary

The original controlled simulation on 2026-09-29 produced evidence of
WinRM process execution, encoded PowerShell, and a Registry Run Key
modification on SOC-WIN10 under SOC-LAB\nam.user.

Separate exercises on 2026-10-07 demonstrated verified process termination,
AD account disable and restoration, and four live detection validation
tests. These exercises extend the portfolio's response evidence but are
not represented as actions performed during the original simulation.

Verdict: authorized controlled lab activity; no real compromise established.
Status: investigation documented; response exercises and sampled recovery
checks verified. Separate INC-002 tuning has live before/after evidence
for preserving severity in the tested PowerShell cases.
SOC-INC-001 is closed as an educational exercise within its verified
scope, with accepted evidence limitations documented in the closure assessment.

## Scope and Evidence Boundaries

| Work item | Date | Context | Evidence |
|---|---|---|---|
| Original simulation | 2026-09-29 | SOC-WIN10, SOC-LAB\nam.user | analysis.md and timeline.md |
| Process response replay | 2026-10-07 | WIN10-01\localadmin | response-replay.md |
| Account response exercise | 2026-10-07 | nam.user, operated by domain Administrator | account-response.md |
| Live detection baseline | 2026-10-07 | WIN10-01\localadmin | Encoded PowerShell test report |

VM and agent name SOC-WIN10 differs from observed Windows hostname WIN10-01.
VM name SOC-DC01 differs from observed Windows hostname DC01.
Only two VMs were operated concurrently during the response exercises.

## Original Investigation

The original incident documents report three correlated observations:

| Timestamp UTC on 2026-09-29 | Detection | Observation |
|---|---|---|
| 14:25:06 | 100502 | cmd.exe with wsmprovhost.exe parent |
| 14:26:37 | 100504 | Encoded PowerShell with wsmprovhost.exe parent |
| 14:34:07 | 100501 | Registry Run Key value SOC-INC-001 modified |

The decoded PowerShell command printed a lab marker.
The Run Key value contained cmd.exe /c echo SOC-INC-001.
These are controlled test artifacts, not malicious indicators.

An attempted connection to 192.168.50.30:55000 was excluded from the
confirmed timeline because matching Sysmon Event 3 was not observed.
Independent rule 100505 validation is not merged into this incident.

## Response Verification

Process replay:
- Rule 92057 detected PID 7380 at level 12.
- PID, creation time, and command line were checked before termination.
- Stop-Process was requested at 03:56:20 UTC on 2026-10-07.
- A query at 03:56:22 UTC confirmed the PID was absent.
- Matching Sysmon termination telemetry remains unverified.

Account exercise:
- nam.user was initially enabled and not locked out.
- Disable was verified on DC01 and corroborated by Event 4725,
  Record ID 18248.
- The enabled baseline was restored and corroborated by Event 4722,
  Record ID 18261.
- Authentication blocking and existing session revocation were not tested.
- A later runas check created PowerShell PID 2536 under the target SID.
  DC01 Event 4768, Record ID 18763, recorded Status 0x0 at
  2026-10-07T06:59:15.4728370Z from client 192.168.50.20.
  This supports successful post-restoration domain authentication;
  the October 8 follow-up additionally verified an observed desktop
  session, DC Kerberos authentication, and profile file readback.
  Recovery of all applications remains unverified.

## Run Key Verification and Sampled Monitoring

On 2026-10-07T05:51:59.2292509Z, the SOC-INC-001 value was absent
from the loaded Run key of the original nam.user SID.

Eleven subsequent samples from 06:22:50.7140884Z to 06:28:04.4634662Z
spanned 313.75 seconds. The value was absent and Sysmon64/WazuhSvc
were Running at every sample. A subsequent manager check reported
agent 001 as Active.

These are October current-state checks, not proof of the historical
deletion action. Changes between samples remain outside the verified scope.
The later authentication check is documented separately in the recovery report.

[Recovery report and supporting screenshots](recovery-verification.md)

## Detection Findings

Four live baseline tests passed:
- PowerShell parent with -EncodedCommand: 92057, level 12.
- CMD parent with -EncodedCommand: 100504, level 8.
- CMD parent with -enc: 100504, level 8.
- Ordinary -Command: 92027, level 4, with no tested encoded detection hit.

Rule 100504 in Git was synchronized with the live-validated manager copy.
No new manager tuning was deployed during these tests.
The remaining XML configuration differences require separate review.

## Separate WebView2 Tuning Review

INC-002 correlated a historical file creation event with WebView2
process ancestry and a subsequent executable signature/hash check.
The assessment is likely benign; the created DLL was not verified.

The old rule reduced severity when msedgewebview2.exe appeared in a
PowerShell-created target filename. After narrowing and deploying rule
100001, both controlled PowerShell file cases received 92213 / level 15.
The intended WebView2 level 3 branch remains unverified by live telemetry.

[INC-002 triage and validation](../INC-002-wazuh-fp-tuning/triage-report.md)

## Evidence and Integrity

- [Original analysis](analysis.md)
- [Original timeline](timeline.md)
- [Process response report](response-replay.md)
- [Account response report](account-response.md)
- [Live detection test report](../../detections/wazuh/tests/encoded-powershell/README.md)
- [Process evidence](evidence/response-replay/)
- [Account evidence](evidence/account-response/)
- [Recovery evidence](evidence/recovery/)

Response artifacts have SHA-256 manifests. Their transferred hashes
matched source values and staged Git bytes were verified.
The detection report describes its separate integrity limitations.

DFIR-001 is a separate investigation using hunting evidence. Its events
must not be treated as part of this incident without correlation evidence.

## Scoped Closure and Follow-up

SOC-INC-001 is closed as an educational exercise on 2026-10-08.
The closure assessment records the verified scope and accepted limits.

Correct-SID Run Key absence, eleven monitoring samples spanning about
five minutes fourteen seconds, post-restoration authentication, and the
October 8 desktop/profile file checks support this scoped decision.
The sampled monitoring window is accepted for this exercise.

Historical Run Key deletion time and actor, Sysmon Event 5 termination
telemetry, existing session revocation, and recovery of all applications
remain unverified. These limits do not become verified through closure.
Longer monitoring may be added if the exercise scope is expanded.

INC-002 live WebView2 positive-branch validation and broader anomaly
evaluation remain separate follow-up work. They are not SOC-INC-001
closure criteria. DFIR-001 remains a separate controlled evidence review.

## Analyst Lessons

A missing custom rule ID does not imply missing detection.
Telemetry gaps must be distinguished from rule failures.
Response requires target identity checks and post-action verification.
Independent exercises must retain separate users, timestamps, and evidence.

- [Lab completion and closure assessment](closure-assessment.md)
