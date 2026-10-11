# INC-003 — Controlled PowerShell Incident Response

## 1. Executive Summary

INC-003 documents an authorized, benign PowerShell
simulation conducted on SOC-WIN10 on 2026-10-11.

A PowerShell process launched a child PowerShell process
using the `-EncodedCommand` argument. Sysmon recorded
the process creation, and Wazuh generated Alert Rule
92057 at Level 12.

The analyst correlated the alert with endpoint process
metadata, confirmed the target process identity,
terminated the controlled process, and verified that
the endpoint monitoring services remained operational.

This case demonstrates a controlled SOC response
workflow. It does not represent a real malware
infection or confirmed unauthorized compromise.

## 2. Incident Classification

| Field | Value |
|---|---|
| Case ID | INC-003 |
| Case type | Authorized incident response simulation |
| Date | 2026-10-11 |
| Endpoint | SOC-WIN10 |
| SIEM | Wazuh 4.14.8 |
| Initial detection | Rule 92057 |
| Detection level | 12 |
| MITRE ATT&CK | T1059.001 — PowerShell |
| Actual impact | No malicious impact intended or established |
| Response status | Containment and verification completed |
| Documentation status | Closed; GitHub publication pending |

The Wazuh alert level is a detection severity,
not proof of an actual high-severity compromise.

## 3. Investigation — 5W1H

**Who:** An authorized lab administrator performed
the simulation using the local test account.

**What:** An encoded PowerShell child process was
created and subsequently terminated.

**When:** The process was created at 07:24:37 and
terminated at 07:26:55 on 2026-10-11 (UTC+07:00).

**Where:** SOC-WIN10, with telemetry ingested by
SOC-WAZUH through Wazuh Agent 001.

**Why flagged:** Encoded PowerShell commands can be
associated with script obfuscation and suspicious
execution, although encoding alone is not malicious.

**How:** Sysmon Event ID 1 was correlated with the
Wazuh alert using EventRecordID and ProcessGuid.
Containment was performed after process identity checks.

## 4. Verified Incident Timeline

All times below are in UTC+07:00.

| Time | Event | Evidence |
|---|---|---|
| 07:14:10 | Baseline encoded PowerShell test | Sysmon Record 20704 |
| 07:24:37 | Controlled incident process created | Sysmon Record 20779 |
| 07:24:39 | SIEM detection generated | Wazuh Rule 92057 |
| 07:26:55 | Targeted process containment | Windows containment transcript |
| 07:28:01 | Containment transcript finalized | SHA-256 verified |
| 07:29:38 | Post-containment checks | Windows recovery transcript |
| 07:32:28 | Positive regression POS-02 | Sysmon Record 20782 |
| 07:34:08 | Negative regression NEG-01 | Sysmon Record 20785 |

## 5. Detection and Triage

The confirmed incident alert contained:

- Wazuh Agent: 001
- Rule ID: 92057
- Rule Level: 12
- Sysmon Event ID: 1
- EventRecordID: 20779
- Process ID: 4512
- Parent Process ID: 7180
- ProcessGuid:
  `{e12a69d9-d745-6aca-e801-000000002300}`
- Process image: `powershell.exe`
- Parent image: `powershell.exe`
- Suspicious argument: `-EncodedCommand`

The test payload only printed an incident marker
and invoked `Start-Sleep -Seconds 1800`.

The alert was correlated with the source process
using the exact EventRecordID and ProcessGuid.

## 6. Containment

Before containment, the analyst verified:

- Target PID 4512 was still running.
- Process name matched `powershell.exe`.
- Command line matched the controlled payload.
- Creation time matched the expected process.

The identity check returned:

`IDENTITY_VERIFIED: YES`

The analyst then executed a targeted `Stop-Process`
at 07:26:55 (UTC+07:00).

The immediate post-action check returned:

`RESULT: CONTAINMENT_VERIFIED`

The measured interval from process creation to
containment was approximately 2 minutes 18 seconds
in this controlled simulation.

No blanket termination of unrelated PowerShell
processes was performed.

## 7. Post-Containment Verification

At 07:29:38, the endpoint check confirmed:

- Target PID 4512: absent
- Sysmon64: Running
- WazuhSvc: Running
- Sysmon Operational log: Enabled

Wazuh Agent 001 was also confirmed Active after
the containment exercise.

A corresponding Sysmon Event ID 5 was not found
during the scoped verification. Therefore, this
report does not claim Sysmon process-termination
telemetry for the target process.

The process absence and Windows execution transcript
provide the verified containment evidence.

No broader enterprise recovery activity was required
for this benign simulation.

## 8. Detection Regression

| Case | Execution chain | Wazuh result | Verdict |
|---|---|---|---|
| POS-01 | PowerShell to encoded PowerShell | 92057, Level 12 | PASS |
| POS-02 | CMD to encoded PowerShell | 100504, Level 8 | PASS |
| NEG-01 | CMD to normal PowerShell | 92032, Level 3 | PASS for encoded-rule negative condition |

For NEG-01, neither Rule 100504 nor Rule 92057
triggered. Event 20785 was confirmed in Wazuh
alerts.json and archives.json.

Rule 92032 matched the CMD parent execution
pattern. The negative test was not alert-free.

**Tuning decision:** No rule modification required
based on these three scoped regression cases.

These tests do not establish a production
false-positive rate.

## 9. Evidence Preservation

Seven source evidence files were collected:

- Five Wazuh JSONL records covering baseline,
  incident detection, positive regression,
  and negative regression.
- Two Windows PowerShell transcripts covering
  containment and post-containment verification.

All seven files passed SHA-256 integrity verification
after transfer to the Parrot analyst host.

Original evidence is stored outside the public
Git repository. Only reviewed, sanitized summaries
are intended for publication.

## 10. Scope and Limitations

- Authorized benign simulation only.
- No evidence of actual malware compromise.
- No Sysmon Event ID 5 found for the target.
- Regression covers three controlled cases only.
- Containment consisted of targeted process
  termination, not network or host isolation.
- Prior SOC incidents are separate exercises and
  are not represented as one continuous attack.

## 11. Closure Assessment

Verified outcomes:

- Detection: PASS
- Event correlation and triage: PASS
- Targeted process containment: PASS
- Post-containment endpoint verification: PASS
- Regression tests: 3/3 PASS
- Evidence integrity: 7/7 PASS

**Technical disposition:** Controlled simulation
successfully contained and verified.

**Case closure:** Closed — authorized benign simulation (2026-10-11). Technical verification, regression testing, and evidence integrity checks completed. GitHub publication completed.

## 12. Lessons Learned

1. Alert severity must be separated from actual
   incident impact and analyst verdict.
2. PID, ProcessGuid, command line, and creation time
   reduce the risk of terminating an unrelated process.
3. Positive and negative regression tests are both
   necessary for detection quality assessment.
4. Evidence hashes and documented limitations
   improve reproducibility and investigation integrity.
