# AD-002 — Active Directory Authentication Detection Tuning

## Executive Summary

AD-002 demonstrates detection engineering, false-positive reduction,
regression testing, controlled deployment, and live alert verification
for Windows Active Directory authentication failures.

The original Wazuh correlation rule (100503) counted repeated Windows
failed logons using parent rule 60122. This included failures unrelated
to incorrect passwords, creating a false-positive risk.

A dedicated classifier (100507) was introduced to identify Windows
Security Event 4625 with SubStatus 0xC000006A.

Rule 100503 was then tuned to correlate events classified by 100507,
using a threshold of five events within 60 seconds for the same account.

## Lab Environment

| Component | Role |
|---|---|
| SOC-DC01 | Windows Server 2022 / Active Directory / Wazuh Agent 002 |
| SOC-WAZUH | Wazuh Manager 4.14.8 |
| Parrot OS | Analyst workstation / evidence management |
| Test account | SOC-LAB\soc.ad002.test |

The lab operates on an 8 GB RAM host with at most two VMs powered on.

## Detection Logic

### Rule 100507 — Incorrect Password Classifier

- Parent rule: 60122
- Windows Event ID: 4625
- SubStatus: 0xC000006A
- Purpose: distinguish incorrect-password failures from other logon failures

### Rule 100503 — Authentication Failure Correlation

- Correlation source: 100507
- Frequency: 5
- Timeframe: 60 seconds
- Grouping: same target account
- Severity: Level 10
- MITRE ATT&CK: T1110 (Brute Force)

This detection identifies repeated incorrect-password attempts against
the same account. It is not a complete password-spraying detection.

## Problem Investigation

Baseline Windows Security telemetry included:

| Record ID | Event ID | Finding |
|---|---|---|
| 22625 | 4625 | Logon rights failure; not an incorrect-password match |
| 22628 | 4771 | Kerberos pre-authentication failure |
| 22629 | 4625 | Incorrect password, SubStatus 0xC000006A |

Rule 100503 originally referenced 60122.

Adding classifier 100507 without updating the correlation rule
caused a regression: 100503 no longer fired for the replayed
incorrect-password sequence.

The corrected configuration declares 100507 before 100503 and
updates 100503 to reference 100507.

## Regression Testing

Testing used archived Windows telemetry replayed through the Wazuh
Rule Engine. The test environment temporarily adapted the
Windows EventChannel base rule for JSON-based logtest input;
the original files were restored after testing.

| Scenario | Expected | Result |
|---|---|---|
| 8 incorrect-password events | Correlation fires | PASS |
| 8 logon-rights failures | No 100503 correlation | PASS |
| 4 incorrect passwords + 4 rights failures | No 100503 correlation | PASS |

Correlation regression: **3/3 PASS**.

The negative test also produced a separate built-in rule (60204).
This does not represent a 100503 correlation alert.

## Controlled Deployment

The Wazuh local rules configuration was backed up before deployment.

- Backup integrity: PASS
- Wazuh configuration validation: PASS
- Controlled wazuh-manager restart: PASS
- Wazuh Agent 002: Active
- Rollback backup retained on SOC-WAZUH

Production-like deployment changed only the relevant local rules;
the built-in ruleset was not permanently modified.

## Live Verification

### Rule 100507

A controlled invalid-password attempt produced Windows Event 4625,
Record ID 22946, which triggered Wazuh Rule 100507.

### Rule 100503

Five controlled invalid-password attempts produced:

- Five Windows Event 4625 records
- Five Windows Event 4771 records
- Four Rule 100507 alerts
- One Rule 100503 correlation alert

Correlation occurred on Event Record ID **23033**.

Archived event metadata and alert metadata were cross-checked.

## Evidence

- [Authentication baseline](../../evidence/ad-002/AD002-auth-baseline-20261009.json)
- [Live rule 100507 detection](../../evidence/ad-002/AD002-live-detection-100507-20261009.json)
- [Live rule 100503 correlation](../../evidence/ad-002/AD002-live-correlation-100503-20261009.json)

Evidence includes metadata and SHA-256 hashes rather than a complete
public dump of raw Windows Security logs.

For some Event 4771 alerts, full_log was absent from alerts.json.
Raw-event hashes were computed from archives.json instead.
Missing alert content was not reconstructed.

## Source Configuration

- [Deployed configuration source](../../configs/wazuh/rules/local_rules.xml)
- [Standalone classifier example](../../detections/wazuh/rules/100507-incorrect-password.xml)

The standalone classifier is for reference and reuse.
Do not install it alongside the integrated local_rules.xml on the
same Manager, because that would duplicate Rule ID 100507.

## Rollback

1. Stop further authentication simulation.
2. Restore local_rules.xml from the verified pre-deployment backup.
3. Validate configuration using wazuh-analysisd -t.
4. Restart wazuh-manager only after validation passes.
5. Verify Manager status, Agent connectivity, and alert behavior.

## Limitations

- Tested on a controlled Active Directory lab account.
- Tests cover specific event types and recorded samples.
- Synthetic replay does not replace live verification.
- No enterprise-wide false-positive rate was measured.
- No broad password-spraying or multi-account coverage is claimed.
- The Git configuration and live Manager configuration had
  pre-existing differences; byte-level parity is not claimed.

## Outcome

AD-002 demonstrates an evidence-based SOC detection improvement cycle:

Telemetry → Detection → Root Cause Analysis → Tuning →
Regression Testing → Controlled Deployment → Live Verification →
Evidence Preservation.
