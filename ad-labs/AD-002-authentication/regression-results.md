# AD-002 — Detection Tuning & Regression Results

## Test Objective

Improve Wazuh Rule 100503 so repeated incorrect-password
attempts are distinguished from unrelated Windows logon failures.

Test environment:
- Windows Server 2022: SOC-DC01
- Wazuh Manager: 4.14.8
- Agent ID: 002
- Test account: SOC-LAB\soc.ad002.test

All authentication attempts were authorized and performed
against the dedicated lab test account.

## 1. Baseline Findings

| Record ID | Event ID | Observation |
|---|---|---|
| 22625 | 4625 | Logon rights failure, Status 0xC000015B |
| 22628 | 4771 | Kerberos authentication failure, Status 0x18 |
| 22629 | 4625 | Incorrect password, SubStatus 0xC000006A |

Original correlation rule:
- Rule ID: 100503
- Parent reference: 60122
- Threshold: 5 matches / 60 seconds
- Same target username

Problem: Parent 60122 matched additional classes of
Windows logon failures, creating a false-positive risk.

## 2. Classifier Development

New Rule 100507:
- Parent: 60122
- Windows Event ID: 4625
- Required SubStatus: 0xC000006A
- Purpose: classify incorrect-password attempts

Initial offline regression: 3/3 PASS.
Wazuh classifier engine regression: 3/3 PASS.

## 3. Regression Gap Discovered

Baseline synthetic replay:
- 8 repeated incorrect-password events
- Rule 100503 triggered at event 5

After adding Rule 100507 without updating 100503:
- 8 events matched Rule 100507
- Rule 100503 did not trigger
- Regression detected: FAIL

Changing only the 100503 reference to 100507 was
insufficient in the first candidate configuration.

An additional attempt failed Wazuh configuration validation
because a group element was inserted inside an existing group.

Root causes and fixes:
1. Update the correlation reference from 60122 to 100507.
2. Declare Rule 100507 before Rule 100503.
3. Insert the rule element, not a nested group wrapper.

## 4. Final Correlation Regression

| Test | Expected | Actual | Result |
|---|---|---|---|
| 8 incorrect-password events | 100503 fires | Fired at event 5 | PASS |
| 8 logon-rights failures | No 100503 | No 100503 | PASS |
| 4 incorrect passwords + 4 rights failures | No 100503 | No 100503 | PASS |

Final correlation regression: **3/3 PASS**.

A separate built-in rule 60204 appeared in the negative
replay. This was not a Rule 100503 correlation alert.

The replay used archived events through wazuh-logtest.
The temporary decoder adaptation and test rule changes
were restored after validation.

## 5. Controlled Deployment

Verified pre-deployment backup:

/var/backups/soc-ad002/20261009T061853Z/local_rules.xml

Checks:
- Backup SHA-256 integrity: PASS
- Wazuh configuration validation: PASS
- Controlled Manager restart: PASS
- Wazuh analysisd: Running
- Agent 002: Active

Deployed configuration SHA-256:

9e07ca5900e3ad0e716858cb6b5e2b2667ba21402ee2fafddd3a0eab76bb54ff

## 6. Live Rule 100507 Verification

Controlled incorrect-password authentication attempt.

| Field | Observed value |
|---|---|
| Event Record ID | 22946 |
| Windows Event | 4625 |
| SubStatus | 0xC000006A |
| Wazuh Rule | 100507 |
| Result | PASS |

Corresponding Kerberos Event:
- Record ID: 22945
- Event ID: 4771
- Rule ID: 60104

## 7. Live Rule 100503 Verification

Five controlled incorrect-password attempts were performed
against the same test account.

Test execution:
- Start UTC: 2026-10-09 06:30:41
- End UTC: 2026-10-09 06:30:45

Observed records:

| Record ID | Event ID | Rule |
|---|---|---|
| 23025 | 4625 | 100507 |
| 23027 | 4625 | 100507 |
| 23029 | 4625 | 100507 |
| 23031 | 4625 | 100507 |
| 23033 | 4625 | 100503 |

Additional five Event 4771 records matched Rule 60104.

Live correlation result: **PASS**.

Archives and Alerts matched for the relevant event
metadata and Event Record IDs.

## 8. Evidence Integrity

Baseline evidence:
- AD002-auth-baseline-20261009.json

Live classifier evidence:
- AD002-live-detection-100507-20261009.json
- SHA-256: d2529d57b5c53450e608ab3923e8ef91bf5e27a16c22950a27797ea1294a98b9

Live correlation evidence:
- AD002-live-correlation-100503-20261009.json
- SHA-256: 9af013724e95ca787b5e35adeb2d0345e5518f5c29daabf4c33087dbf7c50dd8

For five Kerberos 4771 alerts, full_log was absent
from alerts.json. Raw-event SHA-256 values were
taken from archives.json without reconstruction.

## 9. Limitations

- Controlled lab simulation, not a real intrusion.
- Limited event samples and a single test account.
- No enterprise-wide false-positive rate measured.
- Not a multi-account password-spraying detector.
- Git and live Wazuh configuration files had
  pre-existing differences; byte parity is not claimed.
- Regression testing does not guarantee all possible
  Windows authentication cases are covered.

## 10. Outcome

Telemetry -> Investigation -> Rule Development ->
Regression Gap -> Tuning -> Regression PASS ->
Controlled Deployment -> Live Alert Verification ->
Evidence Preservation.

Final AD-002 functional verification: PASS.
