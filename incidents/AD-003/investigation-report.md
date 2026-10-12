# AD-003 — Active Directory Authentication Investigation

## 1. Case Overview

| Field | Value |
|---|---|
| Case ID | AD-003 |
| Case Type | Authorized Authentication Simulation |
| Date | 2026-10-11 |
| Domain | SOC-LAB.LOCAL |
| Target Host | SOC-DC01 |
| Target IP | 192.168.50.10 |
| Source Host | PARROT |
| Source IP | 192.168.50.1 |
| Test Account | soc.ad003.test |
| Authentication Protocol | NTLM |
| Investigation Status | Windows Evidence Verified; SIEM Validation Incomplete |
| Confirmed Security Incident | No |

## 2. Executive Summary

AD-003 investigated two controlled SMB authentication attempts against
SOC-DC01 using a dedicated, non-privileged domain test account.

The first attempt used an incorrect password and produced Windows Security
Events 4776 and 4625. The second used the correct password and produced
Events 4776 and 4624.

Both attempts originated from Parrot OS at 192.168.50.1.

The observed behavior was authorized and expected. No evidence establishes
brute-force activity, account compromise, privilege escalation, or lateral
movement.

Windows telemetry was collected and preserved successfully. The corresponding
AD-003 events were not found in the Wazuh archives examined during the
investigation, so live SIEM detection is not claimed.

## 3. Timeline

All timestamps below are based on the verified Windows Security Events.

| Local Time (UTC+07) | UTC | Event | Record ID | Observation |
|---|---|---|---|---|
| 2026-10-11 10:12:29 | 2026-10-11 03:12:29 | 4776 | 23791 | NTLM credential validation failed |
| 2026-10-11 10:12:29 | 2026-10-11 03:12:29 | 4625 | 23792 | Network Logon Type 3 failed |
| 2026-10-11 10:14:37 | 2026-10-11 03:14:37 | 4776 | 23840 | NTLM credential validation succeeded |
| 2026-10-11 10:14:37 | 2026-10-11 03:14:37 | 4624 | 23841 | Network Logon Type 3 succeeded |

## 4. Technical Findings

### Finding 1 — Failed Authentication

- Account: soc.ad003.test
- Source IP: 192.168.50.1
- Source workstation: PARROT
- Event 4776: Status 0xC000006A
- Event 4625: Status 0xC000006D
- Event 4625: SubStatus 0xC000006A
- Logon Type: 3
- Authentication: NTLM

Assessment: Incorrect password during an authorized test.

### Finding 2 — Successful Authentication

- Account: soc.ad003.test
- Source IP: 192.168.50.1
- Source workstation: PARROT
- Event 4776: Status 0x0
- Event 4624: Network Logon Type 3
- Authentication: NTLM
- Logon ID: 0x275cd0

Assessment: Successful authentication during the authorized test.
SMB share enumeration succeeded, but access to administrative shares
was not demonstrated.

### Finding 3 — Wazuh Telemetry Coverage

- DC01 Agent ID: 002
- Historical ingestion: 3,555 events on 2026-10-09
- AD-003 events in examined Wazuh archives: Not found
- Wazuh version: 4.14.8
- AD-003 live ingestion: Not verified

Historical ingestion demonstrates that the DC01 agent previously delivered
events to Wazuh. It does not establish delivery during AD-003.

### Finding 4 — Detection Configuration

Custom Rule 100507:
- Windows Event ID 4625
- SubStatus 0xC000006A
- Level 3

Custom Rule 100503:
- Parent Rule 100507
- Frequency 5
- Timeframe 60 seconds
- Correlation by targetUserName
- Level 10

Configuration validation: 9/9 PASS.

Python reference-model behavioral validation: 6/6 PASS.

Wazuh runtime regression: NOT VERIFIED.

Historical replay used decoder `json` instead of `windows_eventchannel`.
Its result cannot establish whether the deployed custom rule would match
a live Windows EventChannel event.

## 5. Evidence Handling

Evidence source:
SOC-DC01 Windows Security Log.

Acquisition format:
Individual Windows Event XML exports and baseline JSON.

Transfer:
SCP from SOC-DC01 to Parrot OS.

Destination:
~/soc-evidence/AD-003/windows/

The destination contained six transferred files:
four Event XML files, baseline.json, and sha256-manifest.csv.

SHA-256 verification:
5/5 evidence files matched the source manifest at the destination.

Raw evidence remains outside the public Git repository.

## 6. 5W1H Assessment

| Question | Finding |
|---|---|
| Who | Dedicated account soc.ad003.test |
| What | One failed and one successful NTLM authentication |
| When | 2026-10-11, 10:12–10:14 UTC+07 |
| Where | SOC-DC01, from Parrot 192.168.50.1 |
| Why | Authorized authentication and detection validation |
| How | SMB authentication using an incorrect then correct password |

## 7. Triage and Incident Classification

Classification: Authorized Benign Simulation.

Confirmed compromise: No.

Confirmed brute-force attack: No.

Containment: Not required for the observed authorized behavior.

Recovery: Not required for the observed authorized behavior.

The lack of an AD-003 alert must not be classified as a confirmed custom
rule failure because ingestion of these specific events was not verified.

## 8. Detection Improvement and Next Steps

1. Preserve the verified authentication evidence and hashes.
2. Retain the existing custom rule configuration.
3. Perform a future Wazuh runtime regression when resources permit.
4. Confirm live ingestion before claiming end-to-end detection coverage.
5. Test single-failure, same-account repeated failures, cross-account
   negatives, and timeframe boundaries.
6. Document any confirmed rule behavior and tuning changes separately.

## 9. Final Conclusion

AD-003 demonstrated controlled Windows authentication telemetry
collection, evidence correlation, secure transfer, and SHA-256 verification.

The Python reference model passed six behavioral checks.

Historical Wazuh Agent logs confirmed repeated Agent-to-Manager
connection failures during the October 11 authentication simulation.
This explains the missing AD-003 SIEM visibility within the investigated
scope, while the underlying infrastructure cause remains undetermined.

A separate October 12 recovery verification confirmed 3/3 Windows
Security Event 4624 records ingested and matched to built-in Rule 60106.

Subsequent live regression on October 12 verified custom Rule 100507
for individual incorrect-password events and Rule 100503 for five
same-account failures within 60 seconds. A below-threshold negative
test also passed. The three scoped tests achieved 3/3 PASS; cross-account
and timeframe-boundary scenarios remain untested.

No malicious compromise or brute-force attack was confirmed.

## 10. Historical Connectivity Gap and Recovery Verification

### 10.1 Historical Findings — 2026-10-11

The original AD-003 authentication simulation generated four verified Windows Security Events on SOC-DC01 between 10:12 and 10:14 (UTC+07:00).

Historical Wazuh Agent logs confirmed repeated connection failures to `192.168.50.30:1514/TCP` during the same interval:

- 10:02:21 — Wazuh Agent started.
- 10:12:10 — Connection failure, error 1216.
- 10:12:41 — Connection failure, error 1216.
- 10:13:12 — Connection failure, error 1216.
- 10:13:43 — Connection failure, error 1216.
- 10:14:04 — Enrollment connection failure on TCP/1515, error 1208.

The examined October 11 Wazuh archive contained 3,719 valid JSON records: 2,292 from Agent 000, 1,427 from Agent 001, and none from Agent 002.

**Root Cause Assessment:** Agent-to-Manager connectivity failure is the evidenced immediate explanation for the missing AD-003 SIEM telemetry. The underlying cause of the connection failure was not established.

The missing events must not be classified as a confirmed failure of custom detection Rules 100507 or 100503.

### 10.2 Live Pipeline Recovery Verification — 2026-10-12

After SOC-WAZUH and SOC-DC01 were started, Agent 002 was confirmed Active.

Three newly observed Windows Security Event 4624 records were independently matched to Wazuh archive entries:

| EventRecordID | Event ID | Channel | Wazuh Rule | Result |
|---|---|---|---|---|
| 25370 | 4624 | Security | 60106 | PASS |
| 25373 | 4624 | Security | 60106 | PASS |
| 25386 | 4624 | Security | 60106 | PASS |

**Live ingestion verification: 3/3 PASS.**

A sanitized evidence summary was transferred from SOC-WAZUH to Parrot and verified using SHA-256.

Evidence: [AD003 Live Ingestion](../../evidence/ad-003/AD003-live-ingestion-20261012.json)

SHA-256: `58952851a3d4e0555f66abac2575442d397df713d6b8f668a631bcd8b3b28f1d`

### 10.3 Detection Coverage and Limitations

- October 11 AD-003 historical events were not recovered in the examined archive.
- October 12 recovery verification is a separate test, not a replay of the original authentication simulation.
- Live Event 4624 ingestion and built-in Rule 60106 were verified.
- On October 12, custom Rules 100507 and 100503 passed three scoped live regression tests (see Section 10.4). Cross-account separation and timeframe-boundary tests remain outstanding.
- No configuration change was necessary to restore observed connectivity.
- No production false-positive rate or continuous historical availability is claimed.
- The underlying infrastructure cause of the October 11 connection failure remains unknown.

### 10.4 Live Detection Regression — 2026-10-12

After recovery of Agent-to-Manager connectivity, three controlled
authentication regression tests were completed on SOC-DC01.

| Test | Expected | Observed | Result |
|---|---|---|---|
| AD003-R01 | Single incorrect password triggers Rule 100507 | Event 25687 triggered Rule 100507, Level 3 | PASS |
| AD003-R02 | Five failed logons within 60 seconds trigger Rule 100503 | Events 25720, 25722, 25724, 25726 matched 100507; Event 25731 triggered 100503, Level 10 | PASS |
| AD003-R03A | Two failures below threshold do not trigger Rule 100503 | Events 25770 and 25772 matched 100507; no correlation alert in the scoped test window | PASS |

**Result: 3/3 scoped live regression tests PASS.**

Evidence was collected from Wazuh Archives and Alerts, transferred
to Parrot, and verified with SHA-256.

See [Live Detection Regression Results](../../detections/ad-003/live-regression-results.md)
for the test matrix, evidence links, hashes, and limitations.

These tests are separate from the October 11 historical authentication
simulation. Cross-account separation and the 60-second timeframe
boundary were not live-tested, and no production false-positive rate
was established.

## 11. Related Documentation

- detections/ad-003/offline-validation-results.md
