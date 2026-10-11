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

AD-003 successfully demonstrated controlled Windows authentication
telemetry collection, evidence correlation, secure transfer, and integrity
verification.

The Python reference model passed six behavioral checks, while Wazuh
runtime detection remains unverified.

The investigation did not identify a confirmed malicious incident.

## 10. Related Documentation

- detections/ad-003/offline-validation-results.md
