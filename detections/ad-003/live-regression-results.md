# AD-003 — Live Detection Regression Results

## 1. Objective and Scope

Validate Wazuh custom authentication detection Rules 100507
and 100503 using controlled Windows Security Events.

Test date: 2026-10-12 (UTC+07:00).

Environment:
- Source: Parrot OS (192.168.50.1)
- Endpoint: SOC-DC01 (192.168.50.10)
- Wazuh Manager: SOC-WAZUH (192.168.50.30)
- Wazuh Agent ID: 002
- Test account: soc.ad003.test

All authentication attempts were authorized lab simulations.
No malicious compromise was confirmed.

## 2. Detection Logic

| Rule | Purpose | Condition |
|---|---|---|
| 100507 | Incorrect-password classifier | Event 4625, SubStatus 0xc000006a, parent 60122 |
| 100503 | Repeated failed-logon correlation | Five matching events within 60 seconds, same targetUserName |

Rule 100507 is Level 3; Rule 100503 is Level 10.

## 3. Test Results

| Test | Expected Behavior | Actual Behavior | Result |
|---|---|---|---|
| AD003-R01 | Single incorrect password triggers 100507 | Record 25687 matched Rule 100507 in Archives and Alerts | PASS |
| AD003-R02 | Five failures for one account within 60 seconds trigger 100503 | Records 25720, 25722, 25724, 25726 matched 100507; record 25731 triggered 100503, Level 10 | PASS |
| AD003-R03A | Two failures below threshold do not trigger 100503 | Records 25770 and 25772 matched 100507; no 100503 alert in the scoped test window | PASS |

**Result: 3/3 scoped live regression tests PASS.**

## 4. Evidence and Integrity

Evidence was generated from Wazuh JSON Archives and Alerts,
transferred to the analyst host, and verified with SHA-256.

| Test | Evidence | SHA-256 |
|---|---|---|
| R01 | [R01 JSON](../../evidence/ad-003/AD003-R01-rule100507.json) | `88c9ead3d7dc38c610f59cd86d2f4842c8ef5868b38f39414cf619a2a7598d1a` |
| R02 | [R02 JSON](../../evidence/ad-003/AD003-R02-rule100503.json) | `d0452cbcb378a6d44213a99ccf501e99d59d95fabe89d532d92268feab876fcb` |
| R03A | [R03A JSON](../../evidence/ad-003/AD003-R03A-below-threshold.json) | `76b306f6731197f7eda25701d98f5f56448e78c7c98ea4357cefb94ea7f0dfc9` |

Raw Windows Security evidence is retained outside the public repository.

## 5. Historical Telemetry Gap

The original AD-003 simulation on 2026-10-11 experienced
Agent-to-Manager connection failures.

These historical events were not found in the examined
Wazuh archive.

The live regression tests on 2026-10-12 are separate
verification activities and do not establish retroactive
ingestion of October 11 events.

## 6. Limitations and Next Steps

- Cross-account correlation separation was not live-tested.
- The 60-second timeframe boundary was not live-tested.
- The negative test covers only two failures below threshold.
- No production false-positive rate was established.
- No custom rule changes were necessary for these three tests.
- Additional regression testing is required before claiming
  broader detection coverage.

## 7. Conclusion

Wazuh successfully classified individual incorrect-password
events and correlated five failures for the same account
within 60 seconds.

The scoped negative test did not produce an unexpected
correlation alert.

AD-003 live detection regression: **3/3 PASS within scope**.
