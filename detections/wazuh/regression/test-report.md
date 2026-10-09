# Archived Detection Evidence Verification — Report v1

## Assessment

- Lab: Enterprise SOC Detection & Incident Response Lab
- Scope: Archived evidence verification
- Detection focus: Encoded PowerShell
- Endpoint: SOC-WIN10
- Test IDs: T01, T02, T03, T04
- Verification result: 4/4 PASS

## Evidence Integrity

The existing SHA-256 manifest covers 14 archived artifacts.

- Verified: 14/14
- Hash mismatches: 0
- SHA-256 check exit code: 0

## Automated Verification

Command:

    python3 -B detections/wazuh/regression/verify_archived_evidence.py

Recorded results:

    T01: PASS
    T02: PASS
    T03: PASS
    T04: PASS

    ARCHIVED EVIDENCE REGRESSION: 4/4 PASS

Runner exit code: 0.

## Verification Method

The runner compares selected archived Wazuh alerts and archives
with their original execution records.

Correlation fields:

- Agent ID
- Sysmon Event ID
- Process ID
- Unique test marker
- Expected Rule ID
- Expected alert level

JSON files are read using UTF-8 BOM-compatible decoding.
Encoded PowerShell markers are decoded from Base64 UTF-16LE.

## Limitations

- The current Wazuh Manager ruleset was not re-executed.
- No new endpoint telemetry was generated.
- Results do not establish general detection accuracy.
- The four tests do not represent all PowerShell activity.
- A historical PASS does not prove a modified rule will PASS.
- Full regression coverage for rules 100001 and 100501–100505
  remains incomplete.

## Next Steps

1. Verify archived fixtures before every evidence regression run.
2. Build valid Wazuh rule-level test fixtures.
3. Validate threshold and grouping behavior for rule 100503.
4. Verify the parent-rule conditions for rule 100505.
5. Document actual rule-level regression results separately.
