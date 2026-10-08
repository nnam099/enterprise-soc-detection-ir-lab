# SOC-INC-001 Account Containment and Recovery Exercise

## Summary

On 2026-10-07, the analyst disabled the lab domain account nam.user,
verified its disabled state on DC01, and restored its original enabled
state. Security events 4725 and 4722 corroborated the actions.

This is a separate authorized response exercise. It is not evidence
that nam.user was compromised during the process replay, which ran
under WIN10-01\localadmin.

## Scope

- Domain controller: DC01.SOC-LAB.LOCAL
- VM name: SOC-DC01
- Target account: SOC-LAB\nam.user
- Target SID: S-1-5-21-1324826322-2293316327-2538204677-1108
- Operator: SOC-LAB\Administrator
- Resource mode: SOC-WAZUH + SOC-DC01; SOC-WIN10 shut off

## Timeline

All timestamps are UTC on 2026-10-07.

| Time | Observation | Evidence |
|---|---|---|
| 04:09:22.2680406 | Baseline: Enabled=True, LockedOut=False | account-before.json |
| 04:09:22.3931098 | Disable-ADAccount requested | account-disabled.json |
| 04:09:22.4754485 | Account disable audited | Event 4725, Record ID 18248 |
| 04:09:22.5180539 | Enabled=False verified | account-disabled.json |
| 04:11:30.1586698 | Enable-ADAccount requested | account-recovered.json |
| 04:11:30.1899105 | Enabled=True, LockedOut=False verified | account-recovered.json |
| 04:11:30 (second precision) | Account enable audited | Event 4722, Record ID 18261 |

The 4722 time above is converted from the displayed local time
11:11:30 at UTC+07:00. The exported XML retains the source timestamp.

## Decision and Verification

The target SID and enabled baseline were checked before disabling
the account. The analyst verified the resulting state against the
same domain controller.

Recovery was performed to restore the enabled baseline after the
authorized exercise. No compromise was established by this exercise.
Both audit events identify Administrator as the operator and nam.user
as the target.

Account disable state verification: PASS.
Account enabled state restoration: PASS.
Local audit corroboration: PASS.

## Evidence Integrity

Original transferred artifacts are stored in evidence/account-response/.
SHA-256 values matched source values after transfer to Parrot.
SHA256SUMS.txt records the artifact hashes.

The XML files are event exports, not native EVTX files.
Git attributes preserve JSON and XML bytes without text normalization.

## Limits and Remaining Work

- Failed authentication while disabled was not tested.
- Successful post-restoration authentication was verified in separate
  October 7 and October 8 follow-up checks; see the
  [recovery report](recovery-verification.md).
- Existing sessions and tickets were not tested or revoked.
- Collection of these DC events into Wazuh was not verified.
- This exercise does not establish full endpoint recovery or eradication.

The account state exercise is complete. The overall SOC-INC-001
response lifecycle remains open pending the remaining validation,
detection improvement, and final incident report.
