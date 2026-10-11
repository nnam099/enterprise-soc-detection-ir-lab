# INC-003 — Evidence Manifest

## Evidence Handling

Case: INC-003 — Controlled PowerShell Incident Response

Collection date: 2026-10-11

Sources:
- SOC-WIN10: Sysmon and PowerShell transcripts
- SOC-WAZUH: Wazuh alerts and event archives

Integrity method: SHA-256 verification before and
after transfer to the Parrot analyst host.

Original evidence is retained outside this Git
repository. The paths below are relative to the
private INC-003 evidence collection directory.

## Evidence Inventory

| Evidence File | Purpose | SHA-256 |
|---|---|---|
| `wazuh/INC-003-alert-20704.jsonl` | Baseline encoded PowerShell detection | `338b3629fcd2223cfa89d0c9d25b67d14340105e9eff8834536c470f5d7985f7` |
| `wazuh/INC-003-alert-20779.jsonl` | Live incident detection, Rule 92057 | `8d92284913ee1eda6f5c6e0944b3ac0f9d3bf8fcb17f14fc369109aef525a42a` |
| `wazuh/INC-003-regression-POS02-20782.jsonl` | Positive regression, Rule 100504 | `fe6650678d4a052b198e41a67aa9b7d34c02581d515f38496b919e302e314564` |
| `wazuh/INC-003-NEG01-20785-alerts.jsonl` | Negative regression alert, Rule 92032 | `e2252a2cc5688e3b3fd1e250dd683d148fa06740696b81cb7ebd232df5653483` |
| `wazuh/INC-003-NEG01-20785-archives.jsonl` | Negative regression raw event ingestion | `4862bda0f0002f165d5520e0a89e4d0f44e48d0f36480c3df989ae14a6a7c3cf` |
| `windows/INC-003-containment-4512.txt` | Targeted process containment and verification | `f48809f9d10c8bda48c533bac729127538f49d966e85db3b68134d541cc78120` |
| `windows/INC-003-recovery.txt` | Post-containment endpoint checks | `8e77e26bd98edbebd4f4d1fb8298be4dd366f78938928fa12b57f6a826e8c2e0` |

## Correlation Reference

| Test | Sysmon Record ID | Detection |
|---|---|---|
| Baseline | 20704 | Rule 92057 |
| Live containment scenario | 20779 | Rule 92057 |
| POS-02 | 20782 | Rule 100504 |
| NEG-01 | 20785 | Rule 92032 |

For the live containment scenario:
- Target PID: 4512
- Sysmon Event ID: 1
- Containment result: CONTAINMENT_VERIFIED
- Post-containment result: TARGET_PID_ABSENT

## Evidence Limitations

- This was an authorized benign simulation.
- No corresponding Sysmon Event ID 5 was found.
- NEG-01 produced Rule 92032, but not the two
  encoded PowerShell rules under regression.
- The manifest verifies file integrity, not
  independent forensic attribution.
- Raw evidence is not published in this repository.

## Chain of Custody

The Wazuh evidence was collected from the SIEM and
transferred to Parrot via SCP using a SHA-256 verified
transfer package.

The Windows transcripts were transferred to Parrot
via SCP, and both destination hashes were verified
against their source hashes.

Original files have been retained without
intentional modification after hash verification.
