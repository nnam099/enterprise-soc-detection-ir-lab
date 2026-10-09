# AD-001 — Active Directory Telemetry Baseline

## Scope

- Domain Controller: SOC-DC01 (192.168.50.10)
- SIEM: SOC-WAZUH (192.168.50.30)
- Wazuh Agent ID: 002
- Lab environment: QEMU/KVM, 8GB host
- Maximum concurrent VMs: 2

## Verified observations — 2026-10-09

### Agent connectivity
- SOC-DC01: Active in Wazuh Manager.
- Windows Security EventChannel: configured.
- Wazuh Manager recorded 739 alerts from agent 002
  in the inspected alerts.json file.
- Observed Security Event IDs in alerts:
  - 4688: 345
  - 4634: 15
  - 4624: 14

Note: these are alert counts, not raw EventChannel totals.

### Kerberos Audit Policy
- Kerberos Authentication Service: Success and Failure.
- Kerberos Service Ticket Operations: Success and Failure.

### Native Security Event counts

Window: six hours preceding the measurement on 2026-10-09.

| Event ID | Count |
|---|---:|
| 4624 | 185 |
| 4625 | 0 |
| 4768 | 7 |
| 4769 | 15 |
| 4771 | 0 |

These are native Windows Event Log counts,
not Wazuh detection counts.

## Validation boundaries

- Kerberos 4768/4769 presence on DC01 is confirmed.
- Matching alerts or raw telemetry for these Event IDs
  on Wazuh Manager have not been independently confirmed.
- No AD adversary emulation has been performed in AD-001 yet.
- No attack-detection coverage or precision is claimed.

## Planned work

1. Controlled domain enumeration.
2. Capture native Windows Security Events.
3. Correlate host events with Wazuh telemetry.
4. Build detection and benign-control test cases.
5. Document findings, evidence and recovery.
