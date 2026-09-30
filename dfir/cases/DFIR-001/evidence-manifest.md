# DFIR-001 Evidence Manifest

Case: DFIR-001
Environment: SOC-LAB
Target: SOC-WIN10 / WIN10-01
Status: Open

## Planned Evidence

- Windows Security Event 4624
- Windows Security Event 4625
- Sysmon Event ID 1
- Sysmon Event ID 13
- Wazuh alerts 100501-100504
- WinRM process ancestry
- Registry Run Key activity

## Goal

Reconstruct a defensible timeline from endpoint and SIEM telemetry without assuming independent validation events belong to one real attack chain.

## Collected Evidence

- dfir/timelines/DFIR-001-timeline.jsonl
- dfir/timelines/DFIR-001-timeline.csv
- dfir/timelines/DFIR-001-timeline.md
- dfir/evidence/DFIR-001/SHA256SUMS.txt
- dfir/cases/DFIR-001/investigation-report.md

## Validation

- dfir/scripts/build_timeline.py
- dfir/scripts/export_timeline.py
- dfir/scripts/verify_case.py
- dfir/schemas/timeline-schema.json
