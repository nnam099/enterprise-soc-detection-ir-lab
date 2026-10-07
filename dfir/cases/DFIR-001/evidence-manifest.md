# DFIR-001 Evidence Manifest

## Scope

Four independent controlled hunting exercises.
Findings documented; timeline rebuild matched the existing manifest
on 2026-10-07 in the current environment.
No real compromise or unified attack chain is asserted.

## Sources

| Hunt | Files | Content |
|---|---:|---|
| HUNT-001 | 3 | PowerShell exports, including one curated event record |
| HUNT-002 | 3 | Authentication records with Wazuh metadata |
| HUNT-003 | 2 | WinRM-related process exports |
| HUNT-004 | 2 | Registry Run Key modification exports |

Sources reside in hunting/evidence/ relative to the repository root.
Filenames alone do not establish acquisition provenance.
Ten timeline records are not necessarily ten distinct activities.

## Derived Artifacts

- dfir/timelines/DFIR-001-timeline.jsonl
- dfir/timelines/DFIR-001-timeline.csv
- dfir/timelines/DFIR-001-timeline.md

## Integrity and Verification

dfir/evidence/DFIR-001/SHA256SUMS.txt covers 10 sources and three
derived timelines using repository-relative paths.

Sources matched the baseline saved before the current pipeline changes.
Original acquisition-time hashes and complete chain of custody are
not established.

The verifier checks artifact presence, hashes, JSONL structure,
source types, JSON Schema, and hashed source references.

Reproducibility requires rebuilding and exporting the timeline,
then checking the existing manifest without regenerating it.
