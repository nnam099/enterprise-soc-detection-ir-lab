# Enterprise SOC Detection & Incident Response Lab

A controlled Windows security lab demonstrating telemetry collection,
Wazuh detection engineering, threat hunting, investigation, and verified
response exercises on an 8 GB Parrot OS host.

All documented activity is authorized lab activity. Independent tests
and response exercises retain separate timelines and evidence.

## Start Here

- [Investigation and response capstone](incidents/SOC-INC-001/capstone-report.md)
- [Original incident investigation](incidents/SOC-INC-001/analysis.md)
- [Verified process containment replay](incidents/SOC-INC-001/response-replay.md)
- [AD account containment and restoration](incidents/SOC-INC-001/account-response.md)
- [Encoded PowerShell live detection validation](detections/wazuh/tests/encoded-powershell/README.md)

- [Run Key verification and sampled monitoring](incidents/SOC-INC-001/recovery-verification.md)
- [WebView2 triage and before/after tuning](incidents/INC-002-wazuh-fp-tuning/triage-report.md)

## Verified Outcomes

| Work item | Result | Scope |
|---|---|---|
| Original incident simulation | Three correlated detections documented | WinRM, encoded PowerShell, Registry Run Key modification |
| Process response replay | Target process absent after Stop-Process | Separate local-account exercise |
| AD account response | Disabled state and restored enabled state verified | Security events 4725 and 4722 corroborated actions |
| Encoded PowerShell validation | Four live tests passed their defined expectations | Three positive tests and one encoded negative control |
| Evidence preservation | Source hashes matched for transferred Windows response and execution records | Git index hashes also checked |

Run Key checks confirmed the SOC-INC-001 value was absent under the
original user SID. Eleven follow-up samples spanning 313.75 seconds
recorded absence and Running Sysmon/Wazuh services. Agent 001 was
reported Active in a subsequent manager check.

INC-002 tuning replaced a broad text match with specific creator-image
and target-file predicates. A PowerShell-created filename containing
msedgewebview2.exe retained level 15 after tuning, compared with level 3
before tuning. An adapted historical replay selected rule 100001 at level 3.
The test temporarily adapted base rule 60000 for JSON decoding and
restored it afterward. The intended WebView2 level 3 branch remains
unverified through matching live telemetry.

Process termination telemetry from Sysmon Event 5 remains unverified.
A separate post-restoration check verified successful domain authentication
and creation of a PowerShell process under the target SID.
An October 8 follow-up verified an observed desktop session under the
target SID, successful DC Kerberos authentication, and profile file
creation/readback. Existing session revocation and recovery of all
applications remain unverified.

## Lab Architecture

| VM / agent name | Observed Windows hostname | Role | IP |
|---|---|---|---|
| SOC-DC01 | DC01 | Windows Server 2022 AD DS and DNS | 192.168.50.10 |
| SOC-WIN10 | WIN10-01 | Windows endpoint with auditing and Sysmon | 192.168.50.20 |
| SOC-WAZUH | — | Wazuh manager, indexer, and dashboard | 192.168.50.30 |

The host uses KVM/QEMU through qemu:///system.
Resource limits require switching between operating modes rather than
running every VM concurrently.

- [Topology](architecture/topology.md)
- [IP plan](architecture/ip-plan.md)
- [Resource operating modes](architecture/resource-modes.md)

## Telemetry and Detection Engineering

Windows Security and Sysmon events from SOC-WIN10 are collected by the
Wazuh agent and analyzed on SOC-WAZUH.

| Rule | Level | Detection | ATT&CK mapping |
|---|---:|---|---|
| 100501 | 7 | Registry Run Key modification | T1112 / T1547.001 |
| 100502 | 8 | WinRM process execution | T1021.006 |
| 100503 | 10 | Repeated Windows failed logons | T1110 |
| 100504 | 8 | Encoded PowerShell command | T1059.001 |
| 100505 | 7 | PowerShell connection to the lab target | T1095, lab detection context |

The controlled network traffic is not treated as proof of malicious C2.

[Custom rules](configs/wazuh/rules/local_rules.xml) are maintained in Git.
Rule 100504 was synchronized with the live-validated manager configuration.
This synchronization was not a newly deployed manager tuning change.

### Encoded PowerShell Live Baseline

| Test | Behavior | Observed rule / level |
|---|---|---|
| T01 | PowerShell parent, -EncodedCommand | 92057 / 12 |
| T02 | CMD parent, -EncodedCommand | 100504 / 8 |
| T03 | CMD parent, -enc | 100504 / 8 |
| T04 | PowerShell parent, ordinary -Command | 92027 / 4 |

Neither encoded detection was observed for T04's matching process event
within the documented collection scope.

## Original Incident and Separate Response Exercises

The original simulation on 2026-09-29 documented WinRM execution,
encoded PowerShell, and a Registry Run Key modification under
SOC-LAB\nam.user.

An attempted network connection was excluded from the confirmed incident
timeline because corresponding Sysmon Event 3 evidence was not observed.

The process and account response exercises on 2026-10-07 are documented
separately. They must not be presented as response actions performed
during the original September simulation.

- [Incident overview](incidents/SOC-INC-001/README.md)
- [Original timeline](incidents/SOC-INC-001/timeline.md)
- [Response evidence boundaries and remaining work](incidents/SOC-INC-001/capstone-report.md)

## Threat Hunting, DFIR, and Anomaly Detection

- [Threat hunting investigations](hunting/README.md)
- [ATT&CK coverage matrix](hunting/MITRE-COVERAGE.md)
- [DFIR-001 investigation](dfir/cases/DFIR-001/investigation-report.md)
- [DFIR evidence manifest](dfir/cases/DFIR-001/evidence-manifest.md)
- [Anomaly detection pipeline](ai/README.md)

DFIR-001 has a completed controlled evidence review and a verified
timeline rebuild within its documented scope.
Isolation Forest v3 scoring was reproduced with exactly matching parsed
results. It flagged 2 of 69 benign validation events and did not flag
the single controlled encoded PowerShell test event.
These results do not establish operational detection effectiveness.

## Current Status and Remaining Work

Completed evidence includes telemetry ingestion, custom detection
validation, a controlled investigation, process containment verification,
and AD account disable and restoration.

Remaining priorities:

- Verify the intended WebView2 severity-reduction branch through live
  telemetry; its adapted historical replay has passed.
- Assess remaining application recovery requirements; scoped desktop
  and profile file recovery checks passed on October 8.
- Extend monitoring if the exercise scope is expanded; the existing
  sampled window is accepted for scoped lab closure.
- Expand anomaly detection evaluation beyond the single encoded test event.

SOC-INC-001 is closed as an educational exercise within its verified
scope, with accepted limitations recorded in the
[closure assessment](incidents/SOC-INC-001/closure-assessment.md).

Historical Run Key deletion time and actor remain unverified.
The sampled checks do not establish continuous absence or a fully clean endpoint.

## Lab Use

This repository documents an isolated lab for defensive security
education, detection engineering, and incident response practice.
A detection match demonstrates observed behavior, not malicious intent.

- [Lab completion and closure assessment](incidents/SOC-INC-001/closure-assessment.md)
