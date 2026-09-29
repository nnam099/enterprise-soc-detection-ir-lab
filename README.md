# Enterprise SOC Detection & Incident Response Lab

Enterprise SOC lab for Windows telemetry, Wazuh detection engineering, and incident response.

## Lab Architecture

| System | Role | IP |
|---|---|---|
| SOC-DC01 | Windows Server 2022 AD DS + DNS | 192.168.50.10 |
| SOC-WIN10 | Windows 10 Endpoint | 192.168.50.20 |
| SOC-WAZUH | Wazuh SIEM | 192.168.50.30 |

## Telemetry Pipeline

The SOC-WIN10 endpoint provides Windows Security and Sysmon telemetry to Wazuh.

```text
Windows Activity
      |
      v
Windows / Sysmon Logs
      |
      v
Wazuh Agent
      |
      v
SOC-WAZUH
      |
      v
Custom Detection Rules
```

## Detection Engineering

Five custom detections were implemented and validated.

| Rule | Level | Detection | MITRE ATT&CK |
|---|---:|---|---|
| 100501 | 7 | Registry Run Key modification | T1112 / T1547.001 |
| 100502 | 8 | WinRM process execution | T1021.006 |
| 100503 | 10 | Repeated Windows failed logons | T1110 |
| 100504 | 8 | Encoded PowerShell command | T1059.001 |
| 100505 | 7 | PowerShell TCP connection to lab target | T1095* |

> *T1095 follows the Wazuh detection context used in this lab. The controlled traffic itself is not treated as proof of malicious C2 activity.

## SOC-INC-001 — Controlled Incident Investigation

The lab includes an end-to-end controlled incident simulation on SOC-WIN10.

Confirmed sequence:

```text
WinRM Remote Execution
        |
        v
Encoded PowerShell
        |
        v
Registry Run Key Modification
```

| Time (UTC) | Rule | Observation |
|---|---:|---|
| 2026-09-29 14:25:06 | 100502 | WinRM process execution |
| 2026-09-29 14:26:37 | 100504 | Encoded PowerShell execution |
| 2026-09-29 14:34:07 | 100501 | Registry Run Key modification |

- [Full incident investigation](incidents/SOC-INC-001/README.md)
- [Incident timeline](incidents/SOC-INC-001/timeline.md)
- [Analyst investigation](incidents/SOC-INC-001/analysis.md)

## Incident Evidence

### Alert Timeline

![SOC-INC-001 alert timeline](screenshots/phase4-incident/60-soc-inc-001-alert-timeline.png)

### Encoded PowerShell

![Encoded PowerShell evidence](screenshots/phase4-incident/61-soc-inc-001-encoded-powershell-detail.png)

### Registry Run Key Modification

![Registry persistence evidence](screenshots/phase4-incident/62-soc-inc-001-registry-persistence-detail.png)

## Detection Engineering Finding

During SOC-INC-001, network activity toward 192.168.50.30:55000 was attempted, but the expected Sysmon Event ID 3 was not observed for the incident PowerShell process.

Therefore rule 100505 was not included in the confirmed incident timeline.

Earlier 100505 positive and negative validation remains independent detection evidence.

```text
Activity Generation != Telemetry Generation != Alert Generation
```

This distinction prevents unrelated validation events from being presented as part of the incident.

## Repository Structure

```text
architecture/            Network and resource design
evidence/                Host baseline evidence
incidents/SOC-INC-001/   Incident investigation
screenshots/phase1-*     Active Directory evidence
screenshots/phase2-wazuh Wazuh and Sysmon evidence
screenshots/phase3-*     Detection validation
screenshots/phase4-*     Incident evidence
```

## Project Status

- [x] KVM/QEMU SOC network
- [x] Windows Server 2022 AD DS and DNS
- [x] Windows 10 domain endpoint
- [x] Windows auditing and Sysmon
- [x] Wazuh SIEM and endpoint agent
- [x] Windows/Sysmon log ingestion
- [x] Five custom detection rules
- [x] Positive/negative detection validation
- [x] Controlled incident simulation
- [x] Alert triage and event correlation
- [x] Incident investigation documentation

## Disclaimer

All activity documented in this repository was performed in an isolated lab environment for defensive security education, detection engineering, and incident response practice.
