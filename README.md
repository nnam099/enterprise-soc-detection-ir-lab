# Enterprise SOC Detection & Incident Response Lab

Resource-optimized SOC lab built on an 8 GB Parrot OS host using KVM/QEMU, Windows Active Directory, Sysmon, Wazuh, detection engineering, threat hunting, and DFIR workflows.

## Goal

This project demonstrates the full SOC workflow:

event -> detection -> triage -> investigation -> hunting -> DFIR -> response -> detection improvement.

## Core Network

- Network: soc-net
- CIDR: 192.168.50.0/24
- Gateway: 192.168.50.1

## Planned Core VMs

| VM | Role | IP |
|---|---|---:|
| SOC-DC01 | Windows Server 2022 AD DS + DNS | 192.168.50.10 |
| SOC-WIN10 | Windows 10 endpoint | 192.168.50.20 |
| SOC-WAZUH | Wazuh SIEM single-node | 192.168.50.30 |

## Operating Modes

| Mode | VMs | Purpose |
|---|---|---|
| Identity Mode | SOC-DC01 + SOC-WIN10 | AD, domain join, authentication logs |
| Detection Mode | SOC-WIN10 + SOC-WAZUH | Wazuh ingestion, dashboards, detection testing |
| Attack Mode | SOC-WIN10 + SOC-WAZUH or SOC-DC01 + SOC-WIN10 | Controlled telemetry generation |
| DFIR Mode | One Windows VM + Parrot | EVTX, timeline, process and memory analysis |

## Constraint

The lab is designed for an 8 GB host. VMs are started by operating mode, not all at once.

Hard rule: do not run SOC-DC01 + SOC-WIN10 + SOC-WAZUH + OPNsense at the same time.
