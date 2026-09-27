# Resource Operating Modes

This lab runs on an 8 GB Parrot OS host, so not all VMs are started at the same time.

| Mode | VMs | Purpose |
|---|---|---|
| Identity Mode | SOC-DC01 + SOC-WIN10 | AD, domain join, authentication logs |
| Detection Mode | SOC-WIN10 + SOC-WAZUH | Wazuh ingestion, dashboards, detection testing |
| Attack Mode | SOC-WIN10 + SOC-WAZUH or SOC-DC01 + SOC-WIN10 | Controlled telemetry generation |
| DFIR Mode | One Windows VM + Parrot | EVTX, timeline, process and memory analysis |

Hard rule: do not run DC01 + WIN10 + WAZUH + OPNsense at the same time.
