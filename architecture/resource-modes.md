# Resource Operating Modes

This lab runs on an 8 GB Parrot OS host, so not all VMs are started at the same time.

| Mode | VMs | Purpose |
|---|---|---|
| Identity Mode | SOC-DC01 + SOC-WIN10 | AD, domain join, authentication logs |
| Detection Mode | SOC-WIN10 + SOC-WAZUH | Wazuh ingestion, dashboards, detection testing |
| Attack Mode | SOC-WIN10 + SOC-WAZUH or SOC-DC01 + SOC-WIN10 | Controlled telemetry generation |
| DFIR Mode | One Windows VM + Parrot | EVTX, timeline, process and memory analysis |
| Network Security Mode | OPNsense-Lab6 + Metasploitable2 (+ optional Attacker-MSF) | Firewall, DMZ, recon, scanning, IDS exercises |

Hard rule: do not run DC01 + WIN10 + WAZUH + OPNsense at the same time. Network Security Mode is separate from the SOC rotation and must not run together with any SOC VM.

## Observed Resource Usage (2026-10-26)

| Mode | Host RAM used | Swap used | Load average | Result |
|---|---|---|---|---|
| Detection Mode (WAZUH + WIN10) | ~6.0–6.3 GiB | ~5–6.3 GiB | ~1.3–2.4 | Stable, no OOM |
| Identity Mode (WIN10 + DC01) | ~6.1 GiB | ~5.0 GiB | ~1.3 | Stable |
| Network Security Mode (OPNsense + Metasploitable) | ~5.6 GiB | ~5.0 GiB | stable | Fits; SOC VMs off |

Practical guidance:

- Close browsers, chat clients, and IDE/LLM tools before starting a two-VM mode; the host will otherwise swap heavily.
- Start the heavier VM (SOC-WAZUH) first, wait for its services, then start the endpoint.
- Shut down gracefully with `virsh shutdown` and wait for `shut off` before switching modes.
- Never start all three SOC VMs together on the 8 GB host.
