# DFIR-001 Timeline

Normalized investigation timeline generated from SOC-LAB threat hunting evidence.

> Important: independent controlled validation events are not treated as one confirmed attack chain.

Total records: **10**

## Timeline

| Wazuh timestamp | Hunt | Source | Category | Rule | Event | User | Summary |
|---|---|---|---|---|---|---|---|
| 2026-09-30T00:50:18.094+0000 | HUNT-001 | wazuh_alert | powershell_execution | 92027 | 1 | WIN10-01\\localadmin | PowerShell execution by WIN10-01\\localadmin |
| 2026-09-30T01:00:14.724+0000 | HUNT-001 | wazuh_alert | powershell_execution | 92057 | 1 | WIN10-01\\localadmin | PowerShell execution by WIN10-01\\localadmin |
| 2026-09-30T01:01:29.684+0000 | HUNT-001 | wazuh_alert | powershell_execution | 100504 | 1 | WIN10-01\\localadmin | PowerShell execution by WIN10-01\\localadmin |
| 2026-09-30T01:50:37.815+0000 | HUNT-002 | wazuh_alert | authentication_success | 67022 | 4624 | nam.user | Successful authentication for nam.user |
| 2026-09-30T01:55:22.101+0000 | HUNT-002 | wazuh_alert | authentication_failure | 60122 | 4625 | hunt002-test | Failed authentication for hunt002-test from 127.0.0.1 |
| 2026-09-30T01:55:25.592+0000 | HUNT-002 | wazuh_alert | authentication_failure | 100503 | 4625 | hunt002-test | Failed authentication for hunt002-test from 127.0.0.1 |
| 2026-09-30T04:27:00.449+0000 | HUNT-003 | wazuh_alert | winrm_remote_execution | 100502 | 1 | SOC-LAB\\nam.user | WinRM child process execution: cmd.exe <- wsmprovhost.exe as SOC-LAB\\nam.user |
| 2026-09-30T04:27:00.449+0000 | HUNT-003 | wazuh_alert | winrm_remote_execution | 100502 | 1 | SOC-LAB\\nam.user | WinRM child process execution: cmd.exe <- wsmprovhost.exe as SOC-LAB\\nam.user |
| 2026-09-30T04:53:24.407+0000 | HUNT-004 | wazuh_alert | registry_persistence | 100501 | 13 | SOC-LAB\\nam.user | Registry Run Key modification by SOC-LAB\\nam.user: HKU\\S-1-5-21-1324826322-2293316327-2538204677-1108\\SOFTWARE\\Mi... |
| 2026-09-30T04:53:24.407+0000 | HUNT-004 | wazuh_alert | registry_persistence | 100501 | 13 | SOC-LAB\\nam.user | Registry Run Key modification by SOC-LAB\\nam.user: HKU\\S-1-5-21-1324826322-2293316327-2538204677-1108\\SOFTWARE\\Mi... |

## Interpretation Notes

- `raw_telemetry` represents endpoint/security telemetry evidence.
- `wazuh_alert` identifies stored records containing Wazuh rule metadata; it does not establish whether the export came from alerts.json or archives.json.
- Multiple stored exports may describe the same underlying event. A matching timestamp alone does not establish independent evidence or a distinct activity.
- Timeline order alone does not prove causal relationship between independent lab tests.

## Case Status

DFIR-001 remains a controlled investigation case.

No real compromise is asserted by this timeline.
