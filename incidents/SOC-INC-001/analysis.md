# SOC-INC-001 — SOC Analyst Investigation

## 1. Incident Overview

SOC-INC-001 is a controlled incident simulation performed against the
SOC-WIN10 endpoint in the SOC-LAB.LOCAL domain.

The objective was to validate an end-to-end SOC workflow:

    Endpoint Activity
          |
          v
    Windows / Sysmon Telemetry
          |
          v
    Wazuh Agent
          |
          v
    Wazuh Detection Rules
          |
          v
    Alert Triage
          |
          v
    Event Correlation
          |
          v
    Incident Analysis

The activity was intentionally generated in the lab and does not represent
an actual compromise.

## 2. Initial Triage

Three custom Wazuh alerts were correlated during the incident window.

| Rule | Level | Detection |
|---|---:|---|
| 100502 | 8 | Process spawned through Windows Remote Management |
| 100504 | 8 | Encoded PowerShell execution |
| 100501 | 7 | Registry Run Key modification |

All three events were observed on:

    Endpoint: SOC-WIN10
    Account:  SOC-LAB\nam.user

The alerts occurred between:

    2026-09-29 14:25:06 UTC
    2026-09-29 14:34:07 UTC

The common endpoint, account, time window, process context, and explicit lab
markers provided sufficient evidence to correlate the events as one
controlled simulation.

## 3. Event Analysis

### 3.1 WinRM Remote Execution

At 2026-09-29 14:25:06 UTC, Wazuh rule 100502 detected Sysmon Event ID 1.

Observed process:

    C:\Windows\System32\cmd.exe

Observed parent process:

    C:\Windows\System32\wsmprovhost.exe

Observed user:

    SOC-LAB\nam.user

Command:

    cmd.exe /c "echo SOC-INC-001-WINRM && whoami && hostname"

The wsmprovhost.exe parent process provides evidence that the command was
executed through a Windows Remote Management process context.

MITRE ATT&CK mapping:

    T1021.006 — Windows Remote Management

### 3.2 Encoded PowerShell Execution

At 2026-09-29 14:26:37 UTC, Wazuh rule 100504 detected another Sysmon
Event ID 1.

Observed image:

    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Observed parent:

    C:\Windows\System32\wsmprovhost.exe

Observed user:

    SOC-LAB\nam.user

The command line contained:

    -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMATwBDAC0ASQBOAEMALQAwADAAMQAtAEUATgBDAE8ARABFAEQALQBQAFMAJwA=

The Base64 data decodes from UTF-16LE to:

    Write-Output 'SOC-INC-001-ENCODED-PS'

MITRE ATT&CK mapping:

    T1059.001 — PowerShell

Because the decoded command contains the SOC-INC-001 marker and performs only
a Write-Output operation, the payload is confirmed as controlled simulation
activity.

### 3.3 Registry Run Key Modification

At 2026-09-29 14:34:07 UTC, rule 100501 detected Sysmon Event ID 13.

Observed process:

    C:\Windows\system32\reg.exe

Observed user:

    SOC-LAB\nam.user

Observed target:

    HKU\<USER-SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SOC-INC-001

Observed value:

    C:\Windows\System32\cmd.exe /c echo SOC-INC-001

MITRE ATT&CK mappings:

    T1112    — Modify Registry
    T1547.001 — Registry Run Keys / Startup Folder

The event demonstrates modification of a Windows Run Key, which can be used
as a persistence mechanism.

In this incident the value was deliberately created for the lab simulation
and was removed during cleanup.

## 4. Correlation

The observed process and event sequence was:

    WinRM
      |
      v
    wsmprovhost.exe
      |
      +------> cmd.exe
      |          Rule 100502
      |
      +------> powershell.exe
                 Rule 100504

    Later:

    reg.exe
      |
      v
    HKCU\...\CurrentVersion\Run\SOC-INC-001
      |
      v
    Rule 100501

Correlation factors:

- same endpoint: SOC-WIN10;
- same domain account: SOC-LAB\nam.user;
- events occurred within approximately nine minutes;
- WinRM-related process context was observed for the execution events;
- explicit SOC-INC-001 markers were present in generated test activity.

These factors support treating the three observed alerts as related events
within this controlled simulation.

## 5. Network Telemetry Investigation

A PowerShell/.NET TCP connection attempt to:

    192.168.50.30:55000

was performed during the incident simulation.

The expected detection path was:

    PowerShell
        |
        v
    TCP connection
        |
        v
    Sysmon Event ID 3
        |
        v
    Wazuh rule 92101
        |
        v
    Custom rule 100505

However, investigation of both:

    Microsoft-Windows-Sysmon/Operational

and:

    /var/ossec/logs/archives/archives.json

did not identify a corresponding Sysmon Event ID 3 attributed to the
incident PowerShell process.

Therefore rule 100505 did not generate an alert for SOC-INC-001.

This event is not included as confirmed network telemetry in the incident
timeline.

Rule 100505 had already been independently validated using separate positive
and negative test cases. Those validation events are maintained separately
from SOC-INC-001 evidence.

## 6. Analyst Assessment

Observed evidence confirms the following activity during the controlled
simulation:

1. remote command execution through a WinRM process context;
2. encoded PowerShell execution;
3. modification of a Registry Run Key.

The combination of these behaviors would warrant investigation in a
production SOC because similar telemetry can occur during unauthorized
remote execution and persistence activity.

For SOC-INC-001, the activity is classified as:

    Controlled Lab Simulation

No claim of a real endpoint compromise is made.

## 7. Recommended Response in a Production Environment

If equivalent activity were unexpected on a production endpoint, an analyst
could consider the following response actions.

### Containment

- Isolate the affected endpoint if the activity is confirmed unauthorized.
- Restrict or disable unauthorized WinRM access.
- Review active remote sessions.
- Temporarily restrict the affected account if compromise is suspected.

### Investigation

- Review Sysmon process creation events.
- Review Windows authentication events.
- Identify the source of the WinRM session.
- Decode and inspect encoded PowerShell commands.
- Review PowerShell operational logs where available.
- Inspect Registry Run and RunOnce locations.
- Review network telemetry associated with suspicious processes.
- Search other endpoints for the same indicators and behaviors.

### Eradication

- Remove unauthorized persistence mechanisms.
- Remove confirmed malicious files or scripts.
- Revoke compromised credentials where supported by the investigation.
- Correct unauthorized WinRM configuration or access paths.

### Recovery

- Restore required endpoint services.
- Re-enable legitimate access after remediation.
- Continue monitoring for recurrence.
- Validate that persistence mechanisms do not reappear.

## 8. Detection Engineering Findings

The simulation validated detection coverage for:

    100502 — WinRM process execution
    100504 — Encoded PowerShell
    100501 — Registry Run Key modification

The investigation also identified a telemetry visibility gap during the
network-connection portion of the simulation.

This demonstrates an important distinction between:

    activity generation
    telemetry generation
    telemetry collection
    detection logic
    alert generation

A detection rule cannot generate an alert when the required source telemetry
is not produced or collected.

## 9. Evidence Integrity

Only events actually observed in Sysmon and Wazuh are treated as confirmed
incident evidence.

Previously generated validation alerts from other users, processes, or test
windows are not merged into SOC-INC-001.

This preserves the distinction between:

    detection-rule validation evidence

and:

    incident-correlation evidence

SOC-INC-001 therefore represents a reproducible and evidence-based SOC
investigation workflow rather than a reconstructed or artificially combined
attack timeline.
