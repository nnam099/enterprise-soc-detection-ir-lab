# HUNT-003 — Windows Remote Management Process Execution

## 1. Hunt Information

- **Hunt ID:** HUNT-003
- **Title:** Windows Remote Management Process Execution
- **Environment:** SOC-LAB
- **Target Endpoint:** SOC-WIN10 / WIN10-01
- **Target IP:** 192.168.50.20
- **SIEM:** Wazuh
- **Endpoint Telemetry:** Sysmon
- **Primary Event:** Sysmon Event ID 1 — Process Create
- **Detection Rule:** SOC-LAB Rule 100502
- **MITRE ATT&CK:** T1021.006 — Windows Remote Management
- **Hunt Status:** Completed

---

## 2. Hypothesis

Windows Remote Management (WinRM) can be used by administrators for
legitimate remote management but may also be used for remote execution
and lateral movement.

Processes executed through a WinRM session can be identified by analyzing
process ancestry.

On the target Windows endpoint, commands executed through WinRM may be
spawned by:

```text
wsmprovhost.exe
```

Therefore, the primary hunt hypothesis is:

> A process whose parent process is `wsmprovhost.exe` may represent
> command execution through Windows Remote Management and should be
> investigated in context.

The objective of this hunt is not to classify every WinRM process as
malicious.

The objective is to determine whether SOC-LAB telemetry can reliably
identify process execution associated with WinRM and whether Wazuh can
generate an appropriate detection alert.

---

## 3. Scope

The hunt focuses on the following environment:

| Component | Value |
|---|---|
| Domain | SOC-LAB.LOCAL |
| Endpoint | WIN10-01 |
| Wazuh Agent | SOC-WIN10 |
| Endpoint IP | 192.168.50.20 |
| WinRM Transport | HTTP |
| WinRM Port | TCP/5985 |
| Detection Platform | Wazuh |
| Endpoint Telemetry | Sysmon |
| Primary Event | Sysmon Event ID 1 |
| Test User | `SOC-LAB\nam.user` |

All activity described in this report was intentionally generated inside
the controlled SOC-LAB environment for detection engineering and threat
hunting validation.

---

## 4. MITRE ATT&CK Mapping

The activity is mapped to:

- **Technique:** T1021.006
- **Technique Name:** Windows Remote Management
- **Tactic:** Lateral Movement

The mapping is based on the remote management execution context observed
during the controlled WinRM test.

The ATT&CK mapping does not by itself indicate that compromise occurred.

---

## 5. Data Sources

The hunt used the following telemetry:

### 5.1 Sysmon Event ID 1

Sysmon Event ID 1 provides process creation telemetry.

Relevant fields include:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `User`
- `Computer`
- `ProcessId`
- `ParentProcessId`
- `UtcTime`

For this hunt, the most important field is:

```text
ParentImage
```

Specifically:

```text
C:\Windows\System32\wsmprovhost.exe
```

---

### 5.2 Wazuh

Wazuh receives Sysmon telemetry from the Windows endpoint and evaluates
the event against detection rules.

The custom detection used in this hunt is:

```text
Rule ID: 100502
Level: 8
MITRE: T1021.006
```

---

## 6. WinRM Validation

Before testing the detection rule, WinRM availability on WIN10-01 was
verified.

The Windows Remote Management service was running:

```powershell
Get-Service WinRM
```

Observed state:

```text
Status : Running
Name   : WinRM
```

The WinRM listener was also verified:

```powershell
winrm enumerate winrm/config/listener
```

The endpoint was listening on:

```text
TCP/5985
```

and included:

```text
192.168.50.20
```

as a listening address.

From the Parrot host, TCP connectivity was validated with:

```bash
nc -vz 192.168.50.20 5985
```

The connection to TCP port 5985 succeeded.

This confirmed that the WinRM service was reachable from the lab network.

---

## 7. Remote Management Authorization

The domain account used for the controlled validation was:

```text
SOC-LAB\nam.user
```

The account was confirmed as a member of:

```text
Remote Management Users
```

on WIN10-01.

The PowerShell session configuration also permitted members of the
Remote Management Users group.

On the Domain Controller, the account was verified as:

```text
SamAccountName : nam.user
Enabled        : True
LockedOut      : False
PasswordExpired: False
```

This established that the account was available for the controlled WinRM
validation.

---

## 8. Initial Detection Design

The original SOC-LAB WinRM rule was designed as a child of Wazuh rule
92052.

Conceptually, the original rule operated as:

```text
Sysmon Event ID 1
        |
        v
Wazuh Rule 92052
        |
        v
SOC-LAB Rule 100502
```

Rule 100502 additionally checked whether:

```text
ParentImage = wsmprovhost.exe
```

The intended objective was to identify processes launched through WinRM.

---

## 9. Detection Gap Identified

During validation, an important detection engineering issue was
identified.

Wazuh rule 92052 was inspected directly from:

```text
/var/ossec/ruleset/rules/0800-sysmon_id_1.xml
```

The relevant rule logic showed:

```xml
<rule id="92052" level="4">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName"
         type="pcre2">(?i)cmd\.EXE</field>
  <field name="win.eventdata.parentImage"
         type="pcre2"
         negate="yes">(?i)(explorer|cmd)\.EXE</field>
  <description>
    Windows command prompt started by an abnormal process
  </description>
</rule>
```

This revealed that rule 92052 was specifically designed around execution
of `cmd.exe`.

Therefore, using rule 92052 as the parent of the WinRM detection
introduced an unnecessary dependency.

---

## 10. Why the Original Rule Was Incomplete

A WinRM session does not necessarily spawn only `cmd.exe`.

For example, process telemetry observed during validation included:

```text
wsmprovhost.exe
    |
    +-- cmd.exe
```

and:

```text
wsmprovhost.exe
    |
    +-- powershell.exe
```

The PowerShell execution was visible in Sysmon telemetry with:

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

ParentImage:
C:\Windows\System32\wsmprovhost.exe
```

However, a detection chain dependent on rule 92052 was not a general
WinRM process execution detector because rule 92052 specifically required
the original file name associated with `cmd.exe`.

This produced a detection coverage gap.

---

## 11. Detection Engineering Improvement

The custom rule was modified to detect WinRM process ancestry directly
from the Sysmon Event ID 1 group.

The updated rule is:

```xml
<!--
  SOC-LAB WinRM Remote Process Detection
  Source: Sysmon Event ID 1 - Process Create
  MITRE ATT&CK: T1021.006 - Windows Remote Management
-->
<rule id="100502" level="8">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage"
         type="pcre2">(?i)wsmprovhost\.exe$</field>
  <description>
    SOC Lab: Process spawned via Windows Remote Management (WinRM) -
    $(win.eventdata.image) by $(win.eventdata.user)
  </description>
  <mitre>
    <id>T1021.006</id>
  </mitre>
</rule>
```

The important change was:

```text
OLD:
if_sid = 92052

NEW:
if_group = sysmon_event1
```

The detection now evaluates Sysmon process creation events directly.

---

## 12. Improved Detection Logic

The improved detection pipeline is:

```text
Sysmon Event ID 1
        |
        v
Process Creation
        |
        v
ParentImage
        |
        +---- wsmprovhost.exe ?
                    |
                   YES
                    |
                    v
             Wazuh Rule 100502
                    |
                    v
              Alert Level 8
                    |
                    v
          MITRE ATT&CK T1021.006
```

This approach detects the relevant process ancestry without requiring the
child process to be specifically `cmd.exe`.

---

## 13. Rule Validation

After modifying the rule, configuration validation was performed.

The Wazuh rule XML was checked using:

```bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml
```

The Wazuh analysis engine configuration was tested using:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

The Wazuh manager was then restarted:

```bash
sudo systemctl restart wazuh-manager
```

Service status confirmed:

```text
Active: active (running)
```

This established that the modified detection rule was syntactically valid
and successfully loaded by Wazuh.

---

## 14. Controlled WinRM Execution

A controlled WinRM command execution was generated against WIN10-01.

The validation command produced a marker:

```text
HUNT003-RULE100502-VALIDATION
```

and executed:

```text
whoami
```

The marker was intentionally included so the resulting telemetry could be
located reliably in the Wazuh archive and alert logs.

---

## 15. Raw Sysmon Evidence

Sysmon captured the controlled process creation event at:

```text
2026-09-30T04:27:00.449+0000
```

Relevant fields were:

```text
Event ID:
1

Computer:
WIN10-01.SOC-LAB.LOCAL

Image:
C:\Windows\System32\cmd.exe

CommandLine:
"C:\Windows\system32\cmd.exe" /c
"echo HUNT003-RULE100502-VALIDATION && whoami"

ParentImage:
C:\Windows\System32\wsmprovhost.exe

ParentCommandLine:
C:\Windows\system32\wsmprovhost.exe -Embedding

User:
SOC-LAB\nam.user
```

The process relationship was therefore:

```text
wsmprovhost.exe
        |
        v
     cmd.exe
        |
        v
    whoami.exe
```

The presence of `wsmprovhost.exe` as the direct parent of `cmd.exe`
provided the process ancestry required by rule 100502.

---

## 16. Wazuh Detection Evidence

The same event generated a Wazuh alert at:

```text
2026-09-30T04:27:00.449+0000
```

The alert contained:

```text
Rule ID:
100502

Level:
8

Description:
SOC Lab: Process spawned via Windows Remote Management (WinRM) -
C:\Windows\System32\cmd.exe by SOC-LAB\nam.user

Agent:
SOC-WIN10

Agent IP:
192.168.50.20

Image:
C:\Windows\System32\cmd.exe

ParentImage:
C:\Windows\System32\wsmprovhost.exe

User:
SOC-LAB\nam.user
```

MITRE ATT&CK metadata was:

```text
Technique ID:
T1021.006

Technique:
Windows Remote Management

Tactic:
Lateral Movement
```

This confirms that the custom rule successfully detected the controlled
WinRM process execution.

---

## 17. Event Correlation

The raw Sysmon event and Wazuh alert share the exact timestamp:

```text
2026-09-30T04:27:00.449+0000
```

The following fields also correlate:

| Field | Sysmon Evidence | Wazuh Alert |
|---|---|---|
| Image | `cmd.exe` | `cmd.exe` |
| ParentImage | `wsmprovhost.exe` | `wsmprovhost.exe` |
| User | `SOC-LAB\nam.user` | `SOC-LAB\nam.user` |
| Endpoint | WIN10-01 | SOC-WIN10 |
| Timestamp | 04:27:00.449 | 04:27:00.449 |

This provides direct evidence of the telemetry-to-detection pipeline:

```text
Remote execution
      |
      v
WIN10-01
      |
      v
wsmprovhost.exe
      |
      v
cmd.exe
      |
      v
Sysmon Event ID 1
      |
      v
Wazuh Agent
      |
      v
Wazuh Manager
      |
      v
Rule 100502
      |
      v
Level 8 Alert
      |
      v
MITRE T1021.006
```

---

## 18. Evidence Files

The evidence collected for HUNT-003 is stored under:

```text
hunting/evidence/HUNT-003/
```

### HUNT-003-rule-100502.json

Path:

```text
hunting/evidence/HUNT-003/HUNT-003-rule-100502.json
```

Purpose:

- Preserves the Wazuh alert generated by custom rule 100502.
- Demonstrates the alert level.
- Preserves MITRE ATT&CK mapping.
- Records endpoint identity.
- Records process and parent-process information.
- Records the user context.

---

### HUNT-003-sysmon-winrm-cmd.json

Path:

```text
hunting/evidence/HUNT-003/HUNT-003-sysmon-winrm-cmd.json
```

Purpose:

- Preserves the original Sysmon Event ID 1 telemetry.
- Demonstrates `cmd.exe` process creation.
- Demonstrates `wsmprovhost.exe` as the parent process.
- Preserves command-line information.
- Preserves user context.
- Provides the raw telemetry corresponding to the Wazuh alert.

---

## 19. Investigation Interpretation

The detection demonstrates behavior associated with process execution
through Windows Remote Management.

However:

```text
WinRM activity != automatically malicious activity
```

WinRM is a legitimate Windows administration technology.

Potential legitimate use cases include:

- Remote administration
- Server management
- PowerShell remoting
- Automation
- Configuration management
- Enterprise maintenance

Potential suspicious use cases include:

- Remote command execution
- Lateral movement
- Post-compromise administration
- Execution using compromised credentials

Therefore, rule 100502 should be treated as an investigation signal rather
than automatic proof of compromise.

---

## 20. SOC Analyst Investigation Workflow

When rule 100502 fires, the analyst should investigate:

### Identity

Determine:

```text
Who executed the remote command?
```

Review:

- Username
- Domain
- Account privileges
- Expected administrative role
- Authentication history

---

### Source

Determine:

```text
Where did the WinRM session originate?
```

Correlate with:

- Windows Security logs
- Network telemetry
- Firewall logs
- Authentication events
- Source IP address

---

### Child Process

Determine:

```text
What process was launched?
```

Examples requiring context include:

```text
cmd.exe
powershell.exe
whoami.exe
hostname.exe
net.exe
reg.exe
sc.exe
```

---

### Command Line

Inspect:

```text
CommandLine
```

and determine whether the command matches expected administrative
activity.

---

### Process Tree

Review:

```text
wsmprovhost.exe
        |
        +-- child process
```

and any subsequent descendants.

For example:

```text
wsmprovhost.exe
        |
        +-- cmd.exe
               |
               +-- whoami.exe
```

---

### Authentication Context

Correlate WinRM process execution with Windows authentication telemetry,
particularly successful and failed logon events.

Relevant information includes:

- Account
- Source IP
- Logon type
- Authentication package
- Timestamp

---

## 21. Detection Limitations

Rule 100502 intentionally focuses on:

```text
ParentImage = wsmprovhost.exe
```

This provides useful visibility into processes spawned by the WinRM host
process, but it has limitations.

### Limitation 1 — Legitimate Administrative Activity

Authorized administrators using WinRM may trigger the rule.

Therefore, false positives are expected in environments where WinRM is
used regularly.

---

### Limitation 2 — Detection Is Process-Ancestry Based

The rule detects process creation associated with `wsmprovhost.exe`.

It does not independently prove:

- Credential compromise
- Unauthorized access
- Malicious intent
- Successful lateral movement

Additional context is required.

---

### Limitation 3 — Telemetry Dependency

The rule depends on Sysmon process creation telemetry reaching Wazuh.

If Sysmon is disabled, misconfigured, or Event ID 1 is not collected,
detection coverage will be reduced.

---

### Limitation 4 — WinRM Context Requires Correlation

Process ancestry alone does not provide the complete remote connection
context.

Authentication and network telemetry should be correlated to identify the
origin and purpose of the session.

---

## 22. Detection Recommendations

Future improvements should include correlation between:

```text
WinRM process creation
        +
Windows authentication
        +
Source IP
        +
Account identity
        +
Child process
        +
Command line
```

Higher severity could be assigned when WinRM execution is combined with
additional suspicious indicators.

Examples include:

- WinRM from an unexpected source
- WinRM using an unusual account
- PowerShell with suspicious command-line arguments
- Encoded PowerShell
- Credential discovery commands
- Security configuration modification
- Persistence-related commands
- Multiple endpoints accessed by the same account

---

## 23. Key Detection Engineering Lesson

HUNT-003 identified an important detection engineering principle:

> A custom detection should not inherit from an existing detection rule
> merely because the existing rule happened to match one test case.

The original implementation depended on rule 92052.

That worked for:

```text
wsmprovhost.exe
        |
        +-- cmd.exe
```

because rule 92052 is designed around abnormal `cmd.exe` process
creation.

However, WinRM can spawn other processes.

The improved detection instead models the behavior that the hunt is
actually attempting to identify:

```text
Process creation
        +
ParentImage = wsmprovhost.exe
```

This makes the detection logic better aligned with the behavioral
hypothesis.

---

## 24. Hunt Findings

### Finding 1 — WinRM Telemetry Is Visible

Sysmon successfully captured process creation associated with the WinRM
session.

**Status:** Confirmed

---

### Finding 2 — Process Ancestry Is Useful

`wsmprovhost.exe` was observed as the direct parent of remotely executed
processes.

**Status:** Confirmed

---

### Finding 3 — Original Detection Had a Coverage Gap

The original rule depended on Wazuh rule 92052, which specifically
targets abnormal `cmd.exe` execution.

This dependency did not represent general WinRM process execution.

**Status:** Confirmed

---

### Finding 4 — Detection Was Improved

Rule 100502 was changed to evaluate the `sysmon_event1` group directly
and match:

```text
ParentImage = wsmprovhost.exe
```

**Status:** Implemented

---

### Finding 5 — Improved Rule Generated an Alert

The controlled command:

```text
HUNT003-RULE100502-VALIDATION
```

generated:

```text
Rule 100502
Level 8
MITRE T1021.006
```

**Status:** Confirmed

---

## 25. Final Assessment

HUNT-003 successfully validated visibility and detection of process
execution associated with Windows Remote Management in SOC-LAB.

The endpoint generated Sysmon Event ID 1 telemetry showing:

```text
wsmprovhost.exe
        |
        +-- cmd.exe
```

Wazuh successfully processed the event and generated:

```text
Rule ID: 100502
Level: 8
MITRE ATT&CK: T1021.006
```

The hunt also uncovered a detection engineering weakness in the original
rule design.

The original rule depended on Wazuh rule 92052, which was designed around
abnormal `cmd.exe` execution rather than WinRM behavior in general.

Rule 100502 was therefore redesigned to evaluate Sysmon process creation
events directly and identify processes whose parent is
`wsmprovhost.exe`.

The final detection chain was validated as:

```text
Controlled WinRM execution
          |
          v
WIN10-01
          |
          v
wsmprovhost.exe
          |
          v
cmd.exe
          |
          v
Sysmon Event ID 1
          |
          v
Wazuh Agent
          |
          v
SOC-WAZUH
          |
          v
Rule 100502
          |
          v
Level 8
          |
          v
MITRE ATT&CK T1021.006
```

No real compromise was identified during HUNT-003.

All remote execution activity described in this hunt was intentionally
generated inside the controlled SOC-LAB environment for detection
validation.

---

## 26. Conclusion

HUNT-003 demonstrated both threat hunting and detection engineering
capabilities.

The hunt successfully:

1. Validated WinRM availability.
2. Validated remote management authorization.
3. Generated controlled WinRM process execution.
4. Identified `wsmprovhost.exe` process ancestry.
5. Collected Sysmon Event ID 1 telemetry.
6. Identified a weakness in the original detection design.
7. Improved Wazuh rule 100502.
8. Validated the improved rule.
9. Preserved raw Sysmon evidence.
10. Preserved the resulting Wazuh alert.
11. Mapped the detection to MITRE ATT&CK T1021.006.

The most important lesson from the hunt is that detection engineering
should model the behavior being investigated rather than depend on an
unrelated rule that happens to match a subset of test cases.

HUNT-003 is therefore considered:

```text
COMPLETED
```
