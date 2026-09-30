# HUNT-001 — Suspicious PowerShell Activity

## 1. Hunt Information

- **Hunt ID:** HUNT-001
- **Category:** Endpoint / PowerShell
- **Environment:** SOC-LAB.LOCAL
- **Endpoint:** SOC-WIN10 / WIN10-01
- **SIEM:** Wazuh
- **Telemetry:** Sysmon + Wazuh
- **MITRE ATT&CK:** T1059.001 — PowerShell
- **Status:** Completed

---

## 2. Hypothesis

An attacker or unauthorized user may abuse PowerShell to execute encoded commands or perform suspicious activity on a Windows endpoint.

The objective of this hunt is to:

1. Establish normal PowerShell execution telemetry.
2. Test encoded PowerShell execution.
3. Determine existing Wazuh detection coverage.
4. Compare built-in and custom detection logic.
5. Identify possible detection gaps.

---

## 3. Data Sources

The hunt used the following telemetry:

- Sysmon Event ID 1 — Process Creation
- Process Image
- Process Command Line
- Parent Process Image
- Process ID / Process GUID
- User context
- Integrity level
- Wazuh alerts
- MITRE ATT&CK mappings

Primary endpoint:

- `WIN10-01.SOC-LAB.LOCAL`

Wazuh agent:

- `SOC-WIN10`

---

## 4. Hunt Methodology

The hunt followed the workflow:

**Hypothesis → Search → Evidence → Finding → Detection Recommendation**

Three controlled validation cases were performed.

> **Important:** The generated activity was controlled lab telemetry. Detection of an event does not by itself prove malicious activity.

---

## 5. Test Case 1 — Benign PowerShell Baseline

### Objective

Verify that Sysmon and Wazuh correctly observe PowerShell process creation before testing more suspicious command-line patterns.

### Controlled Activity

A PowerShell process spawned another PowerShell process to execute a harmless `Write-Output` command.

Process relationship:

```text
powershell.exe
    |
    +-- powershell.exe
            |
            +-- Write-Output "HUNT001-BASELINE-TEST"
```

### Detection Result

Wazuh generated:

- **Rule ID:** 92027
- **Level:** 4
- **Description:** `Powershell process spawned powershell instance`

### Analyst Assessment

**Disposition: Benign / Lab Validation**

The activity was intentionally generated for validation.

This demonstrates that a detection alert does not automatically represent a security incident. Analyst context is required.

### Evidence

`evidence/HUNT-001/HUNT-001-rule-92027.json`

---

## 6. Test Case 2 — Encoded PowerShell with PowerShell Parent

### Objective

Determine whether Wazuh provides built-in detection for encoded PowerShell.

### Controlled Activity

A harmless PowerShell command was converted to Base64 and executed using:

```text
powershell.exe -NoProfile -EncodedCommand <BASE64>
```

Process relationship:

```text
powershell.exe
    |
    +-- powershell.exe -EncodedCommand <BASE64>
```

### Detection Result

Wazuh generated:

- **Rule ID:** 92057
- **Level:** 12
- **Description:** `Powershell.exe spawned a powershell process which executed a base64 encoded command`
- **MITRE ATT&CK:** T1059.001 — PowerShell

### Detection Logic Analysis

Built-in rule `92057` requires:

- Sysmon Event ID 1
- Parent process matching `powershell.exe`
- Command line matching PowerShell encoded-command patterns

Therefore, the rule provides detection coverage for:

```text
PowerShell → PowerShell → Encoded Command
```

### Analyst Assessment

**Disposition: Benign / Controlled Suspicious Telemetry**

The encoded command only generated a lab marker and performed no malicious action.

However, the command-line pattern is security-relevant and correctly triggered a high-severity detection.

### Evidence

`evidence/HUNT-001/HUNT-001-rule-92057.json`

---

## 7. Test Case 3 — Encoded PowerShell with CMD Parent

### Objective

Test whether encoded PowerShell remains detectable when the parent process is not PowerShell.

This case was used to evaluate whether custom SOC-LAB rule `100504` provides detection coverage beyond built-in Wazuh rule `92057`.

### Controlled Activity

The encoded PowerShell command was launched from `cmd.exe`.

Process relationship:

```text
cmd.exe
    |
    +-- powershell.exe -NoProfile -EncodedCommand <BASE64>
```

Sysmon confirmed the process relationship:

```text
ParentImage:
C:\Windows\System32\cmd.exe

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The captured command line contained:

```text
powershell.exe -NoProfile -EncodedCommand <BASE64>
```

### Detection Result

Custom Wazuh detection generated:

- **Rule ID:** 100504
- **Level:** 8
- **MITRE ATT&CK:** T1059.001 — PowerShell

Rule `92057` was not responsible for this detection because its detection logic specifically requires a PowerShell parent process.

### Custom Detection Logic

Rule `100504` evaluates:

```text
Sysmon Event ID 1
        +
Image = powershell.exe
        +
CommandLine contains -EncodedCommand
```

The custom rule does not require `powershell.exe` to be the parent process.

The relevant rule logic is stored in:

`configs/wazuh/rules/local_rules.xml`

### Analyst Assessment

**Disposition: Benign / Controlled Detection Validation**

The activity was intentionally generated and the decoded command only produced a lab marker.

However, this test demonstrates additional detection coverage provided by custom rule `100504`.

### Evidence

`evidence/HUNT-001/HUNT-001-rule-100504.json`

---

## 8. Detection Coverage Analysis

The three validation cases produced the following observed coverage.

### Baseline PowerShell

```text
PowerShell
    |
    +-- PowerShell
          |
          +-- Normal command
                  |
                  +-- Wazuh 92027
                      Level 4
```

### Encoded PowerShell with PowerShell Parent

```text
PowerShell
    |
    +-- PowerShell
          |
          +-- -EncodedCommand
                  |
                  +-- Wazuh 92057
                      Level 12
```

### Encoded PowerShell with CMD Parent

```text
CMD
 |
 +-- PowerShell
       |
       +-- -EncodedCommand
               |
               +-- Custom 100504
                   Level 8
```

The validation demonstrates that custom rule `100504` is not merely a duplicate of built-in rule `92057`.

Rule `92057` provides detection for encoded PowerShell where PowerShell is the parent process.

Rule `100504` provides broader parent-independent coverage for PowerShell executing with the `-EncodedCommand` argument.

---

## 9. Findings

### HUNT-001-F01 — Existing Wazuh Coverage

**Encoded PowerShell is covered by the default Wazuh Sysmon detection rules.**

Built-in rule `92057` successfully detected the controlled PowerShell-to-PowerShell encoded-command execution.

This demonstrates that the SIEM already contains detection logic for this PowerShell behavior.

---

### HUNT-001-F02 — Parent Process Affects Detection Coverage

**Parent-process conditions affect which detection rule is applicable.**

Rule `92057` specifically evaluates a PowerShell parent process.

Changing the process relationship from:

```text
powershell.exe → powershell.exe
```

to:

```text
cmd.exe → powershell.exe
```

changes the applicable detection logic.

---

### HUNT-001-F03 — Custom Rule 100504 Extends Coverage

**Custom rule `100504` provides additional detection coverage.**

The custom rule successfully detected:

```text
cmd.exe → powershell.exe -EncodedCommand
```

The test demonstrates that `100504` can detect encoded PowerShell independently of the PowerShell parent-process requirement used by rule `92057`.

---

### HUNT-001-F04 — Detection Does Not Equal Compromise

**An alert is not automatically an incident.**

All activity performed during HUNT-001 was controlled lab validation.

The generated alerts demonstrate detection capability, but they do not demonstrate that `WIN10-01` was actually compromised.

Analyst validation and surrounding context remain necessary.

---

### HUNT-001-F05 — Analyst Activity Can Generate Telemetry

During the investigation, commands executed on the Wazuh server using tools such as `sudo` and `grep` also generated telemetry.

For example, searching the Wazuh archives for `EncodedCommand` caused the analyst's own command line to appear in collected events.

This demonstrates an important threat-hunting consideration:

> Analysts must distinguish endpoint evidence from telemetry generated by their own investigation activity.

For this hunt:

```text
Agent 001 — SOC-WIN10
    |
    +-- Endpoint evidence

Agent 000 — soc-wazuh
    |
    +-- SIEM / analyst-generated activity
```

---

## 10. Detection Recommendation

### Recommendation 1 — Retain Custom Rule 100504

Custom rule `100504` should be retained.

Controlled testing demonstrated that the rule detects:

```text
cmd.exe → powershell.exe -EncodedCommand
```

without requiring PowerShell to be the parent process.

This extends detection coverage beyond the specific parent-process condition observed in built-in rule `92057`.

---

### Recommendation 2 — Document Detection Overlap

The relationship between the following rules should be documented:

- `92057` — Built-in Wazuh encoded PowerShell detection
- `100504` — Custom SOC-LAB encoded PowerShell detection

The rules overlap for some encoded PowerShell executions but have different process-context requirements.

This overlap is intentional because the custom rule provides broader parent-independent coverage.

---

### Recommendation 3 — Require Analyst Context

Encoded PowerShell should be treated as suspicious telemetry requiring investigation rather than automatic proof of compromise.

Analyst triage should consider:

- User account
- Parent process
- Process ancestry
- Full command line
- Integrity level
- Related network connections
- Related child processes
- Host role
- Surrounding authentication events
- Other Sysmon events near the same timestamp

---

### Recommendation 4 — Continue Hunting for Related Activity

Future hunts should correlate suspicious PowerShell execution with:

- Sysmon Event ID 3 — Network Connection
- Authentication events
- Remote execution activity
- Registry persistence
- Related process creation
- Other endpoint telemetry

These correlations should only be treated as part of the same activity when supported by actual timestamps and telemetry.

---

## 11. MITRE ATT&CK Mapping

| Technique | ID | Observed |
|---|---|---|
| PowerShell | T1059.001 | Yes |

The mapping represents behavior exercised during controlled detection validation.

It does not imply that a real intrusion occurred.

---

## 12. Evidence Summary

| Evidence | Rule | Level | Purpose |
|---|---:|---:|---|
| `HUNT-001-rule-92027.json` | 92027 | 4 | PowerShell baseline |
| `HUNT-001-rule-92057.json` | 92057 | 12 | Built-in encoded PowerShell detection |
| `HUNT-001-rule-100504.json` | 100504 | 8 | Custom parent-independent encoded PowerShell detection |

Evidence directory:

```text
hunting/evidence/HUNT-001/
├── HUNT-001-rule-100504.json
├── HUNT-001-rule-92027.json
└── HUNT-001-rule-92057.json
```

Custom Wazuh detection configuration:

```text
configs/wazuh/rules/local_rules.xml
```

---

## 13. Hunt Result

**Hunt Status:** Completed

**Finding:** Detection coverage validated and custom detection value confirmed.

**Incident Created:** No

**Reason:** All suspicious telemetry was intentionally generated as controlled lab validation. No evidence collected during this hunt independently demonstrated a real compromise.

---

## 14. Conclusion

HUNT-001 successfully validated the end-to-end detection path:

```text
Windows Process
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
Detection Rule
      |
      v
Alert
      |
      v
Analyst Investigation
```

The hunt confirmed existing Wazuh coverage for suspicious PowerShell execution and demonstrated that custom rule `100504` extends detection coverage to encoded PowerShell executions where the parent process is not PowerShell.

The hunt also demonstrated two important SOC principles:

1. **Detection does not automatically mean compromise.**
2. **Detection coverage must be validated against process context rather than assumed from rule descriptions alone.**

No real compromise was identified during HUNT-001.

All suspicious activity described in this report was intentionally generated inside the SOC lab for detection validation.
