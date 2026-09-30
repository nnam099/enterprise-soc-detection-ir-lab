# HUNT-004 — Registry Run Key Persistence Analysis

## 1. Hunt Information

- **Hunt ID:** HUNT-004
- **Title:** Registry Run Key Persistence Analysis
- **Environment:** SOC-LAB
- **Target Endpoint:** SOC-WIN10 / WIN10-01
- **Target IP:** 192.168.50.20
- **Domain:** SOC-LAB.LOCAL
- **SIEM:** Wazuh
- **Endpoint Telemetry:** Sysmon
- **Primary Event:** Sysmon Event ID 13 — Registry Value Set
- **Custom Detection Rule:** 100501
- **Detection Level:** 7
- **MITRE ATT&CK:** T1112 / T1547.001
- **Hunt Status:** Completed

---

## 2. Hypothesis

Windows Registry Run keys are commonly used to automatically launch
programs when a user logs on.

Legitimate software frequently uses these registry locations for startup
behavior. However, the same mechanism can also be abused to establish
persistence.

The hunt hypothesis is:

> Modifications to Windows Registry Run keys should be visible through
> Sysmon Event ID 13 and can be detected by Wazuh, but the resulting
> alert requires contextual investigation because legitimate software
> may generate the same registry behavior.

The objective of HUNT-004 is therefore to:

1. Validate Registry Run Key telemetry.
2. Validate Wazuh rule 100501.
3. Compare legitimate and controlled persistence activity.
4. Determine whether a Run Key alert alone is sufficient evidence of
malicious persistence.
5. Document analyst triage requirements.

---

## 3. Scope

The hunt focuses on the following environment:

| Component | Value |
|---|---|
| Domain | SOC-LAB.LOCAL |
| Endpoint | WIN10-01 |
| Wazuh Agent | SOC-WIN10 |
| Endpoint IP | 192.168.50.20 |
| Test User | `SOC-LAB\nam.user` |
| Registry Hive | HKEY_CURRENT_USER |
| Registry Key | `Software\Microsoft\Windows\CurrentVersion\Run` |
| Sysmon Event | Event ID 13 |
| Wazuh Rule | 100501 |

All persistence-related activity documented in this hunt was intentionally
generated inside the controlled SOC-LAB environment.

No real compromise was performed.

---

## 4. MITRE ATT&CK Mapping

The detection is mapped to two ATT&CK techniques.

### T1112 — Modify Registry

This technique represents modification of the Windows Registry.

The controlled test modified a registry value under the current user's
Run key.

---

### T1547.001 — Registry Run Keys / Startup Folder

This technique represents the use of Registry Run keys or Startup Folder
locations to execute programs during user logon.

The relevant registry path in this hunt was:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

The ATT&CK mapping describes the observed behavior.

It does not independently establish malicious intent.

---

## 5. Data Sources

### 5.1 Sysmon Event ID 13

Sysmon Event ID 13 records registry value modification activity.

Important fields include:

- `Image`
- `TargetObject`
- `Details`
- `User`
- `UtcTime`

For this hunt, these fields allow the analyst to determine:

```text
Which process modified the Registry?
+
Which Registry value was modified?
+
What data was written?
+
Which user performed the operation?
```

---

### 5.2 Wazuh

Wazuh receives the Sysmon telemetry from SOC-WIN10.

The custom detection rule used by SOC-LAB is:

```text
Rule ID: 100501
Level: 7
MITRE:
T1112
T1547.001
```

---

## 6. Existing Detection Rule

The SOC-LAB detection was already implemented before HUNT-004:

```xml
<rule id="100501" level="7">
<if_sid>92300</if_sid>
<description>
SOC Lab: Registry Run Key modification detected -
$(win.eventdata.targetObject)
</description>
<mitre>
<id>T1112</id>
<id>T1547.001</id>
</mitre>
</rule>
```

Rule 100501 inherits from Wazuh rule:

```text
92300
```

---

## 7. Parent Rule Analysis

The Wazuh parent rule was inspected from:

```text
/var/ossec/ruleset/rules/0860-sysmon_id_13.xml
```

Relevant logic:

```xml
<rule id="92300" level="0">
<if_group>sysmon_event_13</if_group>
<field name="win.eventdata.targetObject" type="pcre2">
...
</field>
<description>
Added registry content to be executed on next logon
</description>
<mitre>
<id>T1547.001</id>
</mitre>
</rule>
```

Rule 92300 identifies Sysmon Event ID 13 activity associated with relevant
Windows Run key locations.

Custom rule 100501 increases visibility by generating a level 7 alert and
adding SOC-LAB-specific MITRE mapping.

The detection pipeline is therefore:

```text
Registry value modification
|
v
Sysmon Event ID 13
|
v
Wazuh Rule 92300
|
v
SOC-LAB Rule 100501
|
+-- T1112
|
+-- T1547.001
```

---

## 8. Legitimate Run Key Activity Observed

Before generating the controlled test, historical rule 100501 alerts were
reviewed.

Several legitimate Microsoft Edge Run Key modifications were observed.

Example process:

```text
C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
```

Example registry value:

```text
...\Software\Microsoft\Windows\CurrentVersion\Run\
MicrosoftEdgeAutoLaunch_...
```

Example data:

```text
"msedge.exe" --no-startup-window --win-session-start
```

User:

```text
SOC-LAB\nam.user
```

These events triggered:

```text
Rule 100501
Level 7
T1112
T1547.001
```

This demonstrates that Registry Run Key modification is not automatically
malicious.

Legitimate software may use exactly the same persistence mechanism.

---

## 9. Controlled Persistence Validation

A controlled Registry Run Key value was created under:

```text
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
```

The test value name was:

```text
HUNT004-RUNKEY-VALIDATION
```

The test data was:

```text
cmd.exe /c echo HUNT004-PERSISTENCE-TEST > C:\Users\Public\hunt004.txt
```

The PowerShell operation used to generate the test was:

```powershell
$Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

Set-ItemProperty `
-Path $Path `
-Name "HUNT004-RUNKEY-VALIDATION" `
-Value 'cmd.exe /c echo HUNT004-PERSISTENCE-TEST > C:\Users\Public\hunt004.txt'
```

The registry value was then verified with:

```powershell
Get-ItemProperty `
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "HUNT004-RUNKEY-VALIDATION"
```

The value existed successfully.

---

## 10. Raw Sysmon Evidence

Sysmon captured the registry modification at:

```text
2026-09-30T04:53:24.407+0000
```

Relevant telemetry:

```text
Event ID:
13

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

TargetObject:
HKU\<USER-SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
HUNT004-RUNKEY-VALIDATION

Details:
cmd.exe /c echo HUNT004-PERSISTENCE-TEST >
C:\Users\Public\hunt004.txt

User:
SOC-LAB\nam.user
```

The telemetry demonstrates:

```text
powershell.exe
|
v
Registry Value Set
|
v
CurrentVersion\Run
|
v
HUNT004-RUNKEY-VALIDATION
```

This is direct endpoint evidence of a Registry Run Key modification.

---

## 11. Wazuh Detection Evidence

The same event generated Wazuh custom rule 100501 at:

```text
2026-09-30T04:53:24.407+0000
```

The alert contained:

```text
Rule ID:
100501

Level:
7

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

TargetObject:
...\Software\Microsoft\Windows\CurrentVersion\Run\
HUNT004-RUNKEY-VALIDATION

Details:
cmd.exe /c echo HUNT004-PERSISTENCE-TEST >
C:\Users\Public\hunt004.txt

User:
SOC-LAB\nam.user
```

The alert included ATT&CK mappings:

```text
T1112
Modify Registry

T1547.001
Registry Run Keys / Startup Folder
```

The associated tactics included:

```text
Defense Evasion
Persistence
Privilege Escalation
```

---

## 12. Telemetry-to-Detection Correlation

The raw Sysmon event and Wazuh alert share the exact timestamp:

```text
2026-09-30T04:53:24.407+0000
```

They also share the same:

- Process image
- Registry target
- Registry data
- User context

Correlation:

| Field | Sysmon | Wazuh |
|---|---|---|
| Timestamp | 04:53:24.407 | 04:53:24.407 |
| Event | Sysmon 13 | Rule 100501 |
| Image | `powershell.exe` | `powershell.exe` |
| Target | Run Key | Run Key |
| Marker | HUNT004-RUNKEY-VALIDATION | HUNT004-RUNKEY-VALIDATION |
| User | `SOC-LAB\nam.user` | `SOC-LAB\nam.user` |

This proves the complete detection path:

```text
PowerShell
|
v
Registry Run Key modification
|
v
Sysmon Event ID 13
|
v
Wazuh Agent
|
v
Rule 92300
|
v
Rule 100501
|
v
Level 7 Alert
```

---

## 13. Cleanup

The controlled Run Key was removed after evidence collection.

Cleanup command:

```powershell
Remove-ItemProperty `
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "HUNT004-RUNKEY-VALIDATION"
```

The registry value was then queried with:

```powershell
Get-ItemProperty `
-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
-Name "HUNT004-RUNKEY-VALIDATION" `
-ErrorAction SilentlyContinue
```

The test was designed only for controlled telemetry generation and was
not intended to remain persistent in the lab environment.

---

## 14. Evidence Files

Evidence is stored under:

```text
hunting/evidence/HUNT-004/
```

### HUNT-004-sysmon-event13.json

Path:

```text
hunting/evidence/HUNT-004/HUNT-004-sysmon-event13.json
```

Purpose:

- Preserves the raw Sysmon Event ID 13.
- Records the modifying process.
- Records the Run Key path.
- Records the registry data.
- Records the user.
- Provides endpoint-level evidence.

---

### HUNT-004-rule-100501.json

Path:

```text
hunting/evidence/HUNT-004/HUNT-004-rule-100501.json
```

Purpose:

- Preserves the Wazuh alert.
- Demonstrates rule 100501 activation.
- Preserves alert level.
- Preserves ATT&CK mapping.
- Demonstrates correlation with the original Sysmon event.

---

## 15. Benign vs Suspicious Comparison

One of the most important findings from HUNT-004 is that the same rule
can identify both legitimate and suspicious-looking Run Key activity.

### Legitimate Example

```text
Process:
msedge.exe

Registry:
CurrentVersion\Run\MicrosoftEdgeAutoLaunch_...

Details:
Microsoft Edge startup command
```

Rule result:

```text
100501
```

---

### Controlled Persistence Example

```text
Process:
powershell.exe

Registry:
CurrentVersion\Run\HUNT004-RUNKEY-VALIDATION

Details:
cmd.exe /c echo HUNT004-PERSISTENCE-TEST ...
```

Rule result:

```text
100501
```

Therefore:

```text
Rule 100501 firing
!=
Confirmed malicious persistence
```

The alert indicates that a persistence-capable registry location was
modified.

Analyst investigation is still required.

---

## 16. Analyst Triage Workflow

When rule 100501 fires, the SOC analyst should investigate several
dimensions.

### 16.1 Modifying Process

Review:

```text
Image
```

Examples:

```text
msedge.exe
powershell.exe
cmd.exe
reg.exe
installer.exe
updater.exe
```

Ask:

> Is this process normally expected to modify startup configuration?

---

### 16.2 Registry Target

Review:

```text
TargetObject
```

Identify:

- HKCU vs HKLM
- Run vs RunOnce
- Value name
- User SID
- Whether the location is expected for the software involved

---

### 16.3 Registry Data

Review:

```text
Details
```

This is often one of the most important fields.

Examples that deserve additional review include references to:

```text
powershell.exe
cmd.exe
wscript.exe
cscript.exe
rundll32.exe
mshta.exe
user-writable paths
temporary directories
unusual scripts
unknown executables
```

The presence of these processes is not automatically malicious, but can
increase investigation priority.

---

### 16.4 User Context

Review:

```text
User
```

Determine:

- Is the user expected to install or configure software?
- Is the account privileged?
- Did authentication anomalies occur before the registry modification?
- Was the modification initiated through remote administration?

---

### 16.5 Process Ancestry

Investigate the process tree that led to the registry modification.

For example:

```text
wsmprovhost.exe
|
v
powershell.exe
|
v
Registry Run Key
```

would provide more contextual information than the Registry event alone.

---

### 16.6 Timeline Correlation

Correlate Registry persistence activity with:

- Successful logons
- Failed logons
- WinRM activity
- PowerShell execution
- Encoded PowerShell
- File creation
- Network activity

This allows the analyst to determine whether the registry event is part
of a larger suspicious sequence.

---

## 17. Detection Strengths

Rule 100501 provides useful visibility because it identifies modifications
to a persistence-capable Windows Registry location.

Strengths include:

- Uses Sysmon Event ID 13.
- Captures the modifying process.
- Captures registry value data.
- Captures user identity.
- Maps to relevant ATT&CK techniques.
- Works for both benign and controlled test cases.
- Provides a useful investigation pivot.

---

## 18. Detection Limitations

### Limitation 1 — Legitimate Run Keys Are Common

Legitimate applications may use Run keys.

Microsoft Edge activity observed during HUNT-004 demonstrates this
directly.

Therefore, the rule may produce detection noise.

---

### Limitation 2 — Behavior Alone Does Not Prove Malice

The rule identifies a persistence-capable action.

It does not independently prove:

- Malware execution
- Account compromise
- Unauthorized persistence
- Successful exploitation

---

### Limitation 3 — Parent Rule Dependency

Custom rule 100501 depends on:

```text
92300
```

Therefore, detection coverage is partly determined by the registry paths
and patterns recognized by the upstream Wazuh rule.

---

### Limitation 4 — Event ID 13 Dependency

If Sysmon Event ID 13 is unavailable, disabled, filtered, or not forwarded
to Wazuh, the detection cannot operate.

---

## 19. Detection Engineering Assessment

Unlike HUNT-003, no immediate functional detection gap was demonstrated
for the tested Registry Run Key path.
	
	The rule successfully detected:
	
	1. Legitimate Microsoft Edge Run Key activity.
	2. Controlled PowerShell-based Run Key modification.
	
	However, this reveals a different engineering issue:
	
	```text
	Coverage is good
	|
	v
	Context is broad
	|
	v
	Potential alert noise
	```
	
	Therefore, the next improvement should not necessarily be to suppress
	Run Key alerts entirely.
	
	Instead, analysts should preserve visibility while introducing additional
	context or severity differentiation.
	
	---
	
	## 20. Detection Improvement Recommendations
	
	### Recommendation 1 — Preserve General Run Key Visibility
	
	Do not globally suppress all legitimate-looking Run Key modifications.
	
	Run Key telemetry is valuable during incident investigation.
	
	---
	
	### Recommendation 2 — Add Contextual Severity
	
	Consider higher-severity detections when Registry Run Key data references
	unusual interpreters or binaries.
	
	Examples:
	
	```text
	powershell.exe
	cmd.exe
	wscript.exe
	cscript.exe
	mshta.exe
	rundll32.exe
	```
	
	These should still be evaluated in context.
	
	---
	
	### Recommendation 3 — Baseline Common Software
	
	Known enterprise applications may legitimately modify Run keys.
	
	Baseline expected software such as:
	
	```text
	Microsoft Edge
	approved endpoint software
	authorized update agents
	```
	
	without completely removing the telemetry from investigation.
	
	---
	
	### Recommendation 4 — Correlate With Other Hunts
	
	Registry persistence becomes more meaningful when correlated with events
	already covered by SOC-LAB.
	
	For example:
	
	```text
	HUNT-002 Authentication Anomaly
	|
	v
	HUNT-003 WinRM Remote Execution
	|
	v
	HUNT-001 PowerShell Activity
	|
	v
	HUNT-004 Registry Persistence
	```
	
	This correlation can increase confidence that otherwise ambiguous
	registry activity deserves escalation.
	
	---
	
	## 21. Hunt Findings
	
	### Finding 1 — Registry Run Key Telemetry Is Available
	
	Sysmon successfully captured controlled Registry Run Key modification.
	
	**Status:** Confirmed
	
	---
	
	### Finding 2 — Rule 100501 Detects Run Key Modification
	
	The controlled validation successfully generated custom Wazuh rule
	100501.
	
	**Status:** Confirmed
	
	---
	
	### Finding 3 — Raw and Alert Evidence Correlate Exactly
	
	The Sysmon event and Wazuh alert shared:
	
	```text
	2026-09-30T04:53:24.407+0000
	```
	
	as the event timestamp.
	
	**Status:** Confirmed
	
	---
	
	### Finding 4 — Legitimate Software Also Triggers the Detection
	
	Microsoft Edge Run Key modifications generated the same custom rule.
	
	**Status:** Confirmed
	
	---
	
	### Finding 5 — Alert Does Not Equal Incident
	
	Rule 100501 identifies behavior that can provide persistence, but
	additional process, registry, authentication, and timeline context is
	required before escalation.
	
	**Status:** Confirmed
	
	---
	
	### Finding 6 — Detection Coverage Was Effective for the Tested Path
	
	No false negative was observed for the tested:
	
	```text
	HKCU\Software\Microsoft\Windows\CurrentVersion\Run
	```
	
	modification.
	
	**Status:** Confirmed
	
	---
	
	## 22. Final Assessment
	
	HUNT-004 successfully validated visibility and detection of Windows
	Registry Run Key persistence behavior in SOC-LAB.
	
	A controlled Run Key modification generated:
	
	```text
	Sysmon Event ID 13
	```
	
	with:
	
	```text
	Image:
	powershell.exe
	
	TargetObject:
	...\CurrentVersion\Run\HUNT004-RUNKEY-VALIDATION
	
	Details:
	cmd.exe /c echo HUNT004-PERSISTENCE-TEST ...
	
	User:
	SOC-LAB\nam.user
	```
	
	Wazuh correlated the telemetry through rule 92300 and generated custom
	rule:
	
	```text
	100501
	```
	
	at:
	
	```text
	Level 7
	```
	
	with ATT&CK mappings:
	
	```text
	T1112
	T1547.001
	```
	
	The same detection rule was also observed firing for legitimate Microsoft
	Edge autostart activity.
	
	This demonstrates an important SOC principle:
	
	> Detection of persistence-capable behavior is not equivalent to proof
	> of malicious persistence.
	
	Rule 100501 provides useful visibility, but analyst context is required
	to distinguish legitimate startup configuration from suspicious
	persistence.
	
	---
	
	## 23. Conclusion
	
	HUNT-004 demonstrated:
	
	1. Windows Registry Run Key analysis.
	2. Sysmon Event ID 13 investigation.
	3. Wazuh detection validation.
	4. MITRE ATT&CK mapping.
	5. Raw event and alert correlation.
	6. Controlled persistence simulation.
	7. Benign-versus-suspicious comparison.
	8. False-positive and detection-noise analysis.
	9. SOC analyst triage methodology.
	10. Detection engineering recommendations.
	
	The final validated chain is:
	
	```text
	Controlled PowerShell activity
	|
	v
	Registry Run Key modification
	|
	v
	Sysmon Event ID 13
	|
	v
	Wazuh Rule 92300
	|
	v
	SOC-LAB Rule 100501
	|
	v
	Level 7
	|
	+---- T1112
	|
	+---- T1547.001
	```
	
	No real compromise was identified during HUNT-004.
	
	The registry modification was deliberately generated inside SOC-LAB for
	threat hunting and detection validation.
	
	HUNT-004 is therefore considered:
	
	```text
	COMPLETED
	```
