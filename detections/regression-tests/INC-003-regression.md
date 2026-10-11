# INC-003 — PowerShell Detection Regression Testing

## 1. Objective

Validate the Wazuh detection behavior observed
during INC-003, assess the custom Rule 100504,
and determine whether detection tuning is required.

This testing was performed using authorized,
benign PowerShell commands in an isolated SOC lab.

## 2. Environment

| Component | Value |
|---|---|
| Endpoint | SOC-WIN10 |
| Operating System | Windows 10 Pro |
| Wazuh Agent | 001 |
| Wazuh Version | 4.14.8 |
| Telemetry | Sysmon Event ID 1 |
| Custom Rule | 100504 |
| Built-in Rules | 92057, 92032 |
| MITRE ATT&CK | T1059.001 |

## 3. Detection Logic Review

### Custom Rule 100504

- Severity: Level 8
- Parent rule: 61603
- Source: Sysmon Event ID 1
- Process image: powershell.exe
- Command-line indicators:
  - `-EncodedCommand`
  - `-enc`
- No explicit PowerShell parent-process requirement.

### Built-in Rule 92057

- Severity: Level 12
- Source group: sysmon_event1
- Parent image: powershell.exe
- Child command line: encoded PowerShell invocation
- MITRE ATT&CK: T1059.001

### Built-in Rule 92032

- Severity: Level 3
- Parent image: cmd.exe
- Parent command line contains `/C`
- Description: Suspicious Windows cmd shell execution

Rule 92032 is not an encoded PowerShell
detection rule.

## 4. Regression Test Matrix

| Test ID | Execution | Expected | Actual | Result |
|---|---|---|---|---|
| POS-01 | PowerShell to encoded PowerShell | Detect encoded PowerShell | Rule 92057, Level 12 | PASS |
| POS-02 | CMD to encoded PowerShell | Detect encoded PowerShell | Rule 100504, Level 8 | PASS |
| NEG-01 | CMD to normal PowerShell | No alert from encoded-command rules | Rule 92032 only | PASS |

The negative test was not alert-free.

## 5. POS-01 — PowerShell Parent

**Behavior:** A PowerShell process created a
child PowerShell process using `-EncodedCommand`.

**Primary incident event:**

- EventRecordID: 20779
- Process ID: 4512
- ProcessGuid:
  `{e12a69d9-d745-6aca-e801-000000002300}`
- Parent image: powershell.exe
- Wazuh Rule: 92057
- Rule Level: 12

**Verdict: PASS**

Wazuh detected the simulated suspicious
PowerShell execution.

The associated containment workflow is
documented separately under INC-003.

## 6. POS-02 — CMD Parent

**Behavior:** A CMD process launched an encoded
PowerShell command containing a unique test marker.

- Marker: INC003-REG-CMD-20261011073227
- EventRecordID: 20782
- Process ID: 7672
- ProcessGuid:
  `{e12a69d9-d91c-6aca-f101-000000002300}`
- Parent image: cmd.exe
- Child image: powershell.exe
- Wazuh Rule: 100504
- Rule Level: 8

**Verdict: PASS**

The custom rule detected encoded PowerShell
execution without requiring PowerShell as
the parent process.

This test demonstrates a useful detection
case covered by Rule 100504.

## 7. NEG-01 — Normal PowerShell

**Behavior:** CMD launched PowerShell using
the normal `-Command` argument.

- Marker: INC003-NEG-20261011073408
- EventRecordID: 20785
- ProcessGuid:
  `{e12a69d9-d980-6aca-f501-000000002300}`
- Parent image: cmd.exe
- Child image: powershell.exe
- EncodedCommand: absent
- Actual alert: Rule 92032, Level 3
- Rule 100504: not triggered
- Rule 92057: not triggered

The event was found in both Wazuh
`alerts.json` and `archives.json`.

**Verdict: PASS**

The absence of alerts from Rules 100504
and 92057 meets the negative-test criterion.

Rule 92032 matched the CMD execution
pattern and is evaluated separately.

## 8. Detection Tuning Decision

**Decision: NO CHANGE REQUIRED**

Evidence supporting this decision:

1. POS-01 was detected by Rule 92057.
2. POS-02 was detected by custom Rule 100504.
3. NEG-01 did not trigger either encoded-command
   detection rule.
4. Wazuh analysisd configuration validation
   returned exit code 0.

No detection rule was modified as part
of this incident response exercise.

## 9. Regression Limitations

- Only three controlled scenarios were evaluated.
- The simulation did not use real malware.
- The test set cannot establish a production
  false-positive rate.
- Additional parent-process variations and
  PowerShell argument aliases remain untested.
- A single Wazuh event may match multiple rule
  conditions without producing separate alerts
  for every matching rule.

## 10. References and Evidence

- [Incident Report](../../incidents/INC-003/incident-report.md)
- [Incident Timeline](../../incidents/INC-003/timeline.md)
- [Evidence Manifest](../../incidents/INC-003/evidence-manifest.md)

Original JSONL evidence is preserved outside
the public Git repository and verified
using SHA-256 hashes.
