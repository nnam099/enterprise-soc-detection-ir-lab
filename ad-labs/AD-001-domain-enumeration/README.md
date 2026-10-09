# AD-001 — Active Directory Telemetry Baseline

## Scope

- Domain Controller: SOC-DC01 (192.168.50.10)
- SIEM: SOC-WAZUH (192.168.50.30)
- Wazuh Agent ID: 002
- Lab environment: QEMU/KVM, 8GB host
- Maximum concurrent VMs: 2

## Verified observations — 2026-10-09

### Agent connectivity
- SOC-DC01: Active in Wazuh Manager.
- Windows Security EventChannel: configured.
- Wazuh Manager recorded 739 alerts from agent 002
  in the inspected alerts.json file.
- Observed Security Event IDs in alerts:
  - 4688: 345
  - 4634: 15
  - 4624: 14

Note: these are alert counts, not raw EventChannel totals.

### Kerberos Audit Policy
- Kerberos Authentication Service: Success and Failure.
- Kerberos Service Ticket Operations: Success and Failure.

### Native Security Event counts

Window: six hours preceding the measurement on 2026-10-09.

| Event ID | Count |
|---|---:|
| 4624 | 185 |
| 4625 | 0 |
| 4768 | 7 |
| 4769 | 15 |
| 4771 | 0 |

These are native Windows Event Log counts,
not Wazuh detection counts.

## Detection Engineering Case Study

### Objective

Detect PowerShell-based Active Directory enumeration on SOC-DC01
using Windows PowerShell Script Block Logging (Event ID 4104)
and Wazuh custom detection Rule 100506.

Environment:
- Domain: SOC-LAB.LOCAL
- Endpoint: SOC-DC01, Wazuh Agent 002
- SIEM: SOC-WAZUH 4.14.8
- Resource constraint: 8 GB host, maximum two concurrent VMs
- Test date: 2026-10-09

### Telemetry Pipeline

1. A controlled `Get-ADUser` query was executed on SOC-DC01.
2. PowerShell recorded Windows Event ID 4104.
3. Wazuh Agent 002 forwarded the event to SOC-WAZUH.
4. Wazuh stored the event in `archives.json`.
5. Rule 100506 generated an alert in `alerts.json`.

Verified decoder: `windows_eventchannel`.

### Detection Logic

**Rule:** [100506-ad-enumeration.xml](../../detections/wazuh/rules/100506-ad-enumeration.xml)

- Rule ID: `100506`
- Alert level: `3` (low-severity detection signal)
- Parent rule: `91802`
- Required channel: `Microsoft-Windows-PowerShell/Operational`
- Event ID: `4104`
- Indicators: `Get-ADUser`, `Get-ADGroup`, `Get-ADGroupMember`
- Primary ATT&CK mapping for the verified test: `T1087.002` (Domain Account)

Only `Get-ADUser` was verified by the live positive test.
The other two cmdlets are included in the regex but have not
been independently regression-tested.

### Detection Gap and Tuning History

Initial custom Rule 100506 did not generate alerts even though
PowerShell Event 4104 was present in Wazuh archives.

Investigation:
1. Verified native Windows telemetry and Wazuh raw ingestion.
2. Confirmed Event Record 829 contained `Get-ADUser`.
3. Tested parent rules 60000 and 91801 without a live alert.
4. Investigated the built-in PowerShell ruleset.
5. Diagnostic logtest matched Rule 91802 for the archived event.
6. Changed Rule 100506 to inherit from Rule 91802.
7. Repeated the live test and confirmed Alert 100506.

**Finding:** Using parent Rule 91802 resolved the observed
Rule Matching Gap in this environment.

Built-in Wazuh rules were restored after diagnostic testing.

### Live Regression Results

| Test | PowerShell activity | Event Record | Alert 100506 | Result |
|---|---|---|---|---|
| Positive | `Get-ADUser` | 832 | Yes | PASS |
| Negative | `Get-Date` | 837 | No | PASS |

Positive timestamp: `2026-10-09 03:43:12.673 UTC`.

Negative timestamp: `2026-10-09 05:05:32.583 UTC`.

**Result: 2/2 controlled regression cases passed.**

Evidence:
[AD001-regression-20261009.json](../../evidence/ad-001/AD001-regression-20261009.json)

The evidence summary records event identifiers, timestamps,
detection outcomes and SHA-256 hashes of the archived raw events.
Original raw events remain on the Wazuh VM.

### SOC Analyst Triage — 5W1H

- **Who:** Identify the account and process responsible for enumeration.
- **What:** Review the exact PowerShell command and queried objects.
- **When:** Correlate the Event 4104 timestamp with nearby activity.
- **Where:** Confirm the source endpoint and target AD environment.
- **Why:** Determine whether the action was authorized administration.
- **How:** Examine Script Block Logging and surrounding process events.

Escalation requires additional evidence such as suspicious account
context, unauthorized access, credential abuse or lateral movement.

### Validation Boundaries and Limitations

- This was controlled enumeration inside an authorized lab.
- An enumeration alert does not by itself prove compromise.
- A legitimate administrator may trigger Rule 100506.
- The rule only covers matching PowerShell script text.
- It does not cover all LDAP queries, alternative tools or
  other possible Active Directory discovery techniques.
- Only one positive and one negative case were tested.
- No production precision, recall or false-positive rate is claimed.
- Kerberos Event IDs 4768 and 4769 were observed natively;
  corresponding Wazuh detection coverage remains unverified.

### Next Steps

1. Preserve the verified rule and regression evidence in Git.
2. Review additional benign PowerShell administration scenarios.
3. Expand AD discovery coverage with separate, controlled tests.
4. Develop AD-002 only after the AD-001 documentation is committed.
