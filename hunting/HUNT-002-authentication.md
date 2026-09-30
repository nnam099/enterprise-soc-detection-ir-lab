# HUNT-002 — Authentication Anomalies

## 1. Hunt Information

- **Hunt ID:** HUNT-002
- **Title:** Authentication Anomalies
- **Environment:** SOC-LAB
- **Endpoint:** SOC-WIN10 / WIN10-01
- **SIEM:** Wazuh
- **Primary Data Source:** Windows Security Event Log
- **Hunt Status:** Completed
- **MITRE ATT&CK:** T1110 — Brute Force

---

## 2. Hypothesis

Repeated authentication failures against the same account within a short
time window may indicate password guessing, brute-force activity, a
misconfigured service, or repeated user authentication errors.

Successful authentication events must also be reviewed in context because
different Windows logon types represent different authentication activity.

The purpose of this hunt is to determine whether Windows authentication
telemetry collected by Wazuh provides sufficient information to identify
and investigate authentication anomalies.

---

## 3. Data Sources

The hunt used the following telemetry:

- Windows Security Event ID 4625 — Failed Logon
- Windows Security Event ID 4624 — Successful Logon
- Wazuh Windows EventChannel telemetry
- Wazuh built-in authentication detection rule 60122
- SOC-LAB custom correlation rule 100503

Relevant authentication fields include:

- Target username
- Target domain
- Logon type
- Source IP address
- Authentication package
- Logon process
- Status and substatus codes
- Event timestamp

---

## 4. Hunt Workflow

The investigation followed the workflow:

Hypothesis → Search → Evidence → Context Analysis → Finding → Detection Recommendation

The hunt consisted of three separate validation and analysis activities:

1. Review individual failed authentication telemetry.
2. Generate controlled repeated authentication failures and validate correlation.
3. Review a successful authentication event and its Windows logon context.

These activities are separate validation cases and are not presented as a
single attack chain.

---

## 5. Test Case 1 — Individual Failed Authentication

### Objective

Determine whether a single Windows failed authentication attempt is
collected and detected by Wazuh.

### Observation

Windows generated Security Event ID 4625 for failed authentication
activity.

Wazuh processed the event using built-in rule:

- **Rule ID:** 60122
- **Level:** 5
- **Description:** Logon Failure - Unknown user or bad password

During the controlled HUNT-002 validation, the following authentication
context was observed:

- **Target User:** hunt002-test
- **Target Domain:** WIN10-01
- **Logon Type:** 3
- **Source Address:** 127.0.0.1
- **Authentication Package:** NTLM
- **Logon Process:** NtLmSsp
- **Status:** 0xC000006D
- **Substatus:** 0xC0000064

### Analysis

Logon Type 3 represents a network logon.

The failed authentication was generated locally through a network
authentication path using the loopback address 127.0.0.1.

The account `hunt002-test` was intentionally used as a lab validation
identity and did not represent a legitimate production user.

A single failed authentication event alone is insufficient to conclude
that brute-force activity occurred.

### Evidence

`hunting/evidence/HUNT-002/HUNT-002-rule-60122.json`

---

## 6. Test Case 2 — Repeated Failed Authentication Correlation

### Objective

Validate whether repeated authentication failures against the same
username can be correlated into a higher-severity detection.

### Controlled Validation

Five failed authentication attempts were intentionally generated within
the configured detection window.

All attempts targeted:

`WIN10-01\hunt002-test`

This activity was generated only for detection validation inside the
isolated SOC lab.

### Custom Detection Rule

The SOC-LAB custom Wazuh rule is configured as:

- **Rule ID:** 100503
- **Level:** 10
- **Parent Rule:** 60122
- **Frequency:** 5
- **Timeframe:** 60 seconds
- **Correlation Field:** win.eventdata.targetUserName
- **MITRE ATT&CK:** T1110 — Brute Force

Detection logic:

Five events matching Wazuh rule 60122 must occur within 60 seconds for the
same `targetUserName`.

### Detection Result

The custom rule successfully triggered.

Observed alert:

- **Rule ID:** 100503
- **Level:** 10
- **Target User:** hunt002-test
- **Target Domain:** WIN10-01
- **Logon Type:** 3
- **Source Address:** 127.0.0.1
- **Authentication Package:** NTLM
- **Logon Process:** NtLmSsp
- **MITRE ATT&CK:** T1110 — Brute Force

The alert description was:

`SOC Lab: Repeated Windows failed logons detected for account hunt002-test`

### Analysis

This validation demonstrates the difference between event-level detection
and correlation-based detection.

An individual failed logon generated rule 60122 at level 5.

Repeated failures against the same target username within the configured
time window caused rule 100503 to generate a level 10 alert.

The `same_field` condition is important because authentication failures
against unrelated usernames should not automatically be treated as one
password-guessing sequence.

### Evidence

`hunting/evidence/HUNT-002/HUNT-002-rule-100503.json`

---

## 7. Test Case 3 — Successful Authentication Context

### Objective

Review successful authentication telemetry and demonstrate why analysts
must interpret Windows Logon Type rather than treating every Event ID 4624
as equivalent.

### Observation

A Windows Security Event ID 4624 was collected for:

- **User:** nam.user
- **Domain:** SOC-LAB
- **Logon Type:** 7
- **Process:** C:\Windows\System32\lsass.exe
- **Authentication Package:** Negotiate

The event was generated in the context of unlocking the Windows
workstation.

### Analysis

Logon Type 7 represents workstation unlock activity.

This illustrates that Event ID 4624 only indicates creation or use of a
successful logon session; the event must be interpreted together with
fields such as:

- Logon Type
- Target User
- Source Address
- Authentication Package
- Process
- Timestamp

Other successful authentication events observed during the hunt included
different logon types, including Type 3 and Type 11.

Therefore, searching only for Event ID 4624 without considering Logon Type
can produce misleading conclusions.

### Evidence

`hunting/evidence/HUNT-002/HUNT-002-success-4624.json`

---

## 8. Authentication Correlation Analysis

The hunt demonstrated the following detection hierarchy:

Single failed authentication
        |
        v
Windows Security Event 4625
        |
        v
Wazuh Rule 60122
Level 5
        |
        | repeated failures
        | same target username
        | frequency = 5
        | timeframe = 60 seconds
        v
SOC-LAB Rule 100503
Level 10
MITRE ATT&CK T1110

This correlation reduces the need to treat every isolated authentication
failure as a high-priority security incident.

---

## 9. Findings

### HUNT-002-F01 — Windows failed authentication telemetry is available

Windows Security Event ID 4625 is successfully collected from SOC-WIN10
and processed by Wazuh.

---

### HUNT-002-F02 — Individual failed logons are detected

Wazuh built-in rule 60122 identifies individual failed authentication
attempts.

This provides useful event-level visibility but does not by itself prove
brute-force activity.

---

### HUNT-002-F03 — Repeated authentication failures can be correlated

Custom rule 100503 successfully correlated repeated failed logons for the
same target username.

Five matching failures inside a 60-second window generated a level 10
alert.

---

### HUNT-002-F04 — Authentication context is critical

Fields such as username, source address, Logon Type, authentication
package, status code, and timestamp are required to distinguish suspicious
authentication behavior from expected activity.

---

### HUNT-002-F05 — Successful logons require Logon Type analysis

Event ID 4624 cannot be interpreted as a generic interactive login.

During this hunt, successful authentication telemetry included multiple
Windows Logon Types.

The selected evidence demonstrated Logon Type 7 associated with workstation
unlock activity.

---

### HUNT-002-F06 — Detection does not automatically mean compromise

Rule 100503 correctly classified the controlled repeated authentication
failures under MITRE ATT&CK T1110.

However, the activity was intentionally generated for validation.

The alert therefore confirms detection capability, not a real compromise.

---

## 10. Detection Coverage

Current authentication detection coverage includes:

| Activity | Telemetry | Detection | Result |
|---|---|---|---|
| Single failed authentication | Event ID 4625 | Wazuh 60122 | Detected |
| Repeated failed authentication | Multiple 4625 events | Custom 100503 | Detected |
| Successful authentication | Event ID 4624 | Event telemetry / Wazuh processing | Observed |
| Same-user failure correlation | 60122 events | frequency + same_field | Validated |

---

## 11. Detection Recommendations

### Recommendation 1 — Retain rule 100503

The rule provides useful correlation beyond individual failed-logon
alerts and should remain enabled.

### Recommendation 2 — Include source context

Future detection engineering should consider correlation using:

- Target username
- Source IP address
- Host
- Logon Type

This can help distinguish repeated failures originating from one source
from unrelated authentication failures.

### Recommendation 3 — Monitor failure followed by success

A useful future hunting pattern is:

Repeated failed authentication
→ successful authentication
→ same account
→ same or related source
→ short time window

This pattern may provide stronger investigative context than failed
authentication alone.

It must still be reviewed by an analyst because legitimate password
mistakes followed by a successful login can produce similar telemetry.

### Recommendation 4 — Establish authentication baselines

Future hunting should establish expected authentication patterns for:

- Administrative accounts
- Domain users
- Service accounts
- Interactive logons
- Network logons
- Remote administration

Deviation from these baselines can then be prioritized for investigation.

---

## 12. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| T1110 | Brute Force | Repeated authentication failure detection |

The MITRE mapping represents the behavior covered by the detection rule.
It does not imply that the controlled lab validation was a real attack.

---

## 13. Evidence Summary

Evidence retained for HUNT-002:

### Individual Failed Authentication

`hunting/evidence/HUNT-002/HUNT-002-rule-60122.json`

Demonstrates Windows failed authentication detection through Wazuh rule
60122.

### Repeated Authentication Correlation

`hunting/evidence/HUNT-002/HUNT-002-rule-100503.json`

Demonstrates successful triggering of custom correlation rule 100503 after
repeated failed authentication attempts.

### Successful Authentication

`hunting/evidence/HUNT-002/HUNT-002-success-4624.json`

Demonstrates successful authentication telemetry for `SOC-LAB\nam.user`
with Windows Logon Type 7.

---

## 14. Hunt Result

**Result: Detection validated — no real compromise identified.**

The hunt successfully validated authentication visibility and correlation
capabilities in the SOC-LAB environment.

Windows failed authentication events were collected by Wazuh, individual
failures were identified by rule 60122, and repeated failures against the
same target username triggered custom rule 100503.

Successful authentication telemetry was also reviewed to demonstrate the
importance of Windows Logon Type and authentication context.

The repeated failed logons and successful authentication evidence were
generated or reviewed as separate test cases and must not be interpreted
as one attacker sequence.

---

## 15. Conclusion

HUNT-002 demonstrated that authentication investigation requires more than
searching for Event IDs 4624 and 4625.

A SOC analyst must correlate:

- Identity
- Source
- Logon Type
- Authentication mechanism
- Failure reason
- Frequency
- Time window
- Subsequent authentication behavior

The custom Wazuh correlation rule successfully increased the severity of
repeated failed authentication activity while preserving individual
failed-logon visibility through the built-in rule.

The hunt also reinforced a core SOC principle:

**An alert identifies behavior requiring analysis; it does not by itself
prove malicious activity or compromise.**
