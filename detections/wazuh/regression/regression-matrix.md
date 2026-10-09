# Wazuh Detection Regression Matrix v1

## Scope

This matrix verifies archived evidence collected during controlled
Windows PowerShell tests on 2026-10-07.

It is NOT a replay of the current Wazuh ruleset.

## Archived Evidence Tests

| Test | Behavior | Expected alert | Observed alert | Result |
|---|---|---|---|---|
| T01 | PowerShell parent, `-EncodedCommand` | 92057 / 12 | 92057 / 12 | PASS |
| T02 | CMD parent, `-EncodedCommand` | 100504 / 8 | 100504 / 8 | PASS |
| T03 | CMD parent, `-enc` | 100504 / 8 | 100504 / 8 | PASS |
| T04 | Ordinary `-Command` | No encoded detection | 92027 / 4 | PASS |

## Validation Criteria

For each test:

- Agent ID must be 001.
- Sysmon Event ID must be 1.
- Process ID must match the execution record.
- The unique test marker must be identifiable in both the
  archived alert and archive event.
- Positive tests must match the expected rule and level.
- T04 must not match encoded detection rules 100504 or 92057.

## Source Evidence

- [T01–T04 fixtures](../tests/encoded-powershell/)
- [Original validation notes](../tests/encoded-powershell/README.md)
- [SHA-256 manifest](../tests/encoded-powershell/SHA256SUMS.txt)
- [Verification runner](verify_archived_evidence.py)

## Pending Rule Regression

| Rule | Planned test | Status |
|---|---|---|
| 100001 | WebView2 positive replay and nonmatching file creation | Pending automated rule regression |
| 100501 | Run Key positive and negative fixtures | Pending |
| 100502 | WinRM parent-process positive and negative fixtures | Pending |
| 100503 | Five failed logons within 60 seconds; grouping negative test | Pending |
| 100504 | Current-rule replay using valid EventChannel input | Pending |
| 100505 | Destination filtering and parent rule 92101 verification | Pending |

Historical detection evidence for other rules is documented
elsewhere in the repository, but is not counted as a passing
regression test here.
