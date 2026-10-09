# Portfolio Evidence Gaps

Evidence and screenshots that require manual collection to strengthen the portfolio.

## Missing Configuration Artifacts

| Item | Expected Location | What to Capture |
|---|---|---|
| Sysmon configuration XML | `configs/sysmon/sysmonconfig.xml` | Export the active Sysmon config from SOC-WIN10 |
| Windows audit policy export | `configs/windows-auditing/audit-policy.csv` | Run `auditpol /get /category:*` on SOC-WIN10 and SOC-DC01 |

## Missing or Empty Directories

| Directory | Current Status | Recommended Action |
|---|---|---|
| `detections/sigma/` | Empty | Write Sigma YAML equivalents for rules 100501–100504 |
| `playbooks/` | Empty | Create Markdown IR playbooks for encoded PowerShell and persistence |
| `attacks/` | Empty | Document controlled simulation scripts used in SOC-INC-001 |
| `configs/sysmon/` | Empty | Export and commit the active Sysmon configuration |
| `configs/windows-auditing/` | Empty | Export and commit the Windows audit policy |
| `automation/` | Empty | Add any automation scripts used for evidence collection |
| `investigations/` | Empty | Move or link relevant investigation content |

## Unverified Evidence Branches

| Item | Current Status | What Is Needed |
|---|---|---|
| INC-002 live WebView2 positive branch | Predicate/replay passed; live event unverified | Trigger a matching WebView2 file creation and capture the Wazuh alert at level 3 |
| Sysmon Event 5 process termination | Not found in response replay | Capture Sysmon Event 5 for a future process termination exercise |
| Historical Run Key deletion time/actor | Unknown | Not recoverable unless registry auditing captured the deletion |
| Endpoint Event 4624 for post-restoration auth | Not yet incorporated | Export Event 4624 from SOC-WIN10 for the October 7 authentication |
| Session revocation verification | Not tested | Test failed authentication while account is disabled |

## Screenshots That Would Strengthen the Portfolio

| Suggested Screenshot | Purpose | Recommended Path |
|---|---|---|
| Sysmon operational log on SOC-WIN10 | Show raw Sysmon telemetry source | `screenshots/phase2-wazuh/sysmon-operational-log.png` |
| HUNT-002 failed logon burst in Wazuh | Show rule 100503 correlation | `screenshots/phase3-detection/hunt002-failed-logon-burst.png` |
| DFIR timeline verification output | Show `verify_case.py` passing | `screenshots/phase6-ai/dfir-001-verify-pass.png` |
| Wazuh custom rules editor view | Show deployed rules in dashboard | `screenshots/phase2-wazuh/wazuh-custom-rules-editor.png` |
| INC-002 before/after comparison | Show severity change side-by-side | `screenshots/phase4-incident/inc002-before-after-comparison.png` |

## Forensic Artifact Status & Limitations (DFIR-002)

| Artifact / Operation | Status | Details & Forensic Boundaries |
|---|---|---|
| Native Windows EVTX | ✅ 3 channels acquired & verified | Security (13.7 MB), Sysmon-Operational (25.2 MB), PowerShell-Operational (15.8 MB). All passed `Get-WinEvent` readback and SHA-256 checks. |
| Windows Prefetch (`.pf`) | ✅ 255 files acquired & verified | 255/255 files passed SHA-256 verification (~5.09 MB total). No filename matches for `POWERSHELL|CMD|WSMPROVHOST|PWSH` in initial filter (does not prove absence of execution). |
| Aggregate Evidence Manifest | ✅ 261 files verified | 261/261 files passed SHA-256 check against `SHA256SUMS.txt` on WIN10-01 (zero mismatches). |
| Native Sysmon Correlation | ✅ 2 historical events corroborated | Corroborated HUNT-003 (Event ID 1, Record ID 7366) and HUNT-004 (Event ID 13, Record ID 7380) with ProcessGuid matches. Derived artifact: `native-correlation.json`. |
| Amcache (`Amcache.hve`) | ❌ Unacquired (OS File Lock) | `C:\Windows\AppCompat\Programs\Amcache.hve` (~2.36 MB) locked by active Windows OS. Direct copy failed; VSS existed but no shadow snapshot was taken. |
| Attack Chain / Compromise Proof | ⚠️ Non-Attribution Boundary | Corroborating independent hunting records confirms telemetry fidelity, but does not prove real compromise, persistence execution, or a continuous attack chain. |

## Integrity Verification Gaps

| Item | Status |
|---|---|
| SOC-INC-001: 17/17 artifacts across 5 manifests | ✅ Verified |
| INC-002 evidence SHA256SUMS | ✅ Present |
| DFIR-001 SHA256SUMS (10 sources + 3 timelines) | ✅ Present |
| DFIR-002 SHA256SUMS (261 files: 3 EVTX + 255 Prefetch + 3 metadata/manifests) | ✅ Verified (261/261 PASS) |
| Encoded PowerShell test SHA256SUMS (14 artifacts) | ✅ Present |
| Original acquisition-time hashing | ❌ Not established for any evidence set |
| VM backup integrity (boot test) | ❌ Not performed |
| VSS shadow copy acquisition (Amcache / locked hives) | ❌ Not performed |

---

*Generated on 2026-10-09. This checklist should be updated as evidence is collected.*
