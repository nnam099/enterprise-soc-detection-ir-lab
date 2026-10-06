# INC-002: Wazuh Rule 92213 False Positive Tuning

## 1. Alert Summary
- **Alert ID:** 1791274836.2534914
- **Rule ID:** 92213 (Level 15 - Critical)
- **Rule Description:** Executable file dropped in folder commonly used by malware
- **MITRE ATT&CK:** T1105 (Ingress Tool Transfer)
- **Timestamp:** 2026-10-06 08:20:34 UTC
- **Host:** SOC-WIN10 (192.168.50.20)
- **User:** SOC-LAB\nam.user

## 2. Investigation Details
- **Observed Behavior:** Sysmon Event ID 11 detected the creation of `Microsoft.CognitiveServices.Speech.core.dll`.
- **Parent Process:** `msedgewebview2.exe` (Microsoft Edge WebView2).
- **Target Path:** `AppData\Local\Temp\msedge_chrome_Unpacker_BeginUnzipping...`

## 3. Verdict & Reasoning
- **Verdict:** **Benign Positive (False Positive)**
- **Reasoning:** The file creation is a legitimate behavior of Microsoft Edge WebView2 unpacking temporary support files (Speech core DLL) for web rendering. The folder name `msedge_chrome_Unpacker_BeginUnzipping` confirms this is an automated browser process, not a malicious dropper. Rule 92213 is too broad as it flags *any* executable in Temp folders without checking the parent process reputation.

## 4. Remediation / Detection Improvement
- **Action:** Tune Wazuh Rule 92213 to exclude or lower the severity of this specific legitimate behavior to prevent alert fatigue.
- **Implementation:** Add a child rule in `local_rules.xml` to match Rule 92213 AND `msedgewebview2.exe`, setting the level to 3 (or 0).

## 5. Evidence
- Screenshot: `../../screenshots/phase4-incident/inc002-wazuh-alert-raw.png`
