# DFIR-002 — Acquisition Report

## 1. Identification

| Field | Value |
|---|---|
| Case ID | DFIR-002 |
| Source endpoint | WIN10-01 |
| Platform | Windows 10 |
| Acquisition method | Live logical acquisition |
| Acquisition date | 2026-10-09 UTC |
| Collector | Elevated Windows PowerShell session |
| Evidence storage | Local endpoint, outside Git repository |

The collection used native Windows tools: `wevtutil.exe`,
`Get-WinEvent`, `Copy-Item`, and `Get-FileHash`.

## 2. EVTX Collection

| Channel | Exported filename | Size (bytes) |
|---|---|---:|
| Security | Security.evtx | 13,701,120 |
| Sysmon Operational | Sysmon-Operational.evtx | 25,235,456 |
| PowerShell Operational | PowerShell-Operational.evtx | 15,798,272 |

All three exports:
- Completed without reported errors.
- Were readable using `Get-WinEvent -Path`.
- Passed SHA-256 comparison against the acquisition manifest.

## 3. Log Retention Coverage

| EVTX | Oldest UTC | Newest UTC |
|---|---|---|
| Security | 2026-09-27 21:59:55 | 2026-10-09 01:21:36 |
| Sysmon | 2026-09-28 02:02:34 | 2026-10-09 01:22:24 |
| PowerShell | 2026-10-02 04:52:46 | 2026-10-09 01:21:35 |

Retention coverage does not guarantee that every historical event
remains present.

## 4. Prefetch Collection

- Source: `C:\Windows\Prefetch`
- File type: `.pf`
- Files enumerated at collection time: 255
- Files collected: 255
- Aggregate size: 5,089,043 bytes
- Post-collection SHA-256 checks: 255/255 PASS

No Prefetch filenames matched the initial
`POWERSHELL|CMD|WSMPROVHOST|PWSH` search filter.
This does not establish that these executables never ran.

## 5. Amcache Attempt

- Source: `C:\Windows\AppCompat\Programs\Amcache.hve`
- Observed file size: 2,359,296 bytes
- Direct `Copy-Item` failed due to an active file lock.
- No Amcache copy was acquired.
- VSS services existed, but no shadow copy was available.
- No new VSS snapshot was created.

## 6. Acquisition Limitations

This was live logical acquisition, not a forensic disk image.
Files and event logs may change during collection.
The original acquisition-time state was not independently preserved.
No complete chain of custody or disk-wide integrity claim is made.
