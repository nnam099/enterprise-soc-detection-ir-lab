# SOC-INC-001 — Run Key Current-State Verification

## Result

On 2026-10-07T05:51:59.2292509Z, the analyst verified that the
SOC-INC-001 value was absent from the loaded nam.user Registry Run key.

This establishes the current state of the specific value.
It does not establish when it was deleted, who deleted it, or whether
it remained absent throughout the period since the original simulation.

## Scope

- Observed hostname: WIN10-01
- Inspection operator: WIN10-01\localadmin
- Target account profile: C:\Users\nam.user
- Target SID: S-1-5-21-1324826322-2293316327-2538204677-1108
- Target hive: loaded
- Run key: present
- Value name: SOC-INC-001
- Value present: False

The inspection used the target SID under HKEY_USERS rather than
the inspection operator's HKCU.

## Evidence

- [Current-state record](evidence/recovery/runkey-current-state.json)
- [SHA-256 manifest](evidence/recovery/SHA256SUMS.txt)

The transferred record matched its Windows source SHA-256:

    8223418f591de696e965c817275068f444506c3aa46e499719e20f9231203258

## Limitations

No registry modification was performed during this check.
Historical deletion telemetry remains unverified.
Other persistence locations and sustained recurrence monitoring were
not assessed by this check. Full incident closure remains open.
