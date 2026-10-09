# DFIR-002 — Windows Endpoint Artifact Acquisition

## Case Summary

- Case ID: DFIR-002
- Endpoint: WIN10-01 (SOC-WIN10)
- Case type: Controlled lab forensic acquisition and correlation
- Acquisition date: 2026-10-09 (UTC)
- Verdict: Acquisition and scoped correlation validated
- Incident status: No new compromise established

## Objective

Acquire native Windows forensic artifacts, verify their integrity,
and independently corroborate selected historical Wazuh hunting events.

## Workflow

1. Identify native Windows artifact sources.
2. Export Security, Sysmon and PowerShell EVTX logs.
3. Verify EVTX readback and SHA-256 integrity.
4. Collect available Prefetch files.
5. Generate an aggregate SHA-256 evidence manifest.
6. Correlate selected historical events using native Sysmon EVTX.
7. Record acquisition and investigation limitations.

## Reports

- [Acquisition Report](acquisition-report.md)
- [Correlation Report](correlation-report.md)
- [Evidence Manifest](evidence-manifest.md)

## Scope

This case complements DFIR-001 but does not merge the four independent
hunting exercises into a single attack chain.

Raw EVTX and Prefetch artifacts remain outside the public repository.
