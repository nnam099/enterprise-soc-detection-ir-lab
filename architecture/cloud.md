# Cloud Integration (Planned)

**Status:** PLANNED — no cloud component is deployed or represented in this repository as of 2026-10-26.

This document defines the design and acceptance criteria for extending the on-premises lab into a hybrid/cloud topology. Nothing in this document should be read as a deployed configuration until the checklist in [Acceptance Criteria](#acceptance-criteria) is complete and linked evidence is committed.

---

## Why Add a Cloud Component

| Goal | What it demonstrates |
|---|---|
| Hybrid telemetry path | Windows endpoint → cloud Wazuh manager over TLS |
| Cloud network security | Least-privilege security groups, private subnets, no public management ports |
| Identity in the cloud | SSH/SSM access control, key lifecycle, audit trail |
| Reproducibility | Infrastructure described as code or as a runbook, not manual console clicks |

---

## Supported Design Options

### Option A — Cloud Wazuh manager (recommended for detection portfolio value)

```text
SOC-WIN10 (on-prem / NAT)
   │  TLS 1514/tcp (agent → manager)
   ▼
Cloud Wazuh (EC2, private subnet)
   ├─ Wazuh Manager + Indexer
   ├─ Dashboard behind authenticated reverse proxy (no public 9200)
   └─ Access only via SSM Session Manager or WireGuard
```

- Agents authenticate with enrollment credentials; do not expose `1514/1515` to `0.0.0.0/0`.
- Dashboard access through an authenticated proxy or VPN, never direct public exposure.
- Indexer `9200` stays on localhost/private subnet.

### Option B — Cloud jump host only

- Minimal EC2 instance used solely as an administrative jump point.
- No SIEM data leaves the lab.
- Lowest cost, lowest portfolio value; must still be documented and reproducible.

### Option C — Fully local (status quo)

- Keep the lab isolated and document cloud as out of scope.
- Acceptable, but then remove "planned cloud" language from the portfolio to avoid ambiguity.

---

## Non-Negotiable Security Requirements

| Requirement | Rule |
|---|---|
| Management access | No public SSH (`22/tcp`) from `0.0.0.0/0`. Use AWS SSM Session Manager or a VPN, or restrict the security group to a single trusted IP. |
| Key management | Private keys live in `~/.ssh/` with mode `600`, never in `~/Downloads`, never in Git, never in chat/evidence. |
| Dashboard exposure | HTTPS only, authenticated; no public `9200`, no default credentials. |
| Agent traffic | TLS-enabled enrollment; restrict `1514/1515` to known source IPs. |
| Logging | CloudTrail + VPC Flow Logs enabled and retained. |
| Cost control | Budget alarm and instance stop schedule documented. |
| Evidence | Screenshots/logs proving each control, plus SHA-256 manifest. |

---

## Required Documentation When Deployed

Add the following to this file (or a new case study) before linking it from the README:

1. Region, AZ, instance type, AMI, and storage.
2. VPC/subnet layout and security group rules (direction, port, source).
3. Access path diagram (SSM/VPN) and authentication method.
4. Wazuh version, component layout, and agent enrollment procedure.
5. Data flow and retention.
6. Cost estimate and teardown procedure.

Do **not** commit: private keys, `.pem` files, dashboard passwords, API tokens, or unredacted public IPs if they identify a live host.

---

## Acceptance Criteria

- [ ] Cloud resources are reproducible from code (Terraform/CloudFormation) **or** a complete step-by-step runbook.
- [ ] Security group allows management access only from SSM/VPN/trusted IP.
- [ ] No public `22`, `9200`, or `55000`.
- [ ] Wazuh dashboard reachable over HTTPS with a non-default admin password.
- [ ] At least one endpoint (SOC-WIN10 or a cloud agent) reports **Active** for 24 hours.
- [ ] At least one detection rule fires on cloud-ingested telemetry and is captured as evidence.
- [ ] Architecture diagram updated in [`topology.md`](topology.md).
- [ ] Evidence manifest with SHA-256 hashes added under `evidence/` (or an incident case).
- [ ] Teardown/stop procedure tested and documented.

---

## Current State

| Item | Status |
|---|---|
| Cloud account / region | Not documented in this repository |
| Deployed cloud resources | None claimed |
| Cloud evidence in repo | None |
| On-prem lab status | Operational; connectivity verified 2026-10-26 |

Until the acceptance criteria are met, treat cloud as **out of scope** in portfolio claims.
