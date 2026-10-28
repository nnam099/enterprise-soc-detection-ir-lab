# Cloud Deployment Validation — Hybrid Cloud SOC Lab — 2026-10-27

**Scope:** Verify the end-to-end hybrid cloud telemetry path defined by *Recommendation #1*: an AWS Free-Tier EC2 workload reporting to the on-prem Wazuh SIEM over Tailscale, plus AWS native logs (CloudTrail + VPC Flow Logs) streamed to S3 and pulled by the on-prem manager via the `aws-s3` wodle.

**Host:** Parrot Security (analyst workstation), `nnam09` (authorized)
**Cloud:** AWS account `411109262083`, region `ap-southeast-2` (Sydney)
**Method:** Manual AWS Management Console provisioning + AWS CLI (run from EC2) + SSH. No Terraform was used for the deployed resources.
**Result:** **PASS** — agent Active, AWS logs ingested, custom rule 100508 validated. GuardDuty **blocked** by an org Service Control Policy (documented below).

---

## 1. Deployed Components

| Component | Identifier | Notes |
|---|---|---|
| EC2 workload | `SOC-AWS-01` | `t3.micro`, Ubuntu 24.04.5 LTS, 16 GiB gp3 |
| VPC | `SOC-LAB-VPC` (`vpc-0347ee883102f313b`) | `10.20.0.0/16`, subnet `10.20.1.0/24` |
| EC2 private / public IP | `10.20.1.10` / `54.252.238.201` | SSH scoped to analyst IP only |
| Tailscale nodes | `soc-aws-01` `100.101.95.40` · `soc-wazuh` `100.80.140.56` · `parrot-soc` `100.89.43.28` | mesh, outbound-only |
| S3 bucket | `soc-hybrid-logs-411109262083` | block-public, SSE-S3, 90-day lifecycle |
| CloudTrail | `soc-hybrid-trail` | multi-region, global events, log-file validation |
| VPC Flow Logs | `fl-0422e945f4c1d8625` | `ALL` traffic → S3 |
| GuardDuty | — | **blocked** (see §6) |
| IAM | `soc-admin` (setup) · `soc-hybrid-wazuh-reader` (least-privilege S3 read) | — |
| Wazuh agent | `003` `SOC-AWS-01` | → `100.80.140.56` (SOC-WAZUH over Tailscale) |
| Wazuh wodle | `aws-s3` (`cloudtrail` + `vpcflow`) | profile `wazuh-aws` |

---

## 2. Wazuh Agent 003 (cloud workload) — Active

```text
$ sudo /var/ossec/bin/agent_control -l
   ID: 000, Name: soc-wazuh (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: SOC-WIN10, IP: any, Disconnected
   ID: 002, Name: SOC-DC01, IP: any, Disconnected
   ID: 003, Name: SOC-AWS-01, IP: any, Active
```

Agent-side connection evidence (`/var/ossec/logs/ossec.log` on EC2):

```text
wazuh-agentd: INFO: Valid key received
wazuh-agentd: INFO: (4102): Connected to the server ([100.80.140.56]:1514/tcp).
```

| Check | Result |
|---|---|
| EC2 → SOC-WAZUH reachable over Tailscale (1514/1515) | PASS |
| Agent enrolled as ID 003 | PASS |
| Agent `Active` on manager | PASS |

---

## 3. AWS Native Logs → S3

```text
$ aws cloudtrail get-trail-status --name soc-hybrid-trail
  IsLogging: true

$ aws s3 ls s3://soc-hybrid-logs-411109262083/AWSLogs/411109262083/ --recursive
  CloudTrail/ap-southeast-2/.../411109262083_CloudTrail_ap-southeast-2_..._0445Z_....json.gz
  vpcflowlogs/ap-southeast-2/.../fl-0422e945f4c1d8625_..._0440Z_....log.gz
  vpcflowlogs/ap-southeast-2/.../fl-0422e945f4c1d8625_..._0445Z_....log.gz
```

| Source | Delivered to S3 |
|---|---|
| CloudTrail (IAM/API) | PASS |
| VPC Flow Logs (network) | PASS |

---

## 4. Wazuh `aws-s3` Module Ingestion

```text
wazuh-modulesd:aws-s3: INFO: Module AWS started
wazuh-modulesd:aws-s3: INFO: Executing Bucket Analysis: (Bucket: soc-hybrid-logs-411109262083, Type: cloudtrail, Profile: wazuh-aws)
wazuh-modulesd:aws-s3: INFO: Executing Bucket Analysis: (Bucket: soc-hybrid-logs-411109262083, Type: vpcflow, Profile: wazuh-aws)
wazuh-modulesd:aws-s3: INFO: Fetching logs finished.
```

Archives (all decoded events, not only alerts) at first sampling:

| Event source | Count in `archives.json` |
|---|---|
| CloudTrail | 8 |
| VPC Flow Logs | 3 |

No credential or `AccessDenied` errors — the `wazuh-aws` profile authenticated successfully.

---

## 5. Detection — Built-in 80202 + Custom 100508

### 5.1 Built-in rule 80202 (level 3) fired on live CloudTrail

```text
2026-10-27T04:50:43 | rule 80202 | lvl 3 | AWS Cloudtrail: iam.amazonaws.com - CreateUser.
2026-10-27T04:50:43 | rule 80202 | lvl 3 | AWS Cloudtrail: iam.amazonaws.com - CreateAccessKey.
```

### 5.2 Custom rule 100508 (level 10) — validated via `wazuh-logtest`

Deployed to `/var/ossec/etc/rules/aws_rules.xml`; source committed at
[`detections/wazuh/rules/100508-aws-iam.xml`](../../detections/wazuh/rules/100508-aws-iam.xml).

```text
**Phase 3: Completed filtering (rules).
    id: '100508'
    level: '10'
    description: 'SOC Lab: AWS IAM account or access key created in the cloud control plane'
    mitre.id: '['T1136.001', 'T1098.001']'
    mitre.tactic: '['Persistence']'
    mitre.technique: '['Local Account', 'Additional Cloud Credentials']'
    pci_dss: '['10.2.1', '10.2.5']'
    nist_800_53: '['AU.6']'
**Alert to be generated.
```

Rule 100508 elevates `CreateUser`/`CreateAccessKey` (parent rule 80202) from level 3 to
level 10 with MITRE ATT&CK **T1136.001** (Create Account: Cloud Account) and **T1098.001**
(Account Manipulation: Additional Cloud Credentials).

| Detection | Method | Result |
|---|---|---|
| Rule 80202 (live CloudTrail) | live ingestion | PASS |
| Rule 100508 (level 10) | `wazuh-logtest` + live (2026-10-27 05:15:20) | PASS |

### 5.3 Raw evidence files (SHA-256 verified)

Captured from SOC-WAZUH and committed with a manifest (`SHA256SUMS.txt`):

| File | Contents |
|---|---|
| `CLOUD-rule-100508-alerts.jsonl` | Live level-10 alert from the custom rule |
| `CLOUD-rule-80202-alerts.jsonl` | CloudTrail IAM lifecycle: CreateUser → CreateAccessKey → PutUserPolicy → DeleteAccessKey → DeleteUser → StopInstances |
| `CLOUD-rule-80401-alerts.jsonl` | VPC Flow Log alerts (5-line sample of 14,172) |
| `CLOUD-aws-s3-module.log` | `aws-s3` module runs (cloudtrail + vpcflow) |
| `CLOUD-tailscale-status.txt` | Tailscale mesh (SOC-WAZUH view) |
| `CLOUD-agent-003-status.txt` | `agent_control -l` output |

---

## 6. GuardDuty — Blocked by Service Control Policy

GuardDuty could not be enabled. The account is a member of AWS Organization `o-cwcc4rfgqn`,
and a Service Control Policy explicitly denies GuardDuty actions:

```text
An error occurred (AccessDeniedException) when calling the ListDetectors operation:
User: arn:aws:iam::411109262083:user/soc-admin is not authorized to perform: guardduty:ListDetectors ...
with an explicit deny in a service control policy: .../service_control_policy/p-zimswo7d
```

**Impact:** GuardDuty findings are out of scope for this deployment until the org
management account lifts the SCP. CloudTrail + VPC Flow Logs provide the control-plane and
network telemetry in the meantime.

---

## 7. Cost & Security Notes

- **Cost:** EC2 `t3.micro` (Free Tier 750 h/mo) + 16 GiB gp3 EBS (~$1.3/mo); S3 < 5 GB
  (Free Tier); CloudTrail first copy + Flow Logs = $0. GuardDuty not enabled.
- **Secrets in transit:** the `soc-admin` access key and sudo passwords were exchanged in
  chat during setup and **must be rotated/deactivated**.
- **Least privilege:** the on-prem reader (`soc-hybrid-wazuh-reader`) has only
  `s3:ListBucket`/`s3:GetObject` on the log bucket.

---

## 8. Limitations

- GuardDuty not enabled (SCP block) — see §6.
- EC2 `SOC-AWS-01` was stopped at 2026-10-28 00:20 (CloudTrail `StopInstances`), so agent 003
  shows `Disconnected` at capture time. It was `Active` during deployment on 2026-10-27.
- The VPC Flow Log integration generated 14,172 rule-80401 alerts in ~24 h; only a 5-line
  sample is committed (noise/tuning opportunity).
- No screenshots (dashboard/console) — manual capture outstanding.

---

## 9. Reproduce

```bash
# 1. Boot SOC-WAZUH and confirm Tailscale + agent:
./automation/lab-connectivity-check.sh

# 2. AWS-side read-only check (from the analyst host, AWS_CLI configured):
SOC_CLOUD_BUCKET=soc-hybrid-logs-411109262083 ./automation/cloud-check.sh

# 3. Verify the custom rule replay:
sudo /var/ossec/bin/wazuh-logtest < captured-cloudtrail-event.json
```

---

*Generated 2026-10-27. All actions were authorized, non-destructive, and scoped to the lab AWS account.*
