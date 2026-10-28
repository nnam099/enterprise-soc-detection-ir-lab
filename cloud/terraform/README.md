# Terraform — SOC Hybrid (On-Prem Wazuh + AWS Free Tier)

Reproducible AWS infrastructure for **Recommendation #1**: keep the Wazuh SIEM
on-prem, add a Free-Tier EC2 workload with a Wazuh agent (connected over
Tailscale), and stream AWS native logs (CloudTrail, VPC Flow Logs, GuardDuty)
into a single S3 bucket that `SOC-WAZUH` pulls via the `aws-s3` wodle.

## What this deploys

| Resource | Purpose | Free Tier? |
|---|---|---|
| `aws_vpc` + subnet + IGW | Minimal network | Free |
| `aws_security_group` (no inbound) | Zero public management surface | Free |
| `aws_instance` `t3.micro` Ubuntu 24.04 | Web/app workload + Wazuh agent | Free (750 h/mo) |
| `aws_iam_role` + SSM attach | Session Manager shell access (no SSH) | Free |
| `aws_s3_bucket` + encryption + lifecycle | Single log bucket | Free (5 GB) |
| `aws_cloudtrail` | IAM/API control-plane logs | Free (first copy) |
| `aws_flow_log` | VPC network logs | Free |
| `aws_guardduty_detector` + publishing dest | Threat findings → S3 | 30-day trial, then low |
| `aws_kms_key` | SSE-KMS for GuardDuty findings | **~$1/month** (only paid line) |
| `aws_iam_user` (wazuh-reader) + access key | Least-privilege S3 read for SOC-WAZUH | Free |

## Usage

```bash
cd cloud/terraform

# 1. Provide values (secrets only here, never committed)
cat > terraform.tfvars <<'EOF'
region                       = "ap-southeast-2"
wazuh_manager_ip             = "100.x.y.z"        # SOC-WAZUH Tailscale IP
wazuh_agent_name             = "SOC-AWS-01"
wazuh_registration_password  = "<authd password>"
tailscale_authkey            = "tskey-auth-..."
EOF

# 2. Plan and apply
terraform init
terraform plan
terraform apply

# 3. Retrieve outputs (secrets are marked sensitive)
terraform output log_bucket
terraform output wazuh_reader_access_key_id
terraform output wazuh_reader_secret_access_key
```

> **Security note:** `aws_iam_access_key` writes its secret into Terraform state.
> Protect the state file (remote backend with encryption) or, for a stronger
> posture, omit that resource and create the key manually:
> `aws iam create-access-key --user-name soc-hybrid-wazuh-reader`.

## Variables

See [`variables.tf`](variables.tf). Secrets (`wazuh_registration_password`,
`tailscale_authkey`) are sensitive and must be supplied via `terraform.tfvars`
or environment, never committed.

## Teardown

```bash
terraform destroy
```

S3 is not force-destroyed, so `terraform destroy` will fail if the log bucket
still holds objects. Empty it first, or run with a targeted plan:

```bash
aws s3 rm s3://<log_bucket> --recursive
terraform destroy
```
