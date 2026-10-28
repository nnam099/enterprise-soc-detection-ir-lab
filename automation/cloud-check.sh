#!/usr/bin/env bash
set -uo pipefail

REGION="${AWS_REGION:-ap-southeast-2}"
BUCKET="${SOC_CLOUD_BUCKET:-soc-hybrid-logs-411109262083}"
INST_TAG="SOC-AWS-01"
TS_HOST="soc-aws-01"

JSON=0
[ "${1:-}" = "--json" ] && JSON=1
[ "${1:-}" = "--help" ] && { echo "usage: $0 [--json]"; exit 0; }

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found" >&2; exit 2; }

PASS=0; FAIL=0; SKIP=0
declare -a RESULTS=()

record() {
  local status="$1" check="$2" detail="$3"
  case "$status" in
    PASS) PASS=$((PASS+1)) ;;
    FAIL) FAIL=$((FAIL+1)) ;;
    SKIP) SKIP=$((SKIP+1)) ;;
  esac
  RESULTS+=("$status|$check|$detail")
}

IDENT="$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)"
if [ -n "$IDENT" ]; then
  record PASS "AWS identity" "account $IDENT"
else
  record FAIL "AWS identity" "aws sts get-caller-identity failed"
  if [ "$JSON" -eq 1 ]; then
    printf '{"passed":%d,"failed":%d,"skipped":%d,"checks":[' "$PASS" "$FAIL" "$SKIP"
    printf '{"status":"FAIL","check":"AWS identity","detail":"no credentials"}]}\n'
  else
    echo "FAIL AWS identity"
  fi
  exit 1
fi

if aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null 2>&1; then
  record PASS "S3 bucket" "$BUCKET exists"
  for svc in CloudTrail vpcflowlogs; do
    n="$(aws s3 ls "s3://$BUCKET/AWSLogs/$IDENT/$svc/" --recursive --summarize 2>/dev/null \
           | awk '/Total Objects:/{print $3}' | head -1)"
    if [ -n "$n" ] && [ "$n" -gt 0 ]; then
      record PASS "S3 $svc" "$n object(s)"
    else
      record SKIP "S3 $svc" "no objects yet"
    fi
  done
else
  record FAIL "S3 bucket" "$BUCKET not reachable"
fi

CT="$(aws cloudtrail describe-trails --region "$REGION" \
        --query "trailList[?Name=='soc-hybrid-trail']" --output json 2>/dev/null || true)"
if [ -n "$CT" ] && [ "$CT" != "[]" ]; then
  LOGGING="$(aws cloudtrail get-trail-status --name soc-hybrid-trail --region "$REGION" \
               --query 'IsLogging' --output text 2>/dev/null || echo false)"
  [ "$LOGGING" = "true" ] \
    && record PASS "CloudTrail" "soc-hybrid-trail logging" \
    || record FAIL "CloudTrail" "soc-hybrid-trail present but IsLogging=$LOGGING"
else
  record SKIP "CloudTrail" "soc-hybrid-trail not found"
fi

FL="$(aws ec2 describe-flow-logs --region "$REGION" --query 'FlowLogs[].FlowLogId' --output text 2>/dev/null || true)"
if [ -n "$FL" ]; then
  record PASS "VPC Flow Logs" "$(echo "$FL" | wc -w) flow log(s)"
else
  record SKIP "VPC Flow Logs" "none found"
fi

INST="$(aws ec2 describe-instances --region "$REGION" \
          --filters "Name=tag:Name,Values=$INST_TAG" \
          --query 'Reservations[].Instances[].State.Name' --output text 2>/dev/null || true)"
if [ -n "$INST" ]; then
  [ "$INST" = "running" ] \
    && record PASS "EC2 instance" "$INST_TAG running" \
    || record FAIL "EC2 instance" "$INST_TAG state=$INST"
else
  record SKIP "EC2 instance" "$INST_TAG not found"
fi

SSM="$(aws ssm describe-instance-information --region "$REGION" \
         --query 'InstanceInformationList[].PingStatus' --output text 2>/dev/null || true)"
if [ -n "$SSM" ]; then
  [ "$SSM" = "Online" ] \
    && record PASS "SSM managed" "EC2 online" \
    || record FAIL "SSM managed" "ping status=$SSM"
else
  record SKIP "SSM managed" "no managed instances reported"
fi

if command -v tailscale >/dev/null 2>&1; then
  TS="$(tailscale status 2>/dev/null | grep -c "$TS_HOST" || true)"
  [ "$TS" -gt 0 ] \
    && record PASS "Tailscale" "$TS_HOST present on tailnet" \
    || record SKIP "Tailscale" "$TS_HOST not in local tailscale status"
else
  record SKIP "Tailscale" "tailscale CLI not installed here"
fi

if [ "$JSON" -eq 1 ]; then
  printf '{"passed":%d,"failed":%d,"skipped":%d,"checks":[' "$PASS" "$FAIL" "$SKIP"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st chk det <<< "$r"
    [ "$first" -eq 0 ] && printf ','
    first=0
    printf '{"status":"%s","check":"%s","detail":"%s"}' "$st" "$chk" "$det"
  done
  printf ']}\n'
else
  echo "SOC Cloud Check — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "------------------------------------------------------------"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st chk det <<< "$r"
    printf '%-4s %-16s %s\n' "$st" "$chk" "$det"
  done
  echo "------------------------------------------------------------"
  echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
fi

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
