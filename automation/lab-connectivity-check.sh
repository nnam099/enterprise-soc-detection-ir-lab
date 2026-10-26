#!/usr/bin/env bash
# lab-connectivity-check.sh
#
# Read-only health check for the Enterprise SOC Detection & IR Lab.
# Starts/stops nothing and changes no configuration.
#
# Usage:
#   ./automation/lab-connectivity-check.sh
#   ./automation/lab-connectivity-check.sh --json
#
# Exit codes:
#   0 = all running components passed
#   1 = at least one check failed
#   2 = required tooling missing
#   3 = no lab VM is running (nothing to test)

set -uo pipefail

LIBVIRT_URI="${LIBVIRT_URI:-qemu:///system}"
TIMEOUT="${TIMEOUT:-3}"

DC_IP="192.168.50.10"
WIN_IP="192.168.50.20"
WAZUH_IP="192.168.50.30"

DC_MAC="52:54:00:7a:6b:db"
WIN_MAC="52:54:00:09:4e:58"
WAZUH_MAC="52:54:00:fe:8a:46"

JSON=0
[ "${1:-}" = "--json" ] && JSON=1
[ "${1:-}" = "--help" ] && { sed -n '2,17p' "$0"; exit 0; }

command -v virsh >/dev/null 2>&1 || { echo "ERROR: virsh not found" >&2; exit 2; }

PASS=0
FAIL=0
SKIP=0
declare -a RESULTS=()

record() { # status host check detail
  local status="$1" host="$2" check="$3" detail="$4"
  case "$status" in
    PASS) PASS=$((PASS+1)) ;;
    FAIL) FAIL=$((FAIL+1)) ;;
    SKIP) SKIP=$((SKIP+1)) ;;
  esac
  RESULTS+=("$status|$host|$check|$detail")
}

tcp_check() { # host port label
  local host="$1" port="$2" label="$3" attempt
  for attempt in 1 2 3; do
    if timeout "$TIMEOUT" bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
      record PASS "$host" "$label" "tcp/$port open"
      return
    fi
    [ "$attempt" -lt 3 ] && sleep 2
  done
  record FAIL "$host" "$label" "tcp/$port closed or filtered (3 attempts)"
}

arp_check() { # ip mac label
  local ip="$1" mac="$2" label="$3"
  ping -c 1 -W 1 "$ip" >/dev/null 2>&1 || true
  local entry
  entry="$(ip neigh show "$ip" 2>/dev/null || true)"
  if echo "$entry" | grep -qiE "REACHABLE|STALE|DELAY"; then
    if echo "$entry" | grep -qi "$mac"; then
      record PASS "$ip" "$label" "ARP reachable ($mac)"
    else
      record FAIL "$ip" "$label" "ARP resolves to unexpected MAC: $entry"
    fi
  else
    record FAIL "$ip" "$label" "no ARP entry"
  fi
}

vm_state() { # domain
  virsh -c "$LIBVIRT_URI" domstate "$1" 2>/dev/null || echo "undefined"
}

for vm in SOC-DC01 SOC-WIN10 SOC-WAZUH; do
  state="$(vm_state "$vm")"
  if [ "$state" = "running" ]; then
    record PASS "$vm" "libvirt state" "running"
  elif [ "$state" = "shut off" ]; then
    record SKIP "$vm" "libvirt state" "shut off"
  else
    record FAIL "$vm" "libvirt state" "$state"
  fi
done

RUNNING=0
for vm in SOC-DC01 SOC-WIN10 SOC-WAZUH; do
  [ "$(vm_state "$vm")" = "running" ] && RUNNING=$((RUNNING+1))
done
if [ "$RUNNING" -eq 0 ]; then
  if [ "$JSON" -eq 1 ]; then
    printf '{"status":"no-vms-running","passed":0,"failed":0,"skipped":3}\n'
  else
    echo "No lab VM is running. Start a supported mode first (see architecture/resource-modes.md)."
  fi
  exit 3
fi

if [ "$(vm_state SOC-DC01)" = "running" ]; then
  arp_check "$DC_IP" "$DC_MAC" "ARP"
  for p in 53 88 389 445 5985; do tcp_check "$DC_IP" "$p" "AD service"; done
  if command -v dig >/dev/null 2>&1; then
    srv="$(dig +short @$DC_IP _ldap._tcp.dc._msdcs.soc-lab.local SRV 2>/dev/null | head -1)"
    if [ -n "$srv" ]; then
      record PASS "$DC_IP" "LDAP SRV" "${srv//$'\n'/ }"
    else
      record FAIL "$DC_IP" "LDAP SRV" "no SRV answer"
    fi
  fi
else
  record SKIP "$DC_IP" "AD services" "SOC-DC01 not running"
fi

if [ "$(vm_state SOC-WIN10)" = "running" ]; then
  arp_check "$WIN_IP" "$WIN_MAC" "ARP"
  tcp_check "$WIN_IP" 5985 "WinRM / domain profile"
else
  record SKIP "$WIN_IP" "endpoint services" "SOC-WIN10 not running"
fi

if [ "$(vm_state SOC-WAZUH)" = "running" ]; then
  arp_check "$WAZUH_IP" "$WAZUH_MAC" "ARP"
  for p in 443 1514 1515 55000; do tcp_check "$WAZUH_IP" "$p" "Wazuh service"; done
else
  record SKIP "$WAZUH_IP" "Wazuh services" "SOC-WAZUH not running"
fi

if [ "$JSON" -eq 1 ]; then
  printf '{"passed":%d,"failed":%d,"skipped":%d,"checks":[' "$PASS" "$FAIL" "$SKIP"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st host chk det <<< "$r"
    [ "$first" -eq 0 ] && printf ','
    first=0
    printf '{"status":"%s","host":"%s","check":"%s","detail":"%s"}' "$st" "$host" "$chk" "$det"
  done
  printf ']}\n'
else
  echo "SOC Lab Connectivity Check — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "------------------------------------------------------------"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st host chk det <<< "$r"
    printf '%-4s %-12s %-24s %s\n' "$st" "$host" "$chk" "$det"
  done
  echo "------------------------------------------------------------"
  echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
fi

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
