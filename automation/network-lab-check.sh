#!/usr/bin/env bash
# network-lab-check.sh
#
# Read-only health check for Network Security Mode (OPNsense + Metasploitable2).
# Starts/stops nothing and changes no configuration.
#
# Exit codes: 0 = pass, 1 = failure, 2 = missing tool, 3 = VMs not running

set -uo pipefail

LIBVIRT_URI="${LIBVIRT_URI:-qemu:///system}"
OPN_DOMAIN="OPNsense-Lab6"
MSF_DOMAIN="Metasploitable2"
OPN_IP="10.0.0.1"
MSF_IP="10.0.0.5"
MSF_MAC="52:54:00:86:b8:60"
NET="Vung_LAN"

PASS=0; FAIL=0; SKIP=0
declare -a R=()

rec() { case "$1" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; SKIP) SKIP=$((SKIP+1));; esac; R+=("$1|$2|$3|$4"); }
tcp() { local h="$1" p="$2" l="$3" i; for i in 1 2 3; do if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$h/$p" 2>/dev/null; then rec PASS "$h" "$l" "tcp/$p open"; return; fi; sleep 2; done; rec FAIL "$h" "$l" "tcp/$p closed"; }

command -v virsh >/dev/null 2>&1 || { echo "ERROR: virsh not found" >&2; exit 2; }

state() { virsh -c "$LIBVIRT_URI" domstate "$1" 2>/dev/null || echo undefined; }

for d in "$OPN_DOMAIN" "$MSF_DOMAIN"; do
  s="$(state "$d")"
  if [ "$s" = running ]; then rec PASS "$d" "libvirt state" running
  elif [ "$s" = "shut off" ]; then rec SKIP "$d" "libvirt state" "shut off"
  else rec FAIL "$d" "libvirt state" "$s"; fi
done

if [ "$(state "$OPN_DOMAIN")" != running ] && [ "$(state "$MSF_DOMAIN")" != running ]; then
  echo "Network Security Mode is not running. Start OPNsense-Lab6 and Metasploitable2 first."
  exit 3
fi

netinfo="$(virsh -c "$LIBVIRT_URI" net-info "$NET" 2>/dev/null || true)"
if grep -q "Active:[[:space:]]*yes" <<< "$netinfo"; then
  rec PASS "$NET" "network" active
else
  rec FAIL "$NET" "network" inactive
fi

if [ "$(state "$OPN_DOMAIN")" = running ]; then
  if ping -c 2 -W 2 "$OPN_IP" >/dev/null 2>&1; then rec PASS "$OPN_IP" "ICMP" reachable; else rec FAIL "$OPN_IP" "ICMP" unreachable; fi
  code="$(timeout 8 curl -sk -o /dev/null -w '%{http_code}' "https://$OPN_IP/" 2>/dev/null)"
  [ "$code" = 200 ] && rec PASS "$OPN_IP" "HTTPS" "HTTP $code" || rec FAIL "$OPN_IP" "HTTPS" "HTTP ${code:-none}"
else
  rec SKIP "$OPN_IP" "firewall" "OPNsense not running"
fi

if [ "$(state "$MSF_DOMAIN")" = running ]; then
  leases="$(virsh -c "$LIBVIRT_URI" net-dhcp-leases "$NET" 2>/dev/null || true)"
  if grep -q "$MSF_IP" <<< "$leases"; then
    rec PASS "$MSF_IP" "DHCP lease" "$MSF_MAC -> $MSF_IP"
  else
    rec FAIL "$MSF_IP" "DHCP lease" "no reservation lease"
  fi
  if ping -c 2 -W 2 "$MSF_IP" >/dev/null 2>&1; then rec PASS "$MSF_IP" "ICMP" reachable; else rec FAIL "$MSF_IP" "ICMP" unreachable; fi
  for p in 21 22 80; do tcp "$MSF_IP" "$p" "target service"; done
else
  rec SKIP "$MSF_IP" "target" "Metasploitable not running"
fi

echo "Network Security Lab Check — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "------------------------------------------------------------"
for r in "${R[@]}"; do IFS='|' read -r st h c d <<< "$r"; printf '%-4s %-14s %-18s %s\n' "$st" "$h" "$c" "$d"; done
echo "------------------------------------------------------------"
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
