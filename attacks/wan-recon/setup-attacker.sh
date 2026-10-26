#!/bin/sh
# Authorized lab only — run inside the attacker VM on Vung_WAN.
# Stops DHCP from clearing the static address, then installs the route
# to the OPNsense LAN.

set -e

WAN_IF="${WAN_IF:-eth0}"
WAN_IP="${WAN_IP:-192.168.50.10}"
WAN_MASK="${WAN_MASK:-255.255.255.0}"
GW="${GW:-192.168.50.1}"
TARGET_NET="${TARGET_NET:-10.0.0.0}"

killall dhclient 2>/dev/null || true
ifconfig "$WAN_IF" "$WAN_IP" netmask "$WAN_MASK" up
route add -net "$TARGET_NET" netmask 255.255.255.0 gw "$GW" 2>/dev/null || true

echo "[+] $WAN_IF = $WAN_IP/$WAN_MASK"
echo "[+] route $TARGET_NET/24 via $GW"
ifconfig "$WAN_IF" | grep -E "inet|UP"
cat /proc/net/route
