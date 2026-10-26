#!/bin/sh
# Authorized lab only — capture SYN traffic while scanning the LAN target
# through OPNsense. Adjust TARGET/PORTS for your exercise.

set -e

WAN_IF="${WAN_IF:-eth0}"
TARGET="${TARGET:-10.0.0.5}"
PORTS="${PORTS:-21,22,80}"
PCAP="${PCAP:-/tmp/wan-scan.pcap}"
OUT="${OUT:-/tmp/nmap-capture.txt}"

sh "$(dirname "$0")/setup-attacker.sh"

tcpdump -i "$WAN_IF" -nn -w "$PCAP" &
PID=$!
sleep 2

nmap -e "$WAN_IF" -PN -sT -p "$PORTS" "$TARGET" > "$OUT" 2>&1 || true

sleep 2
kill "$PID" 2>/dev/null || true
sleep 1
chmod 644 "$PCAP" 2>/dev/null || true

echo "=== NMAP ==="
cat "$OUT"
echo "=== PCAP ==="
ls -l "$PCAP"
