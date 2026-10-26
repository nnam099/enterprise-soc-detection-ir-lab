#!/bin/sh
# Authorized lab only — HTTP load test against the isolated Metasploitable VM.
# Uses ApacheBench (no raw sockets required).

set -e
TARGET="${TARGET:-http://10.0.0.5/}"
OUT="${OUT:-/tmp/http-dos}"
mkdir -p "$OUT"

echo "[*] Baseline: 200 requests, 10 concurrent"
ab -n 200 -c 10 "$TARGET" > "$OUT/baseline.txt" 2>&1
grep -E "Complete requests|Failed requests|Requests per second|Time per request" "$OUT/baseline.txt"

echo "[*] Load: 10 seconds, 200 concurrent"
ab -t 10 -c 200 "$TARGET" > "$OUT/attack.txt" 2>&1
grep -E "Complete requests|Failed requests|Requests per second|Time per request" "$OUT/attack.txt"

echo "[*] Recovery: 100 requests, 10 concurrent"
ab -n 100 -c 10 "$TARGET" > "$OUT/after.txt" 2>&1
grep -E "Complete requests|Failed requests|Requests per second|Time per request" "$OUT/after.txt"

echo "[+] Logs: $OUT"
