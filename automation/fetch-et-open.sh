#!/bin/sh
# Download ET Open for Suricata and build the lab subset.
# Run on the Parrot host. The rules are third-party content: do not commit them.

set -e
VERSION="${1:-8.0}"
OUT="${2:-/tmp/et-open}"

mkdir -p "$OUT"
curl -sL "https://rules.emergingthreats.net/open/suricata-${VERSION}/emerging.rules.tar.gz" \
  -o "$OUT/et.tar.gz"
tar -xzf "$OUT/et.tar.gz" -C "$OUT"

cat "$OUT/rules/emerging-scan.rules" \
    "$OUT/rules/emerging-dos.rules" \
    "$OUT/rules/emerging-attack_response.rules" \
    "$OUT/rules/emerging-exploit.rules" \
    "$OUT/rules/emerging-web_server.rules" \
    > "$OUT/emerging-subset.rules"

printf 'subset: %s\n' "$OUT/emerging-subset.rules"
printf 'rules:  %s\n' "$(grep -c '^alert\|^drop' "$OUT/emerging-subset.rules")"

cat <<'EOF'
Install on OPNsense:
  fetch -o /usr/local/etc/suricata/rules/emerging-subset.rules \
    http://10.0.0.254:8006/emerging-subset.rules
  # installed_rules.yaml must list:
  #   - /root/lab.rules
  #   - /usr/local/etc/suricata/rules/emerging-subset.rules
  service suricata restart
EOF
