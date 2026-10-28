#!/usr/bin/env bash
set -euo pipefail

WZ_MANAGER="${wazuh_manager_ip}"
WZ_AGENT_NAME="${wazuh_agent_name}"
WZ_REG_PASSWORD="${wazuh_registration_password}"
TS_AUTHKEY="${tailscale_authkey}"

LOG=/var/log/soc-hybrid-bootstrap.log
exec > >(tee -a "$LOG") 2>&1

echo "[bootstrap] $(date -u +%FT%TZ) start"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl gnupg ca-certificates jq nginx auditd

curl -fsSL https://tailscale.com/install.sh | sh
systemctl enable --now tailscaled
if [ -n "$TS_AUTHKEY" ]; then
  tailscale up --authkey="$TS_AUTHKEY" --hostname="soc-aws-01"
else
  echo "[bootstrap] no Tailscale auth key; run 'sudo tailscale up' manually"
fi

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -y

export WAZUH_MANAGER="$WZ_MANAGER"
export WAZUH_REGISTRATION_SERVER="$WZ_MANAGER"
export WAZUH_AGENT_NAME="$WZ_AGENT_NAME"
if [ -n "$WZ_REG_PASSWORD" ]; then
  export WAZUH_REGISTRATION_PASSWORD="$WZ_REG_PASSWORD"
fi

apt-get install -y wazuh-agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

systemctl enable --now nginx
echo "SOC-AWS-01 $(date -u +%FT%TZ)" > /var/www/html/index.html

echo "[bootstrap] $(date -u +%FT%TZ) complete"
