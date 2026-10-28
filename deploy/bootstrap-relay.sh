#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/traced-mvp}"
CORE_URL="${CORE_URL:-}"
EDGE_API_KEY="${EDGE_API_KEY:-}"
TRACED_SHARED_SECRET="${TRACED_SHARED_SECRET:-}"
EDGE_POLL_SECONDS="${EDGE_POLL_SECONDS:-15}"

SO_HOST="${SO_HOST:-}"
SO_PORT="${SO_PORT:-514}"
SO_PROTO="${SO_PROTO:-udp}"

REPO_URL="${REPO_URL:-}"
SERVICE_NAME="traced-relay.service"

if [[ -z "$CORE_URL" || -z "$EDGE_API_KEY" || -z "$TRACED_SHARED_SECRET" ]]; then
  echo "ERROR: CORE_URL, EDGE_API_KEY, and TRACED_SHARED_SECRET are required."
  exit 1
fi

need_cmd() { command -v "$1" >/dev/null 2>&1; }

echo "[*] Installing prerequisites"
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release rsync jq python3

if ! need_cmd docker; then
  echo "[*] Installing Docker Engine + Compose plugin"
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

sudo systemctl enable docker >/dev/null
sudo systemctl start docker

echo "[*] Deploying repo into $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"

if [[ -n "$REPO_URL" ]]; then
  sudo apt-get install -y git
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    sudo git -C "$INSTALL_DIR" pull --ff-only
  else
    sudo rm -rf "$INSTALL_DIR"/*
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
  fi
else
  SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  sudo rsync -a --delete "$SRC_DIR/" "$INSTALL_DIR/"
fi

echo "[*] Creating/reading opaque relay id"
sudo chmod +x "$INSTALL_DIR/deploy/relay_id.sh"
RELAY_ID="$("$INSTALL_DIR/deploy/relay_id.sh")"
echo "[*] Relay ID: $RELAY_ID"

echo "[*] Collecting mapping metadata"
HOSTNAME="$(hostname)"
MODEL="$(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null || true)"
SERIAL="$(cat /sys/devices/virtual/dmi/id/product_serial 2>/dev/null || true)"
ARCH="$(uname -m)"

sudo mkdir -p /etc/traced
cat <<EOF | sudo tee /etc/traced/mapping.json >/dev/null
{
  "relay_id": "$RELAY_ID",
  "hostname": "$HOSTNAME",
  "model": "$(echo "$MODEL" | sed 's/"/\\"/g')",
  "serial": "$(echo "$SERIAL" | sed 's/"/\\"/g')",
  "arch": "$ARCH"
}
EOF
sudo chmod 600 /etc/traced/mapping.json

echo "[*] Writing .env"
cat <<EOF | sudo tee "$INSTALL_DIR/.env" >/dev/null
TRACED_SHARED_SECRET=$TRACED_SHARED_SECRET
EDGE_API_KEY=$EDGE_API_KEY

EDGE_RELAY_ID=$RELAY_ID
EDGE_POLL_SECONDS=$EDGE_POLL_SECONDS

EDGE_SO_HOST=$SO_HOST
EDGE_SO_PORT=$SO_PORT
EDGE_SO_PROTO=$SO_PROTO

EDGE_META_HOSTNAME=$HOSTNAME
EDGE_META_MODEL=$MODEL
EDGE_META_SERIAL=$SERIAL
EDGE_META_ARCH=$ARCH
EOF

echo "[*] Installing systemd unit"
tmpl="$INSTALL_DIR/deploy/traced-relay.service.tmpl"
unit="/etc/systemd/system/$SERVICE_NAME"
if [[ ! -f "$tmpl" ]]; then
  echo "ERROR: missing $tmpl"
  exit 1
fi
sudo sed "s|{{CORE_URL}}|$CORE_URL|g" "$tmpl" | sudo tee "$unit" >/dev/null

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME" >/dev/null
sudo systemctl restart "$SERVICE_NAME"

echo "[*] Smoke test: local relay poll endpoint"
set +e
RESP="$(curl -sS -X POST http://127.0.0.1:9443/v1/edge/poll -H "Authorization: Bearer $EDGE_API_KEY")"
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "[!] Relay poll test failed."
  echo "    Check: sudo systemctl status $SERVICE_NAME --no-pager"
  echo "    Logs:  cd $INSTALL_DIR && docker compose logs -f relay"
  exit 2
fi

echo "[*] Relay poll response: $RESP"
echo "[*] Installed OK."
echo "    Relay ID: $RELAY_ID"
echo "    Mapping:  /etc/traced/mapping.json"
