#!/usr/bin/env bash
set -euo pipefail

DIR="/etc/traced"
FILE="$DIR/relay_id"

sudo mkdir -p "$DIR"
sudo chmod 700 "$DIR"

if [[ -f "$FILE" ]]; then
  cat "$FILE"
  exit 0
fi

ID="rly_$(python3 - <<'PY'
import secrets
alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
print("".join(secrets.choice(alphabet) for _ in range(12)))
PY
)"

echo "$ID" | sudo tee "$FILE" >/dev/null
sudo chmod 600 "$FILE"
cat "$FILE"
