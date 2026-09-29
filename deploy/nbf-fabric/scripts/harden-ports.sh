#!/usr/bin/env bash
# KryxAI — harden inbound ports on the free-tier Oracle ARM VM.
# Allow ONLY SSH (22) and the NBF gateway (4000); deny everything else
# (Kubo IPFS :5001/:8080, CouchDB :5984, Fabric :7050/:7051/:7054 stay private).
#
# Usage:
#   bash scripts/harden-ports.sh                # allow *any* source on 22+4000
#   ALLOW_FROM=203.0.113.0/24 bash scripts/harden-ports.sh   # restrict sources
set -euo pipefail

ALLOW_FROM=${ALLOW_FROM:-0.0.0.0/0}
GATEWAY_PORT=${GATEWAY_PORT:-4000}

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed; run: sudo apt install -y ufw" >&2
  exit 1
fi

echo "==> Allowing only port 22 and ${GATEWAY_PORT} from ${ALLOW_FROM}"
sudo ufw allow from "$ALLOW_FROM" to any port 22 proto tcp
sudo ufw allow from "$ALLOW_FROM" to any port "${GATEWAY_PORT}" proto tcp
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw --force enable

echo "==> Active rules:"
sudo ufw status verbose
echo "OK — ports 5001/8080/5984/7050/7051/7054 are closed on the public interface."
echo "Point the backend at http://<PUBLIC_IP>:${GATEWAY_PORT} (see docs/nbflite-oracle-free-tier.md)."