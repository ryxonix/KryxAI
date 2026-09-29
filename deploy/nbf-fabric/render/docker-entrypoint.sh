#!/usr/bin/env bash
# KryxAI — entrypoint for the single-container NBF anchor image.
# Order: generate crypto/artifacts (first boot) -> start services -> channel +
# chaincode lifecycle (idempotent) -> keep supervisord in the foreground as the
# container's lifetime.
set -euo pipefail

export HOME=/app
export PATH=/usr/local/bin:${PATH}
export FABRIC_CFG_PATH=/app/config
export DATA_DIR=${DATA_DIR:-/app/data}

mkdir -p "${DATA_DIR}/crypto-config" "${DATA_DIR}/channel-artifacts" \
         "${DATA_DIR}/wallet" "${DATA_DIR}/ledger" "${DATA_DIR}/cc" \
         "${DATA_DIR}/ipfs" /app/run

# Resolve the Fabric MSP hostnames (used inside the channel config / connection
# profile) back to loopback so gossip + orderer delivery work without an external
# registry. Done at runtime — /etc/hosts is read-only during image build.
if ! grep -q 'orderer.kryxai.example.com' /etc/hosts; then
  printf '127.0.0.1 orderer.kryxai.example.com peer0.kryxai.example.com\n' >>/etc/hosts
fi

echo "==> [1/3] crypto / channel artifacts / wallet / ccaas package (first boot)"
bash /app/scripts/gen-network.sh

echo "==> [2/3] starting supervised services (orderer, ipfs, chaincode, peer, gateway)"
/usr/bin/supervisord -c /app/supervisord.conf &
SUP_PID=$!

trap 'kill -TERM "${SUP_PID}" 2>/dev/null || true; wait "${SUP_PID}" 2>/dev/null || true' TERM INT

echo "==> [3/3] channel create + join + chaincode lifecycle (idempotent)"
if ! bash /app/scripts/bootstrap.sh; then
  echo "WARNING: bootstrap incomplete (peer/orderer may still be warming up)" >&2
fi

wait "${SUP_PID}"