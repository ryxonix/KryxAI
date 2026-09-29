#!/usr/bin/env bash
# KryxAI — launch the chaincode-as-a-service server.
# The chaincode server registers with the peer under CORE_CHAINCODE_ID_NAME,
# which MUST equal the package id ("<label>:<sha256>") that the peer computes
# during `peer lifecycle chaincode install`. gen-network.sh writes that exact id
# to ${DATA}/cc/package-id; we wait for it (server starts in parallel).
set -euo pipefail

export PATH=/usr/local/bin:${PATH}
DATA=${DATA_DIR:-/app/data}
CC_LABEL=${CC_LABEL:-kryxai-posture_1.0}

PKGID="${DATA}/cc/package-id"
for _ in $(seq 1 120); do
  [ -s "${PKGID}" ] && break
  sleep 1
done
if [ -s "${PKGID}" ]; then
  CORE_CHAINCODE_ID_NAME=$(cat "${PKGID}")
  echo "chaincode-server: package id ${CORE_CHAINCODE_ID_NAME}"
else
  # Caution: without the real id the server cannot register; still start so the
  # peer can succeed on retries after bootstrap computes it.
  CORE_CHAINCODE_ID_NAME=${CORE_CHAINCODE_ID_NAME:-${CC_LABEL}}
  echo "chaincode-server: WARN package-id not found, using label ${CORE_CHAINCODE_ID_NAME}" >&2
fi
export CORE_CHAINCODE_ID_NAME

export CHAINCODE_SERVER_ADDRESS=${CHAINCODE_SERVER_ADDRESS:-127.0.0.1:9999}
exec /usr/local/bin/kryxai-posture-server