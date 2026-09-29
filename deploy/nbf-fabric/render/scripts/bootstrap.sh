#!/usr/bin/env bash
# KryxAI — create/join mychannel and run the chaincode lifecycle.
# Idempotent: channel create/join, install, approve and commit are all skipped
# when already present (persisted /app/data or an existing network).
set -euo pipefail

export PATH=/usr/local/bin:${PATH}
export FABRIC_CFG_PATH=/app/config
export CORE_PEER_TLS_ENABLED=false
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_ADDRESS=127.0.0.1:7051
export CORE_PEER_MSPCONFIGPATH=/app/data/crypto-config/peerOrganizations/kryxai.example.com/users/Admin@kryxai.example.com/msp

DATA=${DATA_DIR:-/app/data}
CHANNEL=${CHANNEL:-mychannel}
CC_NAME=${CC_NAME:-kryxai-posture}
CC_VERSION=${CC_VERSION:-1.0}
CC_LABEL=${CC_LABEL:-${CC_NAME}_${CC_VERSION}}
ORDERER=127.0.0.1:7050

echo "==> waiting for orderer :7050 and peer :7051"
for _ in $(seq 1 240); do
  (echo > /dev/tcp/127.0.0.1/7050) >/dev/null 2>&1 \
    && (echo > /dev/tcp/127.0.0.1/7051) >/dev/null 2>&1 && break
  sleep 2
done

echo "==> waiting for peer gRPC (peer channel list)"
for _ in $(seq 1 120); do
  if peer channel list >/dev/null 2>&1; then break; fi
  sleep 2
done

# create channel (skip if already listed)
if ! peer channel list 2>/dev/null | grep -Fxq "${CHANNEL}"; then
  echo "==> creating channel ${CHANNEL}"
  peer channel create --orderer ${ORDERER} --channelID ${CHANNEL} \
    --file "${DATA}/channel-artifacts/channel.tx" \
    --outputBlock "${DATA}/channel-artifacts/${CHANNEL}.block"
fi
# join (idempotent — swallow the "already member" error)
peer channel join --blockpath "${DATA}/channel-artifacts/${CHANNEL}.block" 2>/dev/null || true

# install ccaas package. The peer store is the source of truth for the package
# id; gen-network.sh only pre-writes ${DATA}/cc/package-id so the ccaas server
# can register with the matching id. Never skip install based on that file
# alone, or the definition commits while the peer has no package.
PKG_ID=$(peer lifecycle chaincode queryinstalled \
  | grep -o "${CC_LABEL}:[a-f0-9]\{64\}" | head -n1 || true)
if [ -z "${PKG_ID}" ]; then
  echo "==> installing chaincode ${CC_LABEL}"
  peer lifecycle chaincode install "${DATA}/cc/${CC_LABEL}.tgz"
  PKG_ID=$(peer lifecycle chaincode queryinstalled \
    | grep -o "${CC_LABEL}:[a-f0-9]\{64\}" | head -n1)
fi
if [ -z "${PKG_ID}" ]; then
  echo "FATAL: chaincode ${CC_LABEL} not present after install" >&2
  exit 1
fi
echo "${PKG_ID}" > "${DATA}/cc/package-id"
echo "    package id ${PKG_ID}"

# approve + commit (skip if already committed)
COMMITTED=$(peer lifecycle chaincode querycommitted \
  --channelID ${CHANNEL} --name ${CC_NAME} 2>/dev/null \
  | grep -o 'Sequence: [0-9]*' | head -n1 | awk '{print $2}' || true)
if [ -z "${COMMITTED}" ] || [ "${COMMITTED}" -lt 1 ]; then
  echo "==> approveformyorg ${CC_NAME}@${CC_VERSION}"
  peer lifecycle chaincode approveformyorg --orderer ${ORDERER} \
    --channelID ${CHANNEL} --name ${CC_NAME} --version ${CC_VERSION} \
    --sequence 1 --package-id "${PKG_ID}" --waitForEvent
  echo "==> commit ${CC_NAME}@${CC_VERSION}"
  peer lifecycle chaincode commit --orderer ${ORDERER} \
    --channelID ${CHANNEL} --name ${CC_NAME} --version ${CC_VERSION} \
    --sequence 1 --waitForEvent
fi

echo "==> smoke test: QueryAll"
for _ in $(seq 1 30); do
  if peer chaincode query --channelID ${CHANNEL} --name ${CC_NAME} \
     -c '{"Args":["QueryAll"]}' >/dev/null 2>&1; then
    echo "    chaincode ${CC_NAME} live on ${CHANNEL}"
    touch "${DATA}/bootstrap-ready"
    exit 0
  fi
  sleep 3
done
echo "WARN: chaincode not answering yet — will be ready on the first request" 2>&1 || true
touch "${DATA}/bootstrap-ready"
exit 0