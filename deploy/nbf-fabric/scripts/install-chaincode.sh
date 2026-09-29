#!/usr/bin/env bash
# KryxAI — build, install, approve & commit the anchors chaincode.
# Run from deploy/nbf-fabric/ after the network is up (scripts/local-wsl2.sh).
set -euo pipefail

CC_NAME=${CC_NAME:-kryxai-posture}
CC_VERSION=${CC_VERSION:-1.0}
CC_SEQUENCE=${CC_SEQUENCE:-1}
CHANNEL=${CHANNEL:-mychannel}
ORDERER=${ORDERER:-orderer.kryxai.example.com:7050}
CC_PATH=${CC_PATH:-/chaincode/src}          # ./go mounted into the peer
ART_DIR=${ART_DIR:-/chaincode/channel-artifacts}
ADMIN_MSP=/etc/hyperledger/crypto/peerOrganizations/kryxai.example.com/users/Admin@kryxai.example.com/msp

echo "==> Packaging chaincode"
# The golang packager normalizes the module root by invoking `go`, which is
# not shipped in the fabric-peer image. Install it once if missing
# (peer:2.2 is Alpine -> apk; Oracle-OpenFairflow builds are Ubuntu -> apt).
docker exec -u root kryxai-peer0 sh -lc \
  'command -v go >/dev/null 2>&1 || { if command -v apk >/dev/null 2>&1; then apk add --no-cache go >/dev/null; else DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go >/dev/null; fi }'
docker exec kryxai-peer0 peer lifecycle chaincode package \
  ${ART_DIR}/${CC_NAME}.tgz \
  --path ${CC_PATH} \
  --lang golang \
  --label "${CC_NAME}_${CC_VERSION}"

echo "==> Install on peer0"
PKG_ID=$(docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
  -e CORE_PEER_ADDRESS=peer0:7051 \
  -e CORE_PEER_TLS_ENABLED=false \
  kryxai-peer0 peer lifecycle chaincode queryinstalled \
  | grep -o "${CC_NAME}_${CC_VERSION}:[A-Za-z0-9]*" | head -1 || true)

if [ -n "${PKG_ID}" ]; then
  echo "    already installed: ${PKG_ID}"
else
  docker exec \
    -e CORE_PEER_LOCALMSPID=Org1MSP \
    -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
    -e CORE_PEER_ADDRESS=peer0:7051 \
    -e CORE_PEER_TLS_ENABLED=false \
    kryxai-peer0 peer lifecycle chaincode install ${ART_DIR}/${CC_NAME}.tgz
  PKG_ID=$(docker exec \
    -e CORE_PEER_LOCALMSPID=Org1MSP \
    -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
    -e CORE_PEER_ADDRESS=peer0:7051 \
    -e CORE_PEER_TLS_ENABLED=false \
    kryxai-peer0 peer lifecycle chaincode queryinstalled \
    | grep -o "${CC_NAME}_${CC_VERSION}:[A-Za-z0-9]*" | head -1)
fi
echo "    package id = ${PKG_ID}"

COMMITTED_SEQ=$(docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
  -e CORE_PEER_ADDRESS=peer0:7051 \
  -e CORE_PEER_TLS_ENABLED=false \
  kryxai-peer0 peer lifecycle chaincode querycommitted \
  --channelID ${CHANNEL} --name ${CC_NAME} 2>/dev/null \
  | grep -o "Sequence: [0-9]*" | head -1 | awk '{print $2}' || true)

if [ -n "${COMMITTED_SEQ}" ] && [ "${COMMITTED_SEQ}" -ge "${CC_SEQUENCE}" ]; then
  echo "    already committed at sequence ${COMMITTED_SEQ}; skipping approve+commit"
else
  echo "==> Approve for Org1"
  docker exec \
    -e CORE_PEER_LOCALMSPID=Org1MSP \
    -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
    -e CORE_PEER_ADDRESS=peer0:7051 \
    -e CORE_PEER_TLS_ENABLED=false \
    kryxai-peer0 peer lifecycle chaincode approveformyorg \
    --orderer ${ORDERER} \
    --channelID ${CHANNEL} \
    --name ${CC_NAME} \
    --version ${CC_VERSION} \
    --package-id "${PKG_ID}" \
    --sequence ${CC_SEQUENCE}

  echo "==> Commit on channel"
  docker exec \
    -e CORE_PEER_LOCALMSPID=Org1MSP \
    -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
    -e CORE_PEER_ADDRESS=peer0:7051 \
    -e CORE_PEER_TLS_ENABLED=false \
    kryxai-peer0 peer lifecycle chaincode commit \
    --orderer ${ORDERER} \
    --channelID ${CHANNEL} \
    --name ${CC_NAME} \
    --version ${CC_VERSION} \
    --sequence ${CC_SEQUENCE}
fi

sleep 3
echo "==> Smoke test: init + query"
docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
  -e CORE_PEER_ADDRESS=peer0:7051 \
  -e CORE_PEER_TLS_ENABLED=false \
  kryxai-peer0 peer chaincode invoke \
  --orderer ${ORDERER} --channelID ${CHANNEL} --name ${CC_NAME} \
  -c '{"Args":["InitLedger"]}' || true
docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
  -e CORE_PEER_ADDRESS=peer0:7051 \
  -e CORE_PEER_TLS_ENABLED=false \
  kryxai-peer0 peer chaincode query \
  --channelID ${CHANNEL} --name ${CC_NAME} -c '{"Args":["QueryAll"]}'

echo "==> Chaincode ${CC_NAME}@${CC_VERSION} live on ${CHANNEL}"