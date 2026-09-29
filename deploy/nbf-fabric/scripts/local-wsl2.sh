#!/usr/bin/env bash
# KryxAI — bring up the NBF anchor network on the DEV box (WSL2 Ubuntu).
# Zero-cost: no cloud spend, uses Docker inside WSL2.
#
#   wsl -d Ubuntu
#   cd /mnt/f/kryxai/deploy/nbf-fabric
#   bash scripts/local-wsl2.sh
set -euo pipefail

CHANNEL=${CHANNEL:-mychannel}
ORDERER=orderer.kryxai.example.com:7050
ADMIN_MSP=/etc/hyperledger/crypto/peerOrganizations/kryxai.example.com/users/Admin@kryxai.example.com/msp

echo "==> [1/5] Generate Org1 + Orderer crypto and channel config"
bash scripts/gen-crypto.sh

echo "==> [2/5] Connection profile + wallet (before compose so the gateway's file mount ./gateway/connection-org1.json exists; otherwise Docker auto-creates it as a directory and the profile can never be written)"
PEER_URL=peer0:7051 ORDERER_URL=orderer.kryxai.example.com:7050 bash scripts/gen-connection-profile.sh
bash scripts/build-wallet.sh

echo "==> [3/5] Start peer+orderer+couchdb+IPFS+gateway"
docker compose up -d

echo "==> [4/5] Create + join channel '${CHANNEL}'"
# Wait for the peer to be live
until docker exec kryxai-peer0 peer node status 2>/dev/null | grep -q SERVER; do sleep 2; done

docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
  -e CORE_PEER_ADDRESS=peer0:7051 \
  -e CORE_PEER_TLS_ENABLED=false \
  kryxai-peer0 peer channel create \
  --orderer ${ORDERER} \
  --channelID ${CHANNEL} \
  --file /chaincode/channel-artifacts/channel.tx \
  --outputBlock /chaincode/channel-artifacts/${CHANNEL}.block

docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH=${ADMIN_MSP} \
  -e CORE_PEER_ADDRESS=peer0:7051 \
  -e CORE_PEER_TLS_ENABLED=false \
  kryxai-peer0 peer channel join \
  --blockpath /chaincode/channel-artifacts/${CHANNEL}.block

echo "==> [5/5] Install, approve and commit chaincode"
bash scripts/install-chaincode.sh

echo ""
echo "NBF anchor network up; channel '${CHANNEL}' created."
echo "Gateway:    http://localhost:4000/health"
echo "Backend:    BLOCKCHAIN_EXTERNAL_ANCHOR=true NBF_GATEWAY_URL=http://localhost:4000 python app/main.py"