#!/usr/bin/env bash
# KryxAI — deploy NBF anchor network on the free-tier Oracle Cloud ARM VM.
# Target: Ubuntu 22.04 (Ampere A1 / 4 OCPU / 24GB) — winner of the tier.
# No billing within Always Free; uses the same Fabric 2.2 images as NBF-Lite.
#
# On the VM:
#   sudo apt update && sudo apt install -y docker.io docker-compose-v2
#   sudo usermod -aG docker $USER && newgrp docker
#   git clone <your repo> kryxai && cd kryxai/deploy/nbf-fabric
#   bash scripts/deploy-cloud.sh
set -euo pipefail

echo "==> [0/5] Stop any previous stack"
# gen-crypto.sh now regenerates crypto-config/ and channel-artifacts/ from a
# clean slate, and refuses to do so while containers still hold bind mounts to
# them. Taking the network down first is what makes a re-run actually
# idempotent, which is what the Codespaces doc already promised.
docker compose down --remove-orphans >/dev/null 2>&1 || true

echo "==> [1/5] Generate Org1 + Orderer crypto and channel config"
bash scripts/gen-crypto.sh

echo "==> [2/5] Connection profile + wallet"
PEER_URL=peer0:7051 ORDERER_URL=orderer.kryxai.example.com:7050 bash scripts/gen-connection-profile.sh
bash scripts/build-wallet.sh

echo "==> [3/5] Starting network"
docker compose up -d --build

echo "==> [4/5] Create mychannel + install chaincode"
CHANNEL=mychannel
# `peer node status` was removed in Fabric 2.x (it only prints usage), so poll
# `peer channel list` (needs the admin identity) until the peer's gRPC is up.
echo "==> Waiting for peer to accept calls…"
for _ in $(seq 1 90); do
  docker exec \
    -e CORE_PEER_LOCALMSPID=Org1MSP \
    -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/crypto/peerOrganizations/kryxai.example.com/users/Admin@kryxai.example.com/msp \
    -e CORE_PEER_ADDRESS=peer0:7051 \
    -e CORE_PEER_TLS_ENABLED=false \
    kryxai-peer0 peer channel list >/dev/null 2>&1 && break
  sleep 2
done
docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/crypto/peerOrganizations/kryxai.example.com/users/Admin@kryxai.example.com/msp \
  -e CORE_PEER_ADDRESS=peer0:7051 \
  -e CORE_PEER_TLS_ENABLED=false \
  kryxai-peer0 peer channel create \
  --orderer orderer.kryxai.example.com:7050 \
  --channelID ${CHANNEL} \
  --file /chaincode/channel-artifacts/channel.tx \
  --outputBlock /chaincode/channel-artifacts/${CHANNEL}.block
docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/crypto/peerOrganizations/kryxai.example.com/users/Admin@kryxai.example.com/msp \
  -e CORE_PEER_ADDRESS=peer0:7051 \
  -e CORE_PEER_TLS_ENABLED=false \
  kryxai-peer0 peer channel join --blockpath /chaincode/channel-artifacts/${CHANNEL}.block
bash scripts/install-chaincode.sh

echo "==> [5/5] Opening the gateway to the app (port 4000)"
echo "    Set OCI: Security List -> Ingress TCP 4000 (or use an SSH tunnel for the demo)."

echo ""
echo "Deployed. Point the backend at it:"
echo "  BLOCKCHAIN_EXTERNAL_ANCHOR=true"
echo "  NBF_GATEWAY_URL=http://<PUBLIC_IP>:4000"
echo "Reachable check: curl http://<PUBLIC_IP>:4000/health"