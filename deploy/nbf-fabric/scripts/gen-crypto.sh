#!/usr/bin/env bash
# KryxAI — generate Org1/Orderer crypto + system/channel config.
# Run from deploy/nbf-fabric/ inside WSL2 Ubuntu (or any host with Docker).
set -euo pipefail

echo "==> Cryptogen: Org1 + Orderer identities"
mkdir -p crypto-config channel-artifacts gateway/wallet

if [ ! -w crypto-config ]; then
  echo "crypto-config/ exists but is not writable (root-owned from a previous" >&2
  echo "run without --user). Remove the stale, root-owned output first:" >&2
  echo "  sudo rm -rf crypto-config channel-artifacts" >&2
  exit 1
fi

docker run --rm --user "$(id -u):$(id -g)" \
  -v ${PWD}:/work -w /work \
  hyperledger/fabric-tools:2.2 \
  cryptogen generate --config=./crypto-config.yaml --output=./crypto-config

echo "==> Configtxgen: genesis (system channel)"
docker run --rm --user "$(id -u):$(id -g)" \
  -v ${PWD}:/work -w /work \
  -e FABRIC_CFG_PATH=/work \
  hyperledger/fabric-tools:2.2 \
  configtxgen -profile KryxAIGenesis \
  -outputBlock ./channel-artifacts/genesis.block -channelID systemchannel

echo "==> Configtxgen: mychannel create tx"
docker run --rm --user "$(id -u):$(id -g)" \
  -v ${PWD}:/work -w /work \
  -e FABRIC_CFG_PATH=/work \
  hyperledger/fabric-tools:2.2 \
  configtxgen -profile KryxAIChannel \
  -outputCreateChannelTx ./channel-artifacts/channel.tx -channelID mychannel

echo "==> Crypto + config generated under crypto-config/ and channel-artifacts/"
ls -R crypto-config 2>/dev/null | head -n 30 || true
echo "OK"