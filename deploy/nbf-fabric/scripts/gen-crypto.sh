#!/usr/bin/env bash
# KryxAI — generate Org1/Orderer crypto + system/channel config.
# Run from deploy/nbf-fabric/ inside WSL2 Ubuntu (or any host with Docker).
set -euo pipefail

echo "==> Cryptogen: Org1 + Orderer identities"

# These get baked into genesis.block and every channel config, so they have to
# describe how peers and clients will *actually* reach each other. The defaults
# are the Docker service aliases from docker-compose.yml; host networking
# (scripts/deploy-codespace.sh) overrides them to loopback.
#
# configtx.yaml keeps them as ${ORDERER_ADDRESS} / ${PEER_HOST} placeholders and
# is rendered to a temp file below. Fabric's configtx loader does NOT expand
# environment variables, so exporting these is not enough on its own - pass them
# through with the config and the literal text "${ORDERER_ADDRESS}" ends up
# inside the genesis block, where the peer faithfully tries to dial it forever:
#   Could not connect to ordering service: could not dial endpoint
#   '${ORDERER_ADDRESS}': ... missing port in address
export ORDERER_ADDRESS="${ORDERER_ADDRESS:-orderer.kryxai.example.com:7050}"
export PEER_HOST="${PEER_HOST:-peer0.kryxai.example.com}"
export FABRIC_TOOLS_IMAGE="${FABRIC_TOOLS_IMAGE:-hyperledger/fabric-tools:2.2}"

# Rendered config, pointed at by FABRIC_CFG_PATH for the configtxgen calls.
# MSPDir values are rewritten to absolute container paths because configtxgen
# resolves them relative to FABRIC_CFG_PATH, which is now the temp dir rather
# than /work where crypto-config/ actually lives.
RENDERED_CFG="$(mktemp -d)"
trap 'rm -rf "${RENDERED_CFG}"' EXIT
sed -e "s|\${ORDERER_ADDRESS}|${ORDERER_ADDRESS}|g" \
    -e "s|\${PEER_HOST}|${PEER_HOST}|g" \
    -e "s|MSPDir: crypto-config/|MSPDir: /work/crypto-config/|g" \
    configtx.yaml > "${RENDERED_CFG}/configtx.yaml"
if grep -q '\${' "${RENDERED_CFG}/configtx.yaml"; then
  echo "configtx.yaml still contains unsubstituted placeholders after rendering:" >&2
  grep -n '\${' "${RENDERED_CFG}/configtx.yaml" >&2
  exit 1
fi

mkdir -p crypto-config channel-artifacts gateway/wallet

if [ ! -w crypto-config ] || [ ! -w channel-artifacts ]; then
  echo "crypto-config/ or channel-artifacts/ exists but is not writable" >&2
  echo "(root-owned from a previous run without --user). Remove the stale," >&2
  echo "root-owned output first:" >&2
  echo "  sudo rm -rf crypto-config channel-artifacts" >&2
  exit 1
fi

# Regenerate from a clean slate. This is not tidiness, it is correctness.
#
# `cryptogen` leaves an existing crypto-config/ in place instead of rewriting it,
# while `configtxgen` below *does* overwrite channel-artifacts/. A re-run would
# therefore emit a brand new genesis block referencing the current CA, alongside
# signing certs from a previous run, and the orderer would die at boot with:
#
#   Failed validating bootstrap block: ... x509: certificate signed by unknown
#   authority ... "ca.kryxai.example.com"
#
# which looks like a corrupt config rather than the stale-output case it is.
# The two directories must always be produced in the same pass.
#
# The ledger in CouchDB is keyed to this crypto too, so wiping it means the
# channel and chaincode have to be recreated - which the deploy scripts do
# immediately afterwards. Bring the network down first so no container is
# holding a bind mount to the files being removed.
if docker ps --format '{{.Names}}' | grep -q '^kryxai-'; then
  echo "Refusing to regenerate crypto while kryxai-* containers are running." >&2
  echo "Run 'docker compose down' first; a live container would keep a bind" >&2
  echo "mount to the deleted files and read an empty directory." >&2
  exit 1
fi
echo "==> Clearing previous crypto-config/ and channel-artifacts/ for a consistent set"
rm -rf crypto-config channel-artifacts
mkdir -p crypto-config channel-artifacts

docker run --rm --user "$(id -u):$(id -g)" \
  -v ${PWD}:/work -w /work \
  "${FABRIC_TOOLS_IMAGE}" \
  cryptogen generate --config=./crypto-config.yaml --output=./crypto-config

echo "==> Configtxgen: genesis (system channel)"
docker run --rm --user "$(id -u):$(id -g)" \
  -v ${PWD}:/work -w /work \
  -v "${RENDERED_CFG}":/rendered \
  -e FABRIC_CFG_PATH=/rendered \
  "${FABRIC_TOOLS_IMAGE}" \
  configtxgen -profile KryxAIGenesis \
  -outputBlock ./channel-artifacts/genesis.block -channelID systemchannel

echo "==> Configtxgen: mychannel create tx"
docker run --rm --user "$(id -u):$(id -g)" \
  -v ${PWD}:/work -w /work \
  -v "${RENDERED_CFG}":/rendered \
  -e FABRIC_CFG_PATH=/rendered \
  "${FABRIC_TOOLS_IMAGE}" \
  configtxgen -profile KryxAIChannel \
  -outputCreateChannelTx ./channel-artifacts/channel.tx -channelID mychannel

echo "==> Crypto + config generated under crypto-config/ and channel-artifacts/"
ls -R crypto-config 2>/dev/null | head -n 30 || true
echo "OK"