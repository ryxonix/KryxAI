#!/usr/bin/env bash
# KryxAI — deploy the NBF anchor network inside a GitHub Codespace.
#
# Same Fabric + IPFS + gateway stack as scripts/deploy-cloud.sh, but wired for a
# Codespace, where Docker bridge networking is broken (see
# docker-compose.codespace.yml for the evidence). Every service shares the host
# network namespace and the scripts address each other over 127.0.0.1.
#
#   cd deploy/nbf-fabric && bash scripts/deploy-codespace.sh
#
# Re-running is safe: crypto is regenerated, the channel already exists, and
# install-chaincode.sh skips an already-installed/committed definition.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Codespace login shells start in $HOME, so never rely on a relative path.
SCRIPTS="$PWD/scripts"
COMPOSE_FILE="docker-compose.codespace.yml"

# Host networking has no Docker DNS, so the service names the bridge compose
# uses (peer0, orderer.kryxai.example.com) do not resolve.
PEER_ADDR=127.0.0.1:7051
ORDERER=127.0.0.1:7050
export PEER_ADDR ORDERER

# These two get baked into genesis.block and channel.tx by configtxgen, so the
# peer's ordering service and anchor peer must be written as loopback too.
# Without this the peer boots fine but then logs, forever:
#   Could not connect to ordering service: could not dial endpoint
#   'orderer.kryxai.example.com:7050': lookup ... no such host
export ORDERER_ADDRESS="127.0.0.1:7050"
export PEER_HOST="127.0.0.1"

# Docker 29.8 in a Codespace breaks Fabric 2.2's vendored Docker client: the
# chaincode build dies instantly with an empty log and
#   docker build failed: write unix @->/var/run/docker.sock: write: broken pipe
# Fabric 2.5 uses a current Docker client, so match the version to the daemon.
export FABRIC_TOOLS_IMAGE="hyperledger/fabric-tools:2.5"

peer_exec() {
  docker exec \
    -e CORE_PEER_LOCALMSPID=Org1MSP \
    -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/crypto/peerOrganizations/kryxai.example.com/users/Admin@kryxai.example.com/msp \
    -e CORE_PEER_ADDRESS="${PEER_ADDR}" \
    -e CORE_PEER_TLS_ENABLED=false \
    kryxai-peer0 "$@"
}

echo "==> [0/5] Stop any previous stack"
# gen-crypto.sh refuses to run while kryxai-* containers are up, because they
# hold bind mounts to the files it is about to delete.
docker compose -f "${COMPOSE_FILE}" down --remove-orphans >/dev/null 2>&1 || true

echo "==> [1/5] Generate Org1 + Orderer crypto and channel config"
bash "${SCRIPTS}/gen-crypto.sh"

echo "==> [2/5] Connection profile + wallet (loopback addresses)"
PEER_URL=127.0.0.1:7051 ORDERER_URL=127.0.0.1:7050 \
  bash "${SCRIPTS}/gen-connection-profile.sh"
bash "${SCRIPTS}/build-wallet.sh"

echo "==> [3/5] Starting network (host networking)"
docker compose -f "${COMPOSE_FILE}" up -d --build

# Wait for the peer AND the orderer. deploy-cloud.sh only waits on the peer, so
# `peer channel create` can run while the orderer is still booting and fail with
# "failed to create deliver client for orderer ... context deadline exceeded".
# The orderer is the one that usually loses this race: it has to create the
# system channel before it serves requests.
#
# The orderer probe is a TCP connect, not `peer channel list --orderer ...`:
# `peer channel list` answers from the peer's own channel state and exits 0
# without ever contacting the orderer, so it reports "ready" instantly and
# proves nothing. (Proven the hard way - a bogus probe passed here and the very
# next command got "connection refused".)
#
# It also runs on the host rather than inside the peer container. Fabric 2.5's
# peer image ships no netcat, so an in-container `nc -z 127.0.0.1 7050` always
# exits 127 and the loop burned its full timeout against a perfectly healthy
# orderer. Under host networking the host's loopback is the same loopback, so
# bash's own /dev/tcp is both sufficient and dependency-free.
orderer_ready() {
  timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/7050' 2>/dev/null
}

echo "==> Waiting for peer and orderer to accept calls…"
peer_ok=0
orderer_ok=0
for _ in $(seq 1 90); do
  if [ "${peer_ok}" -eq 0 ] && peer_exec peer channel list >/dev/null 2>&1; then
    peer_ok=1; echo "    peer ready"
  fi
  if [ "${orderer_ok}" -eq 0 ] && orderer_ready; then
    orderer_ok=1; echo "    orderer ready"
  fi
  [ "${peer_ok}" -eq 1 ] && [ "${orderer_ok}" -eq 1 ] && break
  sleep 2
done
if [ "${peer_ok}" -ne 1 ] || [ "${orderer_ok}" -ne 1 ]; then
  echo "FATAL: peer/orderer never became ready;" \
    "see 'docker logs kryxai-peer0' and 'docker logs kryxai-orderer'" >&2
  exit 1
fi

echo "==> [4/5] Create mychannel + install chaincode"
CHANNEL=mychannel
# Retry: the orderer can still be re-binding after a restart, and a create that
# half-succeeded leaves no channel to detect.
created=0
for attempt in $(seq 1 5); do
  if peer_exec peer channel create \
      --orderer "${ORDERER}" \
      --channelID "${CHANNEL}" \
      --file /chaincode/channel-artifacts/channel.tx \
      --outputBlock /chaincode/channel-artifacts/${CHANNEL}.block; then
    created=1; break
  fi
  echo "    channel create attempt ${attempt} failed; retrying"
  sleep 5
done
[ "${created}" -eq 1 ] || { echo "FATAL: could not create ${CHANNEL}" >&2; exit 1; }
peer_exec peer channel join --blockpath /chaincode/channel-artifacts/${CHANNEL}.block
bash "${SCRIPTS}/install-chaincode.sh"

echo "==> [5/5] Restarting the gateway so it loads the new wallet and profile"
docker restart kryxai-gateway >/dev/null

echo ""
echo "Deployed. Verify inside the codespace:"
echo "  curl http://127.0.0.1:4000/health"
echo "  curl 'http://127.0.0.1:4000/fabric/v1/querycc?fcn=QueryAll&ccname=kryxai-posture&channel=mychannel&mspId=Org1MSP&user=User1'"
echo ""
echo "Then make port 4000 public and point the backend at it:"
echo "  gh codespace ports visibility 4000:public -c <codespace>"
echo "  BLOCKCHAIN_EXTERNAL_ANCHOR=true"
echo "  NBF_GATEWAY_URL=https://<cs>-4000.app.github.dev"
