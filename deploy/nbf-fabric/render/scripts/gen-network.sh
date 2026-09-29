#!/usr/bin/env bash
# KryxAI — first-boot artifact generation for the single-container image.
# Idempotent: every step is skipped when its output already exists (persisted
# /app/data disk on Render, or regenerated fresh on an ephemeral filesystem).
set -euo pipefail

export PATH=/usr/local/bin:${PATH}
export FABRIC_CFG_PATH=/app/config
DATA=${DATA_DIR:-/app/data}
ORG=kryxai.example.com
CC_LABEL=${CC_LABEL:-kryxai-posture_1.0}

mkdir -p "${DATA}/crypto-config" "${DATA}/channel-artifacts" "${DATA}/wallet" "${DATA}/cc"

# 1. identities (cryptogen)
if [ ! -d "${DATA}/crypto-config/peerOrganizations" ]; then
  echo "    cryptogen: Org1 + Orderer identities"
  cryptogen generate --config=/app/config/crypto-config.yaml --output="${DATA}/crypto-config"
fi

# 2. genesis + channel tx (configtxgen)
if [ ! -f "${DATA}/channel-artifacts/genesis.block" ]; then
  echo "    configtxgen: orderer genesis (single-node solo)"
  configtxgen -profile KryxAIGenesis \
    -outputBlock "${DATA}/channel-artifacts/genesis.block" -channelID systemchannel
fi
if [ ! -f "${DATA}/channel-artifacts/channel.tx" ]; then
  echo "    configtxgen: mychannel create tx"
  configtxgen -profile KryxAIChannel \
    -outputCreateChannelTx "${DATA}/channel-artifacts/channel.tx" -channelID mychannel
fi

# 3. connection profile for the gateway (peer + orderer on localhost)
if [ ! -f "${DATA}/connection-org1.json" ]; then
  echo "    writing connection profile"
  cat > "${DATA}/connection-org1.json" <<'EOF'
{
  "name": "kryxai-network-org1",
  "version": "1.0.0",
  "client": {
    "organization": "Org1MSP",
    "connection": { "timeout": { "peer": { "endorser": "30s" } } }
  },
  "organizations": {
    "Org1MSP": { "mspid": "Org1MSP", "peers": ["peer0"], "certificateAuthorities": [] }
  },
  "peers": {
    "peer0": {
      "url": "grpc://127.0.0.1:7051",
      "tlsCACerts": { "pem": "" },
      "grpcOptions": { "grpc.keepalive_time_ms": 600000 }
    }
  },
  "orderers": {
    "orderer": { "url": "grpc://127.0.0.1:7050", "tlsCACerts": { "pem": "" } }
  },
  "channels": {
    "mychannel": { "orderers": ["orderer"], "peers": { "peer0": {} } }
  }
}
EOF
fi

# 4. wallet: cryptogen-issued User1 as a fabric-network X.509 identity
if [ ! -f "${DATA}/wallet/User1.id" ]; then
  echo "    building wallet from User1 identity"
  IDDIR="${DATA}/crypto-config/peerOrganizations/${ORG}/users/User1@${ORG}/msp"
  CERT="${IDDIR}/signcerts/User1@${ORG}-cert.pem"
  KEY=$(ls "${IDDIR}"/keystore/*_sk 2>/dev/null | head -1)
  if [ -f "${CERT}" ] && [ -n "${KEY}" ]; then
    CERT_PEM=$(awk 'NF {printf "%s\\n", $0}' "${CERT}")
    KEY_PEM=$(awk 'NF {printf "%s\\n", $0}' "${KEY}")
    cat > "${DATA}/wallet/User1.id" <<EOF
{
  "name": "User1",
  "type": "X.509",
  "version": 1,
  "credentials": {
    "certificate": "${CERT_PEM}",
    "privateKey": "${KEY_PEM}"
  },
  "mspId": "Org1MSP"
}
EOF
  else
    echo "    WARNING: User1 identity not found under ${IDDIR}" >&2
  fi
fi

# 5. ccaas chaincode package (metadata.json + code.tar.gz w/ connection.json)
if [ ! -f "${DATA}/cc/${CC_LABEL}.tgz" ]; then
  echo "    packaging ccaas chaincode (${CC_LABEL})"
  STAGE="${DATA}/cc/stage"
  rm -rf "${STAGE}"; mkdir -p "${STAGE}"
  cp /app/config/ccaas/connection.json "${STAGE}/connection.json"
  printf '{"type":"ccaas","label":"%s"}\n' "${CC_LABEL}" > "${STAGE}/metadata.json"
  tar -czf "${STAGE}/code.tar.gz" -C "${STAGE}" connection.json
  tar -czf "${DATA}/cc/${CC_LABEL}.tgz" -C "${STAGE}" metadata.json code.tar.gz
  rm -rf "${STAGE}"
fi

# 6. package id: the peer computes packageid = "<label>:<sha256(tgz bytes)>"
#    (util.ComputeSHA256 over the exact install package). We cannot know it until
#    the package file exists, so compute the same hash deterministically from the
#    file. The chaincode-as-a-service server must register with this exact id, so
#    supervisord's chaincode program reads it from here.
if [ ! -f "${DATA}/cc/package-id" ] || [ ! -s "${DATA}/cc/package-id" ]; then
  echo "    computing ccaas package id"
  PKG_SHA=$(sha256sum "${DATA}/cc/${CC_LABEL}.tgz" | awk '{print $1}')
  echo "${CC_LABEL}:${PKG_SHA}" > "${DATA}/cc/package-id"
fi

echo "    artifacts ready under ${DATA}"