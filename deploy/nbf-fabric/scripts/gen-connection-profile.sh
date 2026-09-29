#!/usr/bin/env bash
# KryxAI — generate the Fabric connection profile for the gateway.
# Writes gateway/connection-org1.json (referenced by CCP_FILE).
#   PEER_URL  host:port for peer0 (default localhost:7051 for host-run gateway;
#            set to peer0:7051 inside the compose network / kryxai-gateway).
set -euo pipefail

PEER_URL=${PEER_URL:-localhost:7051}
ORDERER_URL=${ORDERER_URL:-localhost:7050}
TLS_ENABLED=${TLS_ENABLED:-false}

cat > gateway/connection-org1.json <<EOF
{
  "name": "kryxai-network-org1",
  "version": "1.0.0",
  "client": {
    "organization": "Org1MSP",
    "connection": { "timeout": { "peer": { "endorser": "30s" } } }
  },
  "organizations": {
    "Org1MSP": {
      "mspid": "Org1MSP",
      "peers": ["peer0"],
      "certificateAuthorities": []
    }
  },
  "peers": {
    "peer0": {
      "url": "grpc://${PEER_URL}",
      "tlsCACerts": { "pem": "" },
      "grpcOptions": { "grpc.keepalive_time_ms": 600000 }
    }
  },
  "orderers": {
    "orderer": { "url": "grpc://${ORDERER_URL}", "tlsCACerts": { "pem": "" } }
  },
  "channels": {
    "mychannel": {
      "orderers": ["orderer"],
      "peers": { "peer0": {} }
    }
  }
}
EOF

echo "Wrote gateway/connection-org1.json (peer=${PEER_URL}, tls=${TLS_ENABLED})"
echo "Populate the gateway wallet with: bash scripts/build-wallet.sh"