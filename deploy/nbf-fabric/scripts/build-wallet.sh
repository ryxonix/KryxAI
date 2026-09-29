#!/usr/bin/env bash
# KryxAI — build the Fabric filesystem wallet for the gateway from the
# cryptogen-issued User1 identity. Run after gen-crypto.sh.
# Writes gateway/wallet/<label>.id in the fabric-network X.509 identity format.
set -euo pipefail

LABEL=${WALLET_LABEL:-User1}
IDDIR=crypto-config/peerOrganizations/kryxai.example.com/users/User1@kryxai.example.com/msp
WALLET=gateway/wallet

mkdir -p ${WALLET}
CERT=${IDDIR}/signcerts/User1@kryxai.example.com-cert.pem
KEY=$(ls ${IDDIR}/keystore/*_sk | head -1)

if [ ! -f "${CERT}" ] || [ -z "${KEY}" ]; then
  echo "Missing User1 identity under ${IDDIR} — run scripts/gen-crypto.sh first" >&2
  exit 1
fi

CERT_PEM=$(awk 'NF {printf "%s\\n", $0}' "${CERT}")
KEY_PEM=$(awk 'NF {printf "%s\\n", $0}' "${KEY}")

cat > ${WALLET}/${LABEL}.id <<EOF
{
  "name": "${LABEL}",
  "type": "X.509",
  "version": 1,
  "credentials": {
    "certificate": "${CERT_PEM}",
    "privateKey": "${KEY_PEM}"
  },
  "mspId": "Org1MSP"
}
EOF

echo "Wrote ${WALLET}/${LABEL}.id (gateway logs in as '${LABEL}')"