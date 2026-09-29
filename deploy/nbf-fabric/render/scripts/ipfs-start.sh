#!/usr/bin/env bash
# KryxAI — start the Kubo IPFS daemon (offline single-node mode).
# Offline keeps the container private and cheap: /api/v0/add and the local
# HTTP gateway work; no swarm peering.
set -euo pipefail

export IPFS_PATH=${IPFS_PATH:-/app/data/ipfs}
mkdir -p "${IPFS_PATH}"

if [ ! -f "${IPFS_PATH}/config" ]; then
  echo "    ipfs init"
  ipfs init
  ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["*"]'
fi

exec ipfs daemon --offline --migrate=true