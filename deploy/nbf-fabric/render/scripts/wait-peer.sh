#!/usr/bin/env bash
# KryxAI — wait for the peer gRPC endpoint AND for bootstrap (channel
# create/join + chaincode install/approve/commit) to finish before the gateway
# starts, so the gateway doesn't submit transactions mid-lifecycle.
set -uo pipefail

DATA=${DATA_DIR:-/app/data}

for _ in $(seq 1 300); do
  if [ -f "${DATA}/bootstrap-ready" ] \
     && (echo > /dev/tcp/127.0.0.1/7051) >/dev/null 2>&1; then
    exit 0
  fi
  sleep 2
done
echo "peer :7051 not reachable after wait" >&2
exit 1