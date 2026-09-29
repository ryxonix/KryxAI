# syntax=docker/dockerfile:1
#
# Kubo release tag for the official ipfs/kubo image (flaky HTTP tarball mirrors).
ARG KUBO_IMAGE_TAG=v0.43.0
#
# KryxAI — single-container NBF anchor image for Render / Cloud Run.
#
# Everything runs in ONE container (no Docker-in-Docker):
#   fabric-orderer (single-node solo) + fabric-peer (goleveldb) +
#   kryxai-posture chaincode as a chaincode-as-a-service gRPC server +
#   Kubo IPFS (offline) + the trimmed nbf-samplerest gateway (bind $PORT).
#
# Build (from deploy/nbf-fabric, so the context has go/ + gateway/ + render/).
# NOTE: Fabric 2.2 LTS publishes linux-amd64 binaries only — build amd64:
#   docker buildx build --platform linux/amd64 \
#     -f render/Dockerfile -t <dockerhub-user>/nbf-lite-kryxai:latest .
#
# See render/README.md for push + Render/Cloud Run deployment.

# ---- Stage 1: build the ccaas chaincode server binary ---------------------
FROM golang:1.24 AS cc-builder
WORKDIR /src
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/kryxai-posture-server .

# ---- Stage 2: gateway node deps -------------------------------------------
FROM node:20 AS gateway-deps
WORKDIR /app/gateway
COPY gateway/package.json gateway/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY gateway/ ./

# ---- Stage 3: Kubo IPFS binary source (official image) ---------------------
# The dist.ipfs.tech / GitHub release tarball endpoints intermittently 404 in
# CI, which broke curl -fSL; Docker Hub pulls are reliable from GHA runners.
FROM ipfs/kubo:${KUBO_IMAGE_TAG} AS kubo

# ---- Stage 4: runtime (Ubuntu 22.04) ----------------------------------------
# glibc >= 2.34 is required by ipfs/kubo release binaries (needs GLIBC_2.34);
# Ubuntu 22.04 ships glibc 2.35 and still runs the Fabric 2.2 binaries.
FROM ubuntu:22.04 AS runtime

ARG TARGETARCH
# Fabric releases only publish linux-amd64 binary tarballs for the 2.2 LTS line.
# v2.2.15 is the last 2.2.x release and matches the deploy stack (peer:2.2).
ARG FABRIC_VERSION=2.2.15

ENV FABRIC_CFG_PATH=/app/config \
    HOME=/app \
    DATA_DIR=/app/data \
    PATH=/usr/local/bin:/usr/bin:/bin

# base tools + supervisor
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl tar gzip bash python3 supervisor \
 && rm -rf /var/lib/apt/lists/*

# Node 20 runtime from NodeSource (avoid mixing the Debian-based node:20 image's
# /usr/local into ubuntu:22.04). gateway/ node_modules are pure JS and copy over.
RUN set -eux; \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*

# Kubo IPFS binary — pulled from the official image stage above.
COPY --from=kubo /usr/local/bin/ipfs /usr/local/bin/ipfs

# Fabric 2.2 binaries (Official release tarball: peer, orderer, cryptogen, configtxgen)
RUN set -eux; \
    ARCH="${TARGETARCH:-amd64}"; \
    [ "${ARCH}" = "amd64" ] || { echo "Fabric 2.2 binaries are published for linux-amd64 only; build with --platform linux/amd64"; exit 1; }; \
    curl -fsSL "https://github.com/hyperledger/fabric/releases/download/v${FABRIC_VERSION}/hyperledger-fabric-linux-amd64-${FABRIC_VERSION}.tar.gz" -o /tmp/fabric.tgz; \
    mkdir -p /tmp/fabric-release; \
    tar -xzf /tmp/fabric.tgz -C /tmp/fabric-release; \
    D=$(find /tmp/fabric-release -maxdepth 2 -type f -name peer -printf '%h\n' | head -n1); \
    cp "${D}/peer" "${D}/orderer" "${D}/cryptogen" "${D}/configtxgen" /usr/local/bin/; \
    rm -rf /tmp/fabric-release /tmp/fabric.tgz

# Chaincode-as-a-service server + gateway app
COPY --from=cc-builder /out/kryxai-posture-server /usr/local/bin/kryxai-posture-server
COPY --from=gateway-deps /app/gateway /app/gateway

# Config, external builder, supervisor + scripts
WORKDIR /app
COPY render/config /app/config
COPY render/ccaas_builder /opt/hyperledger/ccaas_builder
COPY render/supervisord.conf /app/supervisord.conf
COPY render/docker-entrypoint.sh /app/docker-entrypoint.sh
COPY render/scripts /app/scripts

RUN chmod +x /app/docker-entrypoint.sh /app/scripts/*.sh /opt/hyperledger/ccaas_builder/bin/*

EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=300s --retries=3 \
  CMD /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/${PORT:-4000} >/dev/null 2>&1 || exit 1'

ENTRYPOINT ["/app/docker-entrypoint.sh"]