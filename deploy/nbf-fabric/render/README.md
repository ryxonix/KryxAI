# KryxAI — single-container Fabric anchor (Render / Cloud Run)

Builds **one Docker image** that runs a full minimal Fabric NBF anchor on the
Render Free / Google Cloud Run free tiers (512 MB, no Docker, no persistent
filesystem guarantee):

- Fabric **orderer** (solo ordering, system-channel genesis)
- Fabric **peer** (goleveldb, no CouchDB, no CA)
- **kryxai-posture** chaincode as a **chaincode-as-a-service** gRPC server
- Kubo **IPFS** daemon (offline single-node)
- trimmed **nbf-samplerest**-compatible REST gateway (`server.js`)

Everything lives in one container and is supervised by `supervisord`.

## Versions

- Hyperledger Fabric **v2.2.15** (last 2.2.x; matches the stack used in
  `deploy/nbf-fabric`. Fabric 2.2 publishes **linux-amd64 only** — the image
  must be built/run as `linux/amd64`, and the Dockerfile refuses other arches).
- `fabric-contract-api-go v1.2.2` chaincode, run with `shim.ChaincodeServer`.
- Kubo (IPFS) `v0.43.0` (runs `ipfs daemon --offline`).
- Node.js 20 (NodeSource) on Ubuntu 22.04 runtime (glibc 2.35 for Kubo).

## How it works (boot sequence)

`docker-entrypoint.sh` (see `docker-entrypoint.sh`):

1. `gen-network.sh` — on first boot: cryptogen identities, configtxgen
   genesis + channel tx, gateway connection profile, fabric-network wallet,
   the ccaas `kryxai-posture_1.0.tgz` package, and the deterministic
   **package id** (label + sha256 of the package file) at
   `${DATA_DIR}/cc/package-id`.
2. start `supervisord`: `orderer` → `ipfs` → `chaincode` (ccaas server) →
   `peer` → `gateway`.
3. `bootstrap.sh` — wait for ports, `channel create/join mychannel`, install
   the ccaas package, approve + commit `kryxai-posture`, smoke-test
   `QueryAll`.

Chaincode-as-a-service detail (why the package id file exists): when a peer
installs a ccaas package it dials **out** to the chaincode server at
`connection.json`'s `address` (`127.0.0.1:9999`). The chaincode server must
register with the same id the peer computed, i.e. the **package id**
(`<label>:<sha256>`), so `supervisord` runs `/app/scripts/chaincode-run.sh`,
which reads the id from `${DATA}/cc/package-id` and exports the equivalent of
`CORE_CHAINCODE_ID_NAME` before exec'ing the Go server. The `ccaas_builder`
(`/opt/hyperledger/ccaas_builder`) implements the Fabric external-builder
contract: `detect` (2 args), `build` (3 args → writes connection.json),
`release` (2 args → writes `chaincode/server/connection.json`, which is where
the 2.2 peer looks on launch).

## Build & push

The build context is the parent `deploy/nbf-fabric` (contains `go/`, `gateway/`,
`render/`). The Fabric version is pinned by the release tarball download, so a
`--network=host`-friendly builder with Internet access is needed.

```bash
cd deploy/nbf-fabric

# Must be amd64 (Fabric 2.2 has no arm64 binaries) — the Dockerfile enforces it.
docker buildx build --platform linux/amd64 \
  -f render/Dockerfile \
  -t <dockerhub-user>/nbf-lite-kryxai:latest .
docker push <dockerhub-user>/nbf-lite-kryxai:latest
```

Optional build args: `FABRIC_VERSION=2.2.15`, `KUBO_VERSION=0.43.0`.

## Deploy on Render

1. Push the image to Docker Hub (above).
2. New → Web Service → **Deploy from Docker image** → your image + tag.
3. Instance type: **Free** (512 MB RAM, 0.1 CPU).
4. Health check path: `/health` (the gateway exposes it; the container also
   has its own `HEALTHCHECK` on the port).
5. Port: the gateway respects `PORT` (Render injects it). Render sets `PORT`
   for Docker services; `GATEWAY_PORT` (default 4000) is the fallback.
6. No persistent disk by default on Free — see caveats.

The gateway needs a few env vars (the container supplies sensible defaults):

| Env | Default | Purpose |
|---|---|---|
| `PORT` | Render sets it / `4000` | REST gateway listen port |
| `CCP_FILE` | `/app/data/connection-org1.json` | connection profile |
| `WALLET_DIR` | `/app/data/wallet` | X.509 wallet (User1) |
| `IPFS_API_HOST` / `IPFS_API_PORT` | `127.0.0.1` / `5001` | Kubo API |
| `IPFS_GATEWAY` | `http://127.0.0.1:8080` | Kubo HTTP gateway |
| `DATA_DIR` | `/app/data` | all Fabric/IPFS state |

Backend integration (the KryxAI app that consumes this anchor):

- `BLOCKCHAIN_EXTERNAL_ANCHOR=true`
- `NBF_GATEWAY_URL=https://<your-service>.onrender.com`
- `NBF_IPFS_MODE=auto`

## Deploy on Cloud Run

```bash
# amd64 only (Fabric 2.2). Build/push the image as above, then:
gcloud run deploy nbf-lite-kryxai \
  --image <dockerhub-user>/nbf-lite-kryxai:latest \
  --platform managed --region us-central1 --allow-unauthenticated \
  --memory 512Mi --cpu 1 --port 4000 --concurrency 8 --timeout 300
```

Cloud Run injects `PORT=8080`; if you keep `--port 4000` the gateway uses
`GATEWAY_PORT=4000` as `app.listen` falls back to it. Or just pass
`--port 8080 --set-env-vars GATEWAY_PORT=8080`.

## API (gateway)

Mirrors the `nbf-samplerest` contract (`deploy/nbf-fabric/docs`):

- `GET  /health` — liveness
- `POST /store` — `{fileName, fileContents(base64)}` → `{hash}` (IPFS pin)
- `GET  /retrieve/:cid` — `{data(base64)}` (IPFS fetch)
- `POST /fabric/v1/invokecc` — `{fcn, args, user, ccname, channel, cfgpath, local, mspId, txId}` → `{tx_id}`
- `GET/POST /fabric/v1/querycc` — same args; returns `{result}`

## Caveats (free tiers)

- **Ephemeral disk.** On Render Free and Cloud Run, `/app/data` is not durable
  across redeploys/cold starts, so the ledger, MSP material and IPFS pins are
  regenerated on each fresh boot. The image is fully idempotent
  (`gen-network.sh`/`bootstrap.sh` are all guarded), but **anchored data is
  lost** unless you mount a persistent disk — treat Free tier as a demo/lab.
- **Cold start** ~2–4 min: orderer/peer/gateway supervised boot + chaincode
  lifecycle on first request. Render Free sleeps the instance; the first hit
  after sleep will be slow.
- **No persistent identity rotation**: identities are cryptogen-generated per
  fresh disk. Production should use a real Fabric CA / pre-seeded
  `crypto-config`.
- **Single orderer, solo**: not BFT/highly-available. Fine for lab anchors.

## Layout (inside the image)

```
/app/docker-entrypoint.sh      boot order (gen → supervisord → bootstrap)
/app/supervisord.conf          process manager + memory caps
/app/config/core.yaml          peer config (goleveldb, ccaas builder)
/app/config/orderer.yaml       orderer config (BootstrapFile=genesis.block)
/app/config/configtx.yaml      genesis + mychannel profiles (solo)
/app/ccaas_builder/bin/        detect | build | release (external builder)
/app/scripts/                  gen-network / bootstrap / chaincode-run / …
/usr/local/bin/orderer peer    cryptogen configtxgen ipfs kryxai-posture-server
```