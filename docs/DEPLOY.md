# Deploying KryxAI free on Render

Two services, one repository, one account, **$0**. No credit card required.

| Service | Type | URL | Sleeps? |
|---|---|---|---|
| `kryxai-web` | Static site | `https://kryxai-web.onrender.com` | No — served from Render's CDN |
| `kryxai-api` | Web service, `plan: free` | `https://kryxai-api.onrender.com` | Yes — after 15 min idle |

The API image is a single Python stage. The React SPA is built by Render's static
site service, so the API image needs no Node toolchain.

---

## 1. Prerequisites

- The repository pushed to GitHub, with `KryxAI/` as the **repo root** (so that
  `render.yaml`, `Dockerfile`, and `frontend/` sit at the top level).
- A Render account. The Hobby workspace plan is $0 and seats one member.

## 2. Deploy

1. Render Dashboard → **New → Blueprint**.
2. Connect the repository. Render reads `render.yaml` and creates both services.
3. Wait for the static build and the Docker build to go green.
4. Open the **static site** URL. The API is called cross-origin, so the SPA and
   the API are two different URLs by design.

Validate the blueprint before applying if you have the CLI:

```bash
render blueprints validate render.yaml
```

## 3. Verify the deployed API

```bash
# Liveness. Should print status ok, chain_id KryxAIV1, external_anchor false.
curl -s https://kryxai-api.onrender.com/health

# A real analysis, end to end. The Vodafone-style STARTTLS-suppression capture
# should return posture_grade "F" and chain_state "pending".
# demo_captures/ is gitignored, so generate a capture first if you do not have
# one:  kryxai corpus
curl -s -X POST -F "file=@demo_captures/02_star_ttlssuppressed_vodafone_style.pcap" \
  https://kryxai-api.onrender.com/api/v1/upload
```

`chain_state` must read `pending`, never `anchored`. There is no Fabric network
in this deployment, and the app is built to say so rather than imply an anchor
it does not have.

## 4. Reproduce the build locally

```bash
# API image
docker build -t kryxai-api:local -f Dockerfile .
docker run --rm -p 8000:10000 kryxai-api:local
curl -s http://127.0.0.1:8000/health

# Static site (Linux, with the pinned Node that Vite 8 requires)
docker run --rm -v "$PWD/frontend:/app" -w /app \
  -e VITE_API_BASE=https://kryxai-api.onrender.com \
  node:22.12.0 sh -c "npm ci && npm run build"
```

The static build writes `frontend/dist`, which is what `staticPublishPath`
publishes.

---

## What the free tier actually gives you

| Limit | Value |
|---|---|
| Compute | 0.1 CPU / 512 MB RAM |
| Instance hours | 750 / month (a month has ~720) |
| Build minutes | 500 / month |
| Outbound bandwidth | 5 GB, then $0.15/GB |
| Persistent disk | **None on free** |

Measured on the built image: **48 MiB resident** after a full scan including PDF
render. The 512 MB budget is not the constraint — CPU is.

### What resets

`KRYXAI_HOME=/data` holds the SQLite evidence chain, the rendered reports, and
the report signing key. **Render's free tier has no persistent disk, so all of it
is lost on every spin-down and every redeploy.** After a restart the chain is
empty and a new signing key is generated.

This is fine for a demo. It is not durable evidence storage, and the deployment
should not be described as one. If you need the chain to survive restarts you
need a paid plan with a disk, or an external database.

Report bodies are additionally held in a per-process LRU
(`_SCAN_CACHE_MAX` in `kryxai/api.py`), so report retrieval is lost on restart
even before the disk is considered. This is also why the API runs `--workers 1`:
a second worker would answer 404 for a scan the first worker had analysed.

### Performance

0.1 CPU is slow. The demo captures are small and scan in a couple of seconds.
A large capture will be noticeably slower and may hit Render's request timeout.
The static site is unaffected — it is CDN-served and always instant.

---

## The Fabric + IPFS anchor

The anchor is **not** part of this deployment, and it cannot be: its own
`supervisord.conf` sets `GOMEMLIMIT` caps that sum to **628 MiB** (orderer 128 +
ipfs 96 + chaincode 64 + peer 340) against a 512 MB free instance. It will be
OOM-killed.

The app is fully functional without it. `KRYXAI_BLOCKCHAIN_ANCHOR_REQUIRED`
stays `false`, so reports are generated and labelled `pending` / `demo` and are
never labelled `anchored`.

If you want the anchor for a demo, run it separately where there is enough
memory — Cloud Run's free tier has 2M requests/month, 180,000 vCPU-seconds and
360,000 GiB-seconds, and scales to zero between requests. That budget is
roughly two days of continuous 1 vCPU, so scale-to-zero is what makes it work.

```bash
cd deploy/nbf-fabric

# Fabric 2.2 publishes linux-amd64 binaries only, so build for amd64 explicitly
# (required on Apple Silicon).
docker buildx build --platform linux/amd64 \
  -f render/Dockerfile -t <dockerhub-user>/nbf-lite-kryxai:latest .
docker push <dockerhub-user>/nbf-lite-kryxai:latest

gcloud run deploy nbf-lite-kryxai \
  --image <dockerhub-user>/nbf-lite-kryxai:latest \
  --region us-central1 --allow-unauthenticated \
  --memory 1Gi --cpu 1 --concurrency 1 --timeout 300 --min-instances 0
```

Use `--concurrency 1` and `--min-instances 0`: a Fabric network is
stateful and single-writer, so it must not scale out, and it should not stay
warm between demos.

Then point the API at it, on the `kryxai-api` service:

| Variable | Value |
|---|---|
| `KRYXAI_BLOCKCHAIN_EXTERNAL_ANCHOR` | `true` |
| `KRYXAI_NBF_GATEWAY_URL` | `https://nbf-lite-kryxai-xxxx.a.run.app` |
| `KRYXAI_NBF_IPFS_MODE` | `auto` |

> The `KRYXAI_` prefix is required. `Settings` in `kryxai/config.py` sets
> `env_prefix="KRYXAI_"`, so an unprefixed `NBF_GATEWAY_URL` is silently ignored.
> Note that `deploy/nbf-fabric/render/README.md` documents these variables
> *without* the prefix; that document is wrong on this point.

> Cloud Run discards the ledger on every cold start, exactly like Render's
> ephemeral disk. Anchors written to a previous instance are gone. The image is
> idempotent and regenerates its network on boot, but the anchored data is not
> recovered. Treat the anchor as a live demo, not an archive.

---

## Troubleshooting

**`SettingsError: error parsing value for field "cors_origins"`**
`cors_origins` is a `List[str]`, and pydantic-settings JSON-decodes complex
fields from the environment. The value must be valid JSON:
`'["https://kryxai-web.onrender.com"]'`. A comma-separated string crashes the
API at import.

**SPA loads but every request fails / "Cannot reach the KryxAI API"**
`VITE_API_BASE` is inlined by Vite at **build** time. If you renamed or
repointed the API, the static site must be rebuilt — a redeploy of the API
alone will not update the bundle. Also confirm the API's
`KRYXAI_CORS_ORIGINS` lists the static site's exact origin.

**Static build fails with a Node engine error**
Vite 8 requires Node 20.19+ / 22.12+. `NODE_VERSION` is pinned to `22.12.0` in
`render.yaml` for this reason; do not remove it.

**First request after 15 minutes returns a loading page**
That is Render's free spin-down, roughly a minute to wake. Expected, not a bug.

**`npm ci` fails locally with `EPERM ... unlink` on Windows**
A running Vite dev server holds the native rolldown binding open. Stop it, or
build in a container as shown above.

**Renaming a service**
Render derives the hostname from the service name, so renaming `kryxai-web`
means updating `KRYXAI_CORS_ORIGINS` on the API *and* `VITE_API_BASE` on the
static site, then redeploying both.
