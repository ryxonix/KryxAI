# KryxAI · NBF-Lite / Fabric external anchor

> **Note on the defaults.** The text below describes the strict production
> posture (`KRYXAI_BLOCKCHAIN_EXTERNAL_ANCHOR=true` +
> `KRYXAI_BLOCKCHAIN_ANCHOR_REQUIRED=true`). KryxAI ships with
> `KRYXAI_BLOCKCHAIN_ANCHOR_REQUIRED=false` instead, so the API and CLI are
> usable on a machine with no Fabric network. The permissive default is never
> dishonest: an unanchored report is labelled `pending` or `demo` and its
> `chain_state` says so on every surface. Turn the gate on when you have a real
> network, and then a report that cannot be anchored is rejected outright.

> **Crypto material must be regenerated.** The Fabric org domain is
> `kryxai.example.com`. If you previously deployed this network under a
> different domain, delete `crypto-config/` and re-run `scripts/gen-crypto.sh`
> before bringing containers up, otherwise the bind mounts point at stale
> certificates and the peer fails to start.

**Mandatory, fail-closed in the strict posture** external counterpart to the
local evidence chain (see `kryxai/store.py`). With the production posture on
(`KRYXAI_BLOCKCHAIN_EXTERNAL_ANCHOR=true` + `KRYXAI_BLOCKCHAIN_ANCHOR_REQUIRED=true`),
every report's block gets a second, independently-verifiable commitment, and a
report that cannot be anchored is rejected (503, no block inserted):

1. the report PDF is encrypted (AES-256-GCM, org-custody key) and pinned to
   **IPFS** as ciphertext — raw content never leaves the operator,
2. the block hash, Merkle root, file SHA-256, IPFS CID and a key fingerprint
   are recorded on a **Hyperledger Fabric** ledger through this REST gateway,
3. anyone can verify the public anchor via the backend API:
   `GET /api/blockchain/onchain/{scan_id}`.

If the gateway is unreachable in the mandatory posture, `anchor_report` raises
`BlockAnchorError` — the local block is NOT inserted and the report endpoints
return 503 (see `external_anchor.py`). The graceful `pending` (retryable via
`POST /api/blockchain/retry/{scan_id}`) and truthful `demo` fallback statuses
exist **only** when the operator explicitly disables both flags for offline
dev/demo (`BLOCKCHAIN_EXTERNAL_ANCHOR=false` +
`BLOCKCHAIN_ANCHOR_REQUIRED=false`).

```
┌──────────────┐  POST /store (cipher b64)      ┌──────────────┐   IPFS (Kubo)
│  backend     │ ─────────────────────────────▶ │  gateway :4000 │ ─────────▶ encrypted PDF
│  (FastAPI)   │  POST /fabric/v1/invokecc      │  (express)      │  ┌──────┐
└──────────────┘ ─────────────────────────────▶ │   └─┬─────────┘  │ Hyperledger
       │                                        │    ▼            │ Fabric
       └─ GET /api/blockchain/onchain/{scan_id} │ fabric_client   └──► AnchorReport
                                                └──────────────┘
```

## 1. Gateway endpoints

| Method | Path                    | Body / query                                  | Returns |
|--------|-------------------------|-----------------------------------------------|---------|
| `GET`  | `/health`               | –                                             | `{ status }` |
| `POST` | `/store`                | `{ fileName, fileContents (base64) }`         | `{ hash: CID }` |
| `GET`  | `/retrieve/:cid`        | –                                             | `{ data (base64) }` |
| `POST` | `/fabric/v1/invokecc`   | `{ fcn, args, user, ccname, channel, cfgpath, local, mspId, txId }` | `{ tx_id, status }` |
| `GET`  | `/fabric/v1/querycc`    | `fcn=QueryReport&args=<scan_id>&user=...`     | `{ result }` |
| `POST` | `/fabric/v1/querycc`    | `{ fcn, args: [...] , user, ... }`            | `{ result }` |

## 2. Quick start (WSL2 Ubuntu + Docker)

Prereqs: Docker Desktop (WSL 2 backend), `docker compose`, Node ≥ 16.

```bash
# terminal 1 — Fabric test network (crypto, channel, chaincode)
cd deploy/nbf-fabric
./scripts/gen-crypto.sh                     # cryptogen MSPs (no Fabric CA)
./scripts/gen-connection-profile.sh         # connection-org1.json
docker compose -f docker-compose.yml up --build -d
./scripts/install-chaincode.sh              # deploy kryxai-posture chaincode

# terminal 2 — IPFS daemon
ipfs daemon --init                          # runs on :5001 (API) / :8080 (gateway)

# terminal 3 — REST gateway
cd deploy/nbf-fabric/gateway
npm install
IPFS_API_HOST=127.0.0.1 IPFS_API_PORT=5001 IPFS_GATEWAY=http://127.0.0.1:8080 \
AS_LOCALHOST=true CCP_FILE=../connection-org1.json WALLET_DIR=./wallet \
node server.js                              # listens on :4000

# sanity checks
curl http://localhost:4000/health
curl -X POST http://localhost:4000/store -H 'Content-Type: application/json' \
     -d '{"fileName":"t.pdf.enc","fileContents":"JVBERi0xLjQ="}'          # → { hash }
```

## 3. Free cloud deployment (Oracle Cloud Always Free ARM)

Full step-by-step (VM creation, firewall, Docker, both code-transfer methods,
and public-gateway vs SSH-tunnel modes): **`docs/nbflite-oracle-free-tier.md`**.

**No cloud account / no credit card?** Run the same stack in a GitHub
Codespace (Ubuntu + Docker built in) and expose the gateway via public port
forwarding — see **`docs/nbflite-codespaces.md`**.

Quick path — create a free `VM.Standard.A1.Flex` (Ubuntu 22.04 ARM), install
Docker, copy this folder, then:

```bash
bash scripts/deploy-cloud.sh     # crypto -> wallet -> compose up -> channel -> chaincode
bash scripts/harden-ports.sh     # ufw: allow only 22 + 4000 (or use an SSH tunnel)
```

Point the backend at the public gateway:

```ini
# backend/.env
BLOCKCHAIN_EXTERNAL_ANCHOR=true
NBF_GATEWAY_URL=http://<vm-public-ip>:4000
```

Safer demo mode (no public port — leave :4000 closed and tunnel instead):

```bash
ssh -i ~/.ssh/id_ed25519 -N -L 4000:localhost:4000 opc@<vm-public-ip>
# backend/.env:  NBF_GATEWAY_URL=http://localhost:4000
```

## 4. Enable on the backend

```ini
# backend/.env
BLOCKCHAIN_EXTERNAL_ANCHOR=true
NBF_GATEWAY_URL=http://localhost:4000
# optional overrides:
# NBF_CHANNEL=mychannel
# NBF_CC=kryxai-posture
# NBF_USER=User1
# NBF_MSP=Org1MSP
# IPFS_STORE_URL=http://localhost:4000/store
# REPORT_KEYS_DIR=reports/keys     # org master key custody
```

Restart the backend, then generate any forensic report. The block is mined,
the encrypted PDF pinned, and the Fabric anchor committed.

## 5. Verify an anchor

```bash
curl http://localhost:8000/api/blockchain/onchain/<scan_id>
```

The response runs a live end-to-end check:

- queries the chaincode `QueryReport(<scan_id>)` and compares the on-ledger
  `block_hash`, `file_sha256`, `merkle_root` fields to the local block,
- fetches the pinned ciphertext from IPFS (`GET /retrieve/:cid`),
- decrypts it with the org-derived report key and confirms the document is a
  `%PDF` whose SHA-256 matches the anchored hash.

It is **fail-open**: any unreachable service is reported in `problems`, never
masked as a false success. Also available:

- `GET /api/blockchain/onchain` — summary of anchored vs demo/pending anchors
- `GET /api/blockchain/verify/call/{scan_id}` — full local tamper-evidence
  check plus the external-anchor state
- `POST /api/blockchain/retry/{scan_id}` — re-attempt a `pending` anchor

## 6. Data-privacy notes (DPDP-first)

- The ledger stores only hashes, the IPFS CID and a 16-hex key fingerprint —
  **no** audio, transcript, names or decrypted content.
- The PDF is AES-256-GCM encrypted with a per-report key derived from an
  org-custody master key (`HMAC-SHA256(master, "kryxai-posture-anchor:"+scan_id)`);
  the key never leaves the operator machine.
- Chaincode invocation does not include caller PII.