# Plan A — Swap to the official NBFLite gateway (zero cost)

This guide lets the KryxAI backend anchor reports onto the **official
MeitY/C-DAC NBFLite** sandbox instead of our trimmed gateway. It costs
nothing: NBFLite is free software, it runs on your own machine (WSL2 +
free Docker Desktop), and no cloud resource is provisioned.

The backend code already tolerates NBFLite's response quirks (camelCase
`ReportAnchor` fields, result-as-JSON-string, base64-text IPFS payloads), so
this is a deployment + config exercise, not a code project.

```
backend ──rest──▶ NBFLite samplerest gateway ──fabric-network──▶ NBFLite single-node Fabric
        ──rest──▶   /store, /retrieve ──▶ Kubo IPFS
```

---

## 1. Download NBFLite (free)

- Portal: https://blockchain.meity.gov.in → "Download NBFLite"
  (or https://cdacchain.in/nbflite/). Fill the registration form
  (https://cforms.in/formview/NBFLiteReg) — C-DAC emails you the archive.
- Contact for the actual archive: `cdacchain@cdac.in`.
- Unzip to e.g. `~/nbflite` inside your WSL2 Ubuntu home (or `/mnt/c/...`).

## 2. Host prereqs (free)

- Windows 10/11 with **WSL2** enabled, then:
  ```bash
  wsl --install -d Ubuntu        # PowerShell, admin
  docker --version                # in Ubuntu; Docker Desktop 4.x is free
  ```
- The archive ships its own `docker_images`, compose file and the
  `nbf-samplerest` gateway. Use **their** compose, not ours.

## 3. Bring up their network

```bash
cd ~/nbflite
bash ./script/gen_org.sh          # or ./nbf_c/startNetwork.sh — see the README they ship
docker compose up -d              # peer, orderer, ca, couchdb, ipfs, gateway
curl http://localhost:4000/health
```

Note the details you'll need for the backend (the next section):
`CHANNEL`, `CCNAME` (e.g. `mychannel` / `fabcar`), the registered `USER`
(e.g. `User1`), the MSP id (e.g. `Org1MSP`), and the connection profile
path your gateway uses (`cfgpath`).

## 4. Deploy the KryxAI anchors chaincode

Our chaincode (`deploy/nbf-fabric/go/kryxai-posture.go`) is a fabcar-style
CRUD, so it deploys onto NBFLite unchanged:

```bash
# inside the NBFLite dir, after the network is up
CC_PATH=./go  # or copy ../deploy/nbf-fabric/go into your NBFLite tree
bash ../deploy/nbf-fabric/scripts/install-chaincode.sh   # adapt container names (nbf_peer0)
```

If NBFLite's lifecycle tooling differs, deploy the equivalent steps with
`peer lifecycle chaincode package/install/approveformyorg/commit`, naming it
`kryxai-posture`.

## 5. Run a gateway the backend can reach

Two options — prefer (a):

**(a) Keep our trimmed gateway, point it at their network.**
Zero backend change; identity comes from their wallet + connection profile.

```bash
cd deploy/nbf-fabric/gateway
npm install                                   # free, local
cp /path/to/nbflite/generated/connection-org1.json .
                                              # NBFLite's generated connection profile
# Wallet identity: enroll the same org user NBFLite created (their CA). The
# bundled scripts/build-wallet.sh only works with OUR cryptogen layout, so for
# an NBFLite network use their enroll/registerUser wallet instead.
CCP_FILE=./connection-org1.json WALLET_DIR=./wallet \
  AS_LOCALHOST=true node server.js            # :4000
```

**(b) Use their `nbf-samplerest` gateway instead.**
Backend config identical to (a) except `nbf_cfgpath`/`nbf_user` should match
their defaults; the backend auto-detects their IPFS base64-text payloads, so
no extra setting is needed (`NBF_IPFS_MODE=auto`).

## 6. Point the backend at it

```ini
# backend/.env
BLOCKCHAIN_EXTERNAL_ANCHOR=true
NBF_GATEWAY_URL=http://localhost:4000
NBF_CHANNEL=mychannel          # ← NBFLite's channel name
NBF_CC=kryxai-posture      # ← chaincode deployed in step 4
NBF_USER=User1                 # ← identity enrolled in the gateway wallet
NBF_MSP=Org1MSP                # ← NBFLite org MSP id
NBF_CFGPATH=                   # leave blank unless their gateway requires it
NBF_IPFS_MODE=auto             # auto | raw (our gateway) | base64text (their sample)
# IPFS_STORE_URL=              # defaults to {gateway}/store
```

Restart the backend (Windows dev box: same `F:\kryxai` tree — the
gateway can even run in WSL2 localhost-forwarded to Windows).

## 7. Verify end-to-end

```bash
# sanity: gateway
curl http://localhost:4000/health
curl -X POST http://localhost:4000/store -H 'Content-Type: application/json' \
     -d '{"fileName":"t.pdf.enc","fileContents":"JVBERi0xLjQ="}'       # → {hash}

# run any scan, e.g. `kryxai scan corpus/02_star_ttlssuppressed_vodafone_style.pcap`, then:
curl http://localhost:8000/api/blockchain/onchain/<scan_id>             # expect verified:true
curl http://localhost:8000/api/blockchain                            # anchor summary
```

## Pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `on-chain query failed (fail-open)` | `NBF_CHANNEL`/`NBF_CC`/`NBF_USER`/`NBF_MSP` misconfigured | Re-check step 6 values against NBFLite's README |
| Hashes/CIDs right but `does not decrypt` | Gateway pins base64 *text* instead of raw bytes | Set `NBF_IPFS_MODE=base64text` (or leave `auto`) |
| `identity "User1" missing` | Wallet not built / wrong wallet dir | Run `build-wallet.sh` with their CA, or point `WALLET_DIR` at their wallet |
| Chaincode not found | CC not installed/committed on their channel | Run step 4 against their peer |
| Anchor stays `pending` | Gateway unreachable at anchor time | Fix gateway, then `POST /api/blockchain/retry/{scan_id}` |

## Zero-cost checklist

- NBFLite archive: free (MeitY/C-DAC registration).
- Docker Desktop + WSL2 Ubuntu: free.
- No cloud, no paid API keys, no new npm/pip dependencies.
- Local PoW chain remains authoritative; the anchor is fail-open the whole time.