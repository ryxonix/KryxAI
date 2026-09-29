# Run the NBF anchor on a free oracle cloud ARM VM

Deploy the KryxAI NBF anchor stack (Hyperledger Fabric 2.2 + Kubo IPFS +
REST gateway) on an **Oracle Cloud Always Free** Ampere ARM instance running
Ubuntu. Everything here is ₹0/$0:

- `VM.Standard.A1.Flex` — free tier caps: 4 OCPU + 24 GB RAM + 200 GB boot.
- Docker Engine + Docker Compose — free, apt-installed on the VM.
- The stack is the self-hosted NBF-compatible one in `deploy/nbf-fabric/`
  (`scripts/deploy-cloud.sh`), which needs no NBFLite registration.

```
Windows dev box (backend) ──http──▶ VM :4000 gateway ──fabric-network──▶ Fabric(:7050/:7051)
                        ──http──▶               └──────────────▶ IPFS (Kubo :5001/:8080)
```

---

## 1. Create the free VM (≈10 minutes)

1. Sign up at https://cloud.oracle.com → "Always Free" (Oracle may ask for a
   card at signup but charges nothing on free-tier resources).
2. Create a Compute instance:
   - **Image**: Canonical Ubuntu 22.04 (ARM).
   - **Shape**: `VM.Standard.A1.Flex`, **2 OCPU / 12 GB RAM** (within the
     4 OCPU / 24 GB always-free allowance; leave the rest free for other uses).
   - **Networking**: default VCN + subnet; upload your **SSH public key**.
3. Saving the instance prints a **Public IP** — note it (e.g. `203.0.113.9`).

## 2. Open only what is needed

VCN → **Virtual Cloud Networks** → your VCN → **Security Lists** → default →
"Add Ingress Rules" — allowed in from anywhere (or restrict `0.0.0.0/0`):

| Direction | Protocol | Port | Purpose |
|-----------|----------|------|---------|
| Ingress   | TCP      | 22   | SSH |
| Ingress   | TCP      | 4000 | gateway (skip if you use the SSH tunnel mode, §6b) |

Everything else stays **closed**. The stack's internal ports
(5001/8080 Kubo IPFS, 5984 CouchDB, 7050 orderer, 7051 peer) must
never be exposed — the Kubo API on :5001 is unauthenticated.

## 3. SSH in + install Docker

```bash
ssh -i ~/.ssh/id_ed25519 opc@<PUBLIC_IP>
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER && newgrp docker
docker --version && docker compose version
```

## 4. Get the code onto the VM — either method

### 4a. scp from this Windows box (no repo remote needed)

From PowerShell on the Windows machine:

```powershell
scp -i "$env:USERPROFILE\.ssh\id_ed25519" -r "F:\kryxai\deploy\nbf-fabric" opc@<PUBLIC_IP>:/home/opc/kryxai/
ssh -i "$env:USERPROFILE\.ssh\id_ed25519" opc@<PUBLIC_IP> "cd /home/opc/kryxai/nbf-fabric && pwd"
```

### 4b. git clone (if the repo has a remote)

```bash
git clone <your-repo-url> kryxai
cd kryxai/deploy/nbf-fabric
```

(Add a remote if you have one: `git -C F:\kryxai remote add origin <url> && git push -u origin main` — the repo has real commit history, not a single initial commit.)

## 5. Deploy the whole stack (self-contained)

```bash
cd /home/opc/kryxai/nbf-fabric        # per your method above
bash scripts/deploy-cloud.sh
```

The script (see `scripts/deploy-cloud.sh`) does everything:

- `gen-crypto.sh` — Org1 + Orderer crypto + channel config,
- `gen-connection-profile.sh` + `build-wallet.sh` — gateway connection profile
  and the `User1` wallet identity,
- `docker compose up -d --build` — peer, orderer, CouchDB, **Kubo IPFS and
  the gateway** in one network (cryptogen identities, no Fabric CA; no separate
  IPFS daemon needed on the VM; the compose sets `AS_LOCALHOST=false` for
  docker-internal discovery),
- channel `mychannel` creation + join,
- `install-chaincode.sh` — package/install/approve/commit `kryxai-posture`.

Smoke-test on the VM:

```bash
curl http://localhost:4000/health
curl -X POST http://localhost:4000/store -H 'Content-Type: application/json' \
     -d '{"fileName":"t.pdf.enc","fileContents":"JVBERi0xLjQ="}'          # → { "hash": "Qm..." }
```

## 6. Connect the backend — two equal options

### 6a. Public gateway on :4000

- Announce the gateway reachable:
  ```bash
  bash scripts/harden-ports.sh   # ufw: allow 22 + 4000, deny everything else
  ```
  (or add the TCP 4000 ingress rule from §2 if you skipped it).
- Windows `backend/.env`:
  ```ini
  BLOCKCHAIN_EXTERNAL_ANCHOR=true
  NBF_GATEWAY_URL=http://<PUBLIC_IP>:4000
  NBF_CHANNEL=mychannel
  NBF_CC=kryxai-posture
  NBF_USER=User1
  NBF_MSP=Org1MSP
  NBF_IPFS_MODE=auto
  ```

### 6b. SSH tunnel — no public port at all

Keeps the gateway private; safest for a lab demo.

```bash
ssh -i ~/.ssh/id_ed25519 -N -L 4000:localhost:4000 opc@<PUBLIC_IP>
```

- Windows `backend/.env`:
  ```ini
  BLOCKCHAIN_EXTERNAL_ANCHOR=true
  NBF_GATEWAY_URL=http://localhost:4000
  NBF_IPFS_MODE=auto
  ```
- The tunnel must stay open while the backend anchors reports.

## 7. Verify end-to-end

1. Restart the backend (`cd F:\kryxai\backend && venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000`).
2. Run a scan, e.g. `kryxai scan capture.pcap`.
3. Verify the anchor:
   ```bash
   curl http://localhost:8000/api/blockchain/onchain/<scan_id>     # expect "verified": true
   curl http://localhost:8000/api/blockchain                        # anchor summary
   ```
   The check queries `QueryReport`, pulls the IPFS ciphertext, decrypts it and
   compares the SHA-256 + `%PDF` magic. With the mandatory posture on
   (`BLOCKCHAIN_ANCHOR_REQUIRED=true`, the default), a call that is not really
   anchored is reported truthfully (never a false pass); when the VM is off,
   anchoring fails hard — the block is not inserted and the report endpoints
   return 503 until the gateway is back. The `pending` (retryable) / `demo`
   statuses only appear when the operator explicitly disables the mandatory
   flags for offline dev/demo.

## 8. Official NBFLite swap later (optional)

Once the stack works, you can replace it with the C-DAC NBFLite distro on the
*same* free VM (their compose + `nbf-samplerest`). The backend is already
tolerant of their envelopes — just point `NBF_CHANNEL`/`NBF_CC`/`NBF_USER`/
`NBF_MSP` at their values and keep `NBF_IPFS_MODE=auto`. See
`docs/nbflite-swap.md`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `on-chain query failed (fail-open)` | Backend can't reach :4000 or bad `NBF_*` names | `curl http://<PUBLIC_IP>:4000/health` from a browser/Windows; re-check channel/cc/user/msp |
| `identity "User1" missing in wallet` | Wallet not built on the VM | `bash scripts/build-wallet.sh` after `gen-crypto.sh` |
| `chaincode not found` | CC not committed | Re-run `scripts/install-chaincode.sh`; check `docker exec kryxai-peer0 peer lifecycle chaincode queryinstalled` |
| Anchor stuck `pending` | Gateway unreachable at anchor time | Fix gateway; `POST /api/blockchain/retry/{scan_id}` |
| `does not decrypt` after IPFS success | Wrong `NBF_IPFS_MODE` | Keep `auto` (or `base64text` for the NBFLite sample gateway) |
| Slow first invoke | Fabric 2.2 chaincode container cold start | Wait a few seconds then retry |
| VM free but shows "free tier exceeded" | Over the 4 OCPU/24 GB cap | Reduce OCPUs/RAM to 2 OCPU/12 GB |

## Zero-cost checklist

- Free-tier ARM VM (Always Free), no billing.
- Docker via `apt` on the VM — free, no license.
- Our self-hosted NBF-compatible stack — free; official NBFLite (if used) is
  also free from MeitY/C-DAC.
- No paid domains, load balancers or API keys.
- Stop/terminate the VM when not in use to keep the anchor honest: with the VM
  off in the default mandatory posture, anchoring fails hard (503) rather than
  silently passing; with the mandatory flags off for dev/demo, anchors are
  `pending` (retryable), not lost.