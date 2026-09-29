/**
 * KryxAI — NBF-Lite-compatible REST gateway for the reports anchor.
 *
 * Trimmed clone of the nbf-samplerest pattern so the KryxAI backend can
 * push report anchors onto a Hyperledger Fabric ledger and pin ciphertext to
 * IPFS without bundling Fabric SDKs into the app itself.
 *
 * Endpoints (mirror NBF samples):
 *   GET  /health
 *   POST /store           {fileName, fileContents(base64)}  -> {hash(CID)}
 *   GET  /retrieve/:cid   -> {data(base64)}
 *   POST /fabric/v1/invokecc  {fcn, args, user, ccname, channel, cfgpath, local, mspId, txId}
 *   GET  /fabric/v1/querycc   {fcn, args, ...}  (querystring or POST body)
 */

const express = require('express');
const cors = require('cors');

// IPFS client (Kubo) — reuse minimal client from nbf-samplerest.
const { uploadToIPFS, fetchFromIPFS } = require('./ipfs_client');

// Fabric gateway helpers — reuse single connection per request (sample pattern).
const {
  invokeFunction,
  queryFunction,
} = require('./fabric_client');

const app = express();
app.use(cors());
app.use(express.json({ limit: '100mb' }));

app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'kryxai-nbf-gateway' }));

// ---- IPFS ----
app.post('/store', async (req, res) => {
  try {
    const { fileName, fileContents } = req.body;
    if (!fileContents) return res.status(400).json({ error: 'fileContents required (base64)' });
    const hash = await uploadToIPFS(fileName, fileContents);
    res.json({ hash });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/retrieve/:cid', async (req, res) => {
  try {
    const data = await fetchFromIPFS(req.params.cid);
    res.json({ data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---- Fabric ----
app.post('/fabric/v1/invokecc', async (req, res) => {
  try {
    const { fcn, args, user, ccname, channel, cfgpath, local, mspId, txId } = req.body;
    const txid = await invokeFunction({ fcn, args, user, ccname, channel, cfgpath, local, mspId, txId });
    res.json({ tx_id: txid, status: 'SUCCESS' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/fabric/v1/querycc', async (req, res) => {
  try {
    const { fcn, user, ccname, channel, cfgpath, local, mspId } = req.query;
    const args = req.query.args ? req.query.args.split(',') : [];
    const result = await queryFunction({ fcn, args, user, ccname, channel, cfgpath, local, mspId });
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST body form (args is an array): mirrors the NBF samplerest contract.
app.post('/fabric/v1/querycc', async (req, res) => {
  try {
    const { fcn, user, ccname, channel, cfgpath, local, mspId, args } = req.body;
    const argList = Array.isArray(args) ? args : (args ? String(args).split(',') : []);
    const result = await queryFunction({ fcn, args: argList, user, ccname, channel, cfgpath, local, mspId });
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Bind to the platform-injected $PORT (Render / Cloud Run) when present.
const PORT = process.env.PORT || process.env.GATEWAY_PORT || 4000;
app.listen(PORT, () => console.log(`KryxAI NBF gateway on :${PORT}`));