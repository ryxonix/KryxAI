/**
 * Kubo (IPFS) client for the KryxAI NBF gateway.
 *
 * Talks to Kubo's own HTTP RPC API (POST /api/v0/add, POST /api/v0/cat) using
 * Node 18's built-in fetch + FormData — no `ipfs-http-client` npm dependency.
 * The npm package v60+ is ESM-only and cannot be `require()`d from a CommonJS
 * module (ERR_PACKAGE_PATH_NOT_EXPORTED), so we avoid it entirely.
 */

const IPFS_API_HOST = process.env.IPFS_API_HOST || '127.0.0.1';
const IPFS_API_PORT = process.env.IPFS_API_PORT || '5001';
const IPFS_GATEWAY = process.env.IPFS_GATEWAY || 'http://127.0.0.1:8080';

const API_BASE = `http://${IPFS_API_HOST}:${IPFS_API_PORT}`;

/**
 * Upload base64 file contents to IPFS, return the CID (hash).
 * The bytes are stored raw (the backend already base64-encodes the
 * ciphertext); storing the decoded buffer keeps the equality check exact.
 */
async function uploadToIPFS(name, base64Contents) {
  const bytes = Buffer.from(base64Contents, 'base64');
  const form = new FormData();
  form.append('file', new Blob([bytes]), name);

  const res = await fetch(`${API_BASE}/api/v0/add?stream-channels=true`, {
    method: 'POST',
    body: form,
  });
  if (!res.ok) {
    throw new Error(`IPFS add failed (${res.status}): ${await res.text()}`);
  }

  const result = await res.json();
  let cid;
  if (Array.isArray(result)) {
    cid = result.length && (result[0].Hash || (result[0].Cid && result[0].Cid['/']));
  } else {
    cid = result.Hash || (result.Cid && result.Cid['/']) || result.cid;
  }
  if (!cid) {
    throw new Error('IPFS add returned no CID');
  }
  return cid;
}

/** Fetch content for a CID from the configured HTTP gateway, base64 of the
 * RAW bytes (never decode to UTF-8 — the stored payload is opaque ciphertext). */
async function fetchFromIPFS(cid) {
  const url = `${IPFS_GATEWAY}/ipfs/${cid}`;
  const res = await fetch(url);
  if (res.status === 404) {
    throw new Error(`IPFS content not found: ${cid}`);
  }
  if (!res.ok) {
    throw new Error(`IPFS fetch failed (${res.status}): ${await res.text()}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  return buf.toString('base64');
}

module.exports = { uploadToIPFS, fetchFromIPFS, IPFS_API_HOST, IPFS_API_PORT, IPFS_GATEWAY };