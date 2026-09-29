/**
 * Fabric network access for the KryxAI NBF gateway.
 * Pattern lifted from NBF-Lite `nbf-samplerest` (fabric-network / evaluate /
 * submit). Uses the same `cfgpath`, `user`, `channel`, `ccname`, `mspId`,
 * `local` conventions so the backend's request shape stays NBF-compatible.
 */
const { Wallets, Gateway } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const CCP = process.env.CCP_FILE || './connection-org1.json';
const WALLET_DIR =
  process.env.WALLET_DIR || path.join(__dirname, 'wallet');

async function buildCore({ user, channel, ccname, cfgpath, local, mspId, fcn, args, evaluate }) {
  const identityLabel = user || 'User1';
  const ccp = JSON.parse(fs.readFileSync(CCP, 'utf8'));
  const wallet = await Wallets.newFileSystemWallet(WALLET_DIR);
  const identity = await wallet.get(identityLabel);
  if (!identity) throw new Error(`identity "${identityLabel}" missing in wallet (run enrollAdmin/registerUser)`);

  const gw = new Gateway();
  const asLocalhost = process.env.AS_LOCALHOST !== 'false';
  await gw.connect(ccp, { wallet, identity: identityLabel, discovery: { enabled: false, asLocalhost } });
  const network = await gw.getNetwork(channel || 'mychannel');
  const contract = network.getContract(ccname || 'fabcar');
  return { gw, contract };
}

/**
 * Submit a chaincode transaction. Returns the peer-acknowledged transaction id.
 */
async function invokeFunction({ fcn, args, user, ccname, channel, cfgpath, local, mspId, txId }) {
  const { gw, contract } = await buildCore({ user, channel, ccname, cfgpath, local, mspId, fcn, args, evaluate: false });
  try {
    const res = await contract.submitTransaction(fcn, ...(args || []));
    return res ? res.toString() || txId : txId;
  } finally {
    gw.disconnect();
  }
}

/**
 * Evaluate a chaincode query. Returns the result (usually JSON).
 */
async function queryFunction({ fcn, args, user, ccname, channel, cfgpath, local, mspId }) {
  const { gw, contract } = await buildCore({ user, channel, ccname, cfgpath, local, mspId, fcn, args, evaluate: true });
  try {
    const res = await contract.evaluateTransaction(fcn, ...(args || []));
    return res.toString('utf8');
  } finally {
    gw.disconnect();
  }
}

module.exports = { invokeFunction, queryFunction, buildCore };