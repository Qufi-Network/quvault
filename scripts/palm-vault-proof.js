/*
 * Puts palm-vault transactions in front of Bitcoin Core's own consensus checks, on a private
 * regtest chain this script starts and throws away. Nothing here is our word for it: every
 * verdict below is the node's.
 *
 *   1. Bitcoin Core derives the same address from the vault's descriptor as QuVault does.
 *   2. A spend signed by enough signers, but not by the palm key, is refused.
 *   3. A spend where an attacker signs the exact transaction with their own key, in the palm
 *      key's place, is refused.
 *   4. The palm signer refuses to sign when it is given no palm approvals.
 *   5. The same spend as (2), once the palm signer has checked two palms and signed, is
 *      accepted and mined.
 *   6. The recovery path, which needs no palm, is refused before the delay and accepted after.
 *
 * "Refused" means twice over: the mempool turns it away, and the node will not mine it into a
 * block either. The second is consensus, which no miner can opt out of; the first alone could
 * be only relay policy.
 *
 * Run: npm run proof:palm-vault        (needs `bitcoind` on the PATH)
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as btc from '@scure/btc-signer';
import { hex, base64 } from '@scure/base';
import { createKey, publicKeyOf } from '../src/bitcoin.js';
import { canonicalTransaction } from '../src/canonical.js';
import { transactionDigest, actionDigest } from '../src/veyns.js';
import {
  palmVaultOf, planPalmSpend, palmVaultPsbt, signPalmPsbt, finalizePalmPsbt, LEAF_VERSION,
} from '../src/palm-vault.js';
import { createPalmSigner, PalmRefused } from '../src/palm-signer.js';

const REGTEST = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4, wif: 0xef };
const DELAY = 10; // blocks: short, so this proof can mine past it. A real vault uses about a year.
const ISSUER = 'https://veyns.regtest';
const AUDIENCE = 'quvault-proof';
const FEE_RATE = 2;

const results = [];
const record = (name, pass, detail) => {
  results.push({ name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}\n      ${detail}`);
};

const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    server.close(() => resolve(port));
  });
});

/* ------------------------------------------------------------- a throwaway node */

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'palm-vault-regtest-'));
const password = crypto.randomBytes(16).toString('hex');
const rpcPort = await freePort();
const node = spawn('bitcoind', [
  '-regtest', `-datadir=${dir}`, `-rpcport=${rpcPort}`, '-rpcuser=proof', `-rpcpassword=${password}`,
  '-server=1', '-listen=0', '-fallbackfee=0.0002', '-printtoconsole=0',
], { stdio: 'ignore' });
let exited = false;
node.on('exit', () => { exited = true; });

async function rpc(method, params = [], wallet = null) {
  const response = await fetch(`http://127.0.0.1:${rpcPort}/${wallet ? `wallet/${wallet}` : ''}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Basic ${Buffer.from(`proof:${password}`).toString('base64')}` },
    body: JSON.stringify({ jsonrpc: '1.0', id: method, method, params }),
  });
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}
const wallet = (method, params = []) => rpc(method, params, 'proof');

async function ready() {
  for (let i = 0; i < 120; i++) {
    if (exited) throw new Error('bitcoind exited before it was ready');
    try {
      return await rpc('getblockchaininfo');
    } catch {
      await new Promise(resolve => setTimeout(resolve, 250));
    }
  }
  throw new Error('bitcoind did not become ready');
}

async function stop() {
  try {
    await rpc('stop');
  } catch {
    node.kill();
  }
  for (let i = 0; i < 80 && !exited; i++) await new Promise(resolve => setTimeout(resolve, 250));
  fs.rmSync(dir, { recursive: true, force: true });
}

/* ------------------------------------------------------------- the proof */

const accept = async raw => (await rpc('testmempoolaccept', [[raw]]))[0];

/**
 * The mempool also applies relay policy, so a mempool refusal alone does not show a miner could
 * not include the transaction anyway. This asks the node to mine it straight into a block, which
 * only consensus rules decide. Returns null if it was mined, or the node's reason if not.
 */
async function blockRefusal(raw, miner) {
  try {
    await rpc('generateblock', [miner, [raw]]);
    return null;
  } catch (error) {
    return error.message.replace(/^generateblock: /, '');
  }
}

/** Where coins sent to `address` landed in a funding transaction. */
async function utxoOf(txid, address) {
  const tx = await wallet('gettransaction', [txid, true, true]);
  const out = tx.decoded.vout.find(o => o.scriptPubKey.address === address);
  return { txid, vout: out.n, value: Math.round(out.value * 1e8), height: tx.blockheight };
}

try {
  const chain = await ready();
  console.log(`Bitcoin Core ${(await rpc('getnetworkinfo')).subversion} on ${chain.chain}, throwaway data dir\n`);
  await rpc('createwallet', ['proof']);
  const miner = await wallet('getnewaddress');
  await rpc('generatetoaddress', [101, miner]);

  // Veyns, as far as the palm signer can tell: an ES256 key it pins, signing decision tokens.
  const veynsKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...veynsKey.publicKey.export({ format: 'jwk' }), kid: 'proof-1' };
  let serial = 0;
  const decision = (sub, action) => {
    const at = Math.floor(Date.now() / 1000);
    const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const input = `${b64({ alg: 'ES256', kid: 'proof-1', typ: 'JWT' })}.${b64({
      iss: ISSUER, aud: AUDIENCE, sub, iat: at, exp: at + 300, auth_time: at,
      veyns_intent: 'action', veyns_presence: true, amr: ['veyns:palm'],
      request_id: `req-${++serial}`, request_nonce: crypto.randomBytes(12).toString('base64url'),
      veyns_action: { statement: action.statement, digest: actionDigest(action.statement, action.details) },
    })}`;
    return `${input}.${crypto.sign('sha256', Buffer.from(input), { key: veynsKey.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  };

  const signer = createPalmSigner({
    seed: crypto.randomBytes(32), issuer: ISSUER, audience: AUDIENCE, pinnedKeys: [jwk],
    networkName: 'regtest', network: REGTEST,
  });
  const people = { alex: createKey(), bea: createKey(), cara: createKey() };
  const policy = {
    signerKeys: Object.values(people).map(publicKeyOf), required: 2, delay: DELAY,
    signerSubs: ['sub-alex', 'sub-bea', 'sub-cara'],
  };
  const vaultId = 'proof-vault';
  const vault = palmVaultOf({ palmKey: signer.publicKeyFor(vaultId), ...policy, network: REGTEST });
  console.log(`Vault ${vault.address}\n      2 of 3 signers + the palm key; recovery: 2 of 3 after ${DELAY} blocks\n`);

  // 1. Bitcoin Core reads the descriptor and derives the same address.
  const [body, ours] = vault.descriptor.split('#');
  const info = await rpc('getdescriptorinfo', [body]);
  const [derived] = await rpc('deriveaddresses', [vault.descriptor]);
  record('Bitcoin Core derives the same vault from its descriptor',
    info.checksum === ours && derived === vault.address,
    `checksum ${info.checksum} (ours ${ours}); address ${derived === vault.address ? 'matches' : `differs: ${derived}`}`);

  // Fund three separate coins: one per spend below.
  const funding = [];
  for (let i = 0; i < 3; i++) funding.push(await wallet('sendtoaddress', [vault.address, 0.01]));
  await rpc('generatetoaddress', [1, miner]);
  const [coinA, coinB, coinC] = await Promise.all(funding.map(txid => utxoOf(txid, vault.address)));
  const dest = await wallet('getnewaddress');

  const approve = coin => {
    const plan = planPalmSpend({ vault, utxos: [coin], toAddress: dest, amountSats: 500_000, feeRate: FEE_RATE });
    const digest = transactionDigest(canonicalTransaction({ chain: 'bitcoin', network: 'regtest', from: vault.address, plan }));
    const action = { statement: `Send 500000 sats to ${dest}`, details: { action: 'withdraw', to: dest, amount_sats: 500_000, transaction_hash: digest } };
    let psbt = palmVaultPsbt(vault, plan);
    psbt = signPalmPsbt(psbt, people.alex);
    psbt = signPalmPsbt(psbt, people.bea);
    return { plan, action, psbt };
  };

  /** The signers' witness as a finished transaction, with `palm` (bytes) in the palm key's slot. */
  const withPalmSlot = (psbt, palm) => {
    const tx = btc.Transaction.fromPSBT(base64.decode(psbt), { allowUnknownInputs: true });
    const input = tx.getInput(0);
    const leafHash = vault.leaves.normal.leafHash;
    const sigOf = key => input.tapScriptSig.find(([m]) => hex.encode(m.pubKey) === hex.encode(key) && hex.encode(m.leafHash) === hex.encode(leafHash))?.[1];
    let used = 0;
    const slots = vault.keys.map(key => {
      const sig = used < vault.required ? sigOf(key) : undefined;
      if (!sig) return new Uint8Array(0);
      used++;
      return sig;
    });
    tx.updateInput(0, {
      finalScriptWitness: [...slots.reverse(), palm, vault.leaves.normal.script, btc.TaprootControlBlock.encode(vault.leaves.normal.controlBlock)],
    }, true);
    return { raw: tx.hex, tx };
  };

  // 2. Enough signers, no palm signature: the network refuses it.
  const spendA = approve(coinA);
  const noPalm = withPalmSlot(spendA.psbt, new Uint8Array(0));
  const verdictNoPalm = await accept(noPalm.raw);
  const minedNoPalm = await blockRefusal(noPalm.raw, miner);
  record('Signers without the palm key: Bitcoin refuses the spend, in the mempool and in a block',
    verdictNoPalm.allowed === false && Boolean(minedNoPalm),
    `mempool: ${verdictNoPalm['reject-reason']}\n      block:   ${minedNoPalm}`);

  // 3. An attacker signs the exact transaction with their own key, in the palm key's place.
  const spendB = approve(coinB);
  const attacker = createKey();
  const draft = btc.Transaction.fromPSBT(base64.decode(spendB.psbt), { allowUnknownInputs: true });
  const sighash = draft.preimageWitnessV1(0, [vault.script], btc.SigHash.DEFAULT, [BigInt(coinB.value)], undefined, vault.leaves.normal.script, LEAF_VERSION);
  const forged = withPalmSlot(spendB.psbt, schnorr.sign(sighash, attacker));
  const verdictForged = await accept(forged.raw);
  const minedForged = await blockRefusal(forged.raw, miner);
  record('An attacker\'s own signature in the palm slot: Bitcoin refuses it, in the mempool and in a block',
    verdictForged.allowed === false && Boolean(minedForged),
    `mempool: ${verdictForged['reject-reason']}\n      block:   ${minedForged}`);

  // 4. The palm signer will not sign without palm approvals.
  let refusal = null;
  try {
    signer.sign({ vaultId, policy, psbt: spendA.psbt, action: spendA.action, decisions: [] });
  } catch (error) {
    if (error instanceof PalmRefused) refusal = error.message;
  }
  record('No palms: the palm signer refuses to sign', Boolean(refusal), `signer says: ${refusal}`);

  // 5. Two palms, checked by the signer; the same spend as (2) now goes through.
  const signed = signer.sign({
    vaultId, policy, psbt: spendA.psbt, action: spendA.action,
    decisions: [decision('sub-alex', spendA.action), decision('sub-bea', spendA.action)],
  });
  const finished = finalizePalmPsbt(vault, signed.psbt);
  const verdictPalm = await accept(finished.hex);
  let mined = false;
  if (verdictPalm.allowed) {
    await rpc('sendrawtransaction', [finished.hex]);
    await rpc('generatetoaddress', [1, miner]);
    mined = (await wallet('gettransaction', [finished.txid])).confirmations >= 1;
  }
  const paidRate = verdictPalm.allowed ? (verdictPalm.fees.base * 1e8) / verdictPalm.vsize : 0;
  record('Two palms checked, palm key signs: Bitcoin accepts and mines the same spend',
    verdictPalm.allowed && mined && paidRate >= FEE_RATE,
    `accepted ${verdictPalm.allowed}, mined ${mined}, ${verdictPalm.vsize} vB at ${paidRate.toFixed(2)} sat/vB (planned ${FEE_RATE}); palms from ${signed.approvedBy.join(', ')}`);

  // 6. Recovery: no palm, but only once the coin is DELAY blocks old.
  const recoveryPlan = planPalmSpend({ vault, utxos: [coinC], toAddress: dest, amountSats: 'max', feeRate: FEE_RATE, path: 'recovery' });
  let recovery = palmVaultPsbt(vault, recoveryPlan, { path: 'recovery' });
  recovery = signPalmPsbt(recovery, people.alex);
  recovery = signPalmPsbt(recovery, people.cara);
  const recoveryTx = finalizePalmPsbt(vault, recovery);
  const early = await accept(recoveryTx.hex);
  const age = (await rpc('getblockcount')) - coinC.height + 1;
  const minedEarly = await blockRefusal(recoveryTx.hex, miner);
  record(`Recovery before ${DELAY} blocks (coin is ${age} blocks old): Bitcoin refuses it, in the mempool and in a block`,
    early.allowed === false && Boolean(minedEarly),
    `mempool: ${early['reject-reason']}\n      block:   ${minedEarly}`);

  await rpc('generatetoaddress', [DELAY, miner]);
  const late = await accept(recoveryTx.hex);
  let recovered = false;
  if (late.allowed) {
    await rpc('sendrawtransaction', [recoveryTx.hex]);
    await rpc('generatetoaddress', [1, miner]);
    recovered = (await wallet('gettransaction', [recoveryTx.txid])).confirmations >= 1;
  }
  record(`Recovery after ${DELAY} blocks, no palm: Bitcoin accepts and mines it`,
    late.allowed && recovered, `accepted ${late.allowed}, mined ${recovered}`);
} catch (error) {
  record('the proof ran to the end', false, error.stack || String(error));
} finally {
  await stop();
}

const failed = results.filter(r => !r.pass).length;
console.log(`\n${results.length - failed} of ${results.length} checks passed.${failed ? '' : ' Bitcoin requires the palm key on the normal path.'}`);
process.exit(failed ? 1 : 0);
