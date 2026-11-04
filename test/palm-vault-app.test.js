/*
 * The palm vault inside the app: locking an account so Bitcoin itself needs the palm key, and
 * spending from it. Each test checks the palm key's signature on what went out, cryptographically
 * and against the vault's own script, because "the palm signer said yes" is not the claim. The
 * claim is that the transaction carries a palm signature Bitcoin will check.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import * as btc from '@scure/btc-signer';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend } from './harness.js';
import { cosignerFrom, signQuorum } from '../client/wallet.js';
import { signKeyProof } from '../src/key-proof.js';
import { palmVaultOf, LEAF_VERSION } from '../src/palm-vault.js';
import { NETWORK } from '../src/bitcoin.js';

const PHRASES = {
  alex: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  bea: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  cara: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
};

async function signingKey(env, client, vaultOwnerId, phrase) {
  const started = ok(await client.post('/api/signing-key/approval', { vaultOwnerId }));
  await palmApprove(env, client, started.operation.id);
  ok(await client.post(`/api/operations/${started.operation.id}/unlock`, {}));
  const key = cosignerFrom(phrase, started.index);
  ok(await client.post('/api/signing-key/register', {
    operationId: started.operation.id,
    publicKey: Buffer.from(key.publicKey).toString('hex'),
    proof: signKeyProof(key.privateKey, { vaultOwnerId, memberId: client.id, publicKey: Buffer.from(key.publicKey).toString('hex') }),
  }));
  return key;
}

async function joins(env, owner, guest, label, approvers = [owner]) {
  const { operation } = ok(await owner.post('/api/invites/approval', { network: 'bitcoin', label }));
  for (let i = 0; i < operation.required; i++) await palmApprove(env, approvers[i], operation.id);
  const { invites } = ok(await owner.get('/api/invites'));
  const join = ok(await guest.post('/api/invites/join', { code: invites[0].code }));
  await palmApprove(env, guest, join.operation.id);
}

const bitcoinAccount = async client => ok(await client.get('/api/wallet')).accounts.find(a => a.network === 'bitcoin');

/** Rebuilds the vault from what the account reports, the way any outside wallet would. */
function vaultOf(account) {
  const palmKey = account.quorum.palm.descriptor.match(/v:pk\(([0-9a-f]{64})\)/)[1];
  return palmVaultOf({
    palmKey, signerKeys: account.quorum.keys, required: account.quorum.required,
    delay: account.quorum.palm.recoveryDelayBlocks, network: NETWORK,
  });
}

/** One person's vault, locked to their palm, with coins in it. */
async function palmVaultOfOne(env) {
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await signingKey(env, alex, alex.id, PHRASES.alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 1, palm: true }));
  await palmApprove(env, alex, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 700_000 }];
  return { alex, asked, account: await bitcoinAccount(alex) };
}

/** Three people, locked to 2 of 3 and the palm. */
async function palmVaultOfThree(env) {
  const alex = await signedIn(env, 'sub-alex');
  const bea = await signedIn(env, 'sub-bea');
  const cara = await signedIn(env, 'sub-cara');
  for (const who of [alex, bea, cara]) await walletFor(env, who);
  await joins(env, alex, bea, 'Bea');
  await joins(env, alex, cara, 'Cara', [alex, bea]);
  await signingKey(env, alex, alex.id, PHRASES.alex);
  await signingKey(env, bea, alex.id, PHRASES.bea);
  await signingKey(env, cara, alex.id, PHRASES.cara);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 2, palm: true }));
  for (let i = 0; i < asked.operation.required; i++) await palmApprove(env, [alex, bea, cara][i], asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 700_000 }];
  return { alex, bea, cara, account: await bitcoinAccount(alex) };
}

/** What a signer's browser does once the palms are in: open its own key, add one signature. */
async function addSignature(client, operationId, phrase) {
  const unlocked = ok(await client.post(`/api/operations/${operationId}/unlock`, {}));
  const { psbt } = signQuorum(phrase, {
    psbt: unlocked.psbt, plan: unlocked.plan, index: unlocked.keyIndex, address: unlocked.address,
    transactionHash: unlocked.transactionHash, network: 'testnet4', lockKind: unlocked.lockKind,
  });
  return { unlocked, result: await client.post(`/api/operations/${operationId}/signature`, { psbt }) };
}

/** Checks every signature in a broadcast palm vault spend the way Bitcoin would. */
function checkPalmSpend(sent, vault, amount) {
  const leaf = vault.leaves.normal.script;
  for (let i = 0; i < sent.tx.inputsLength; i++) {
    const witness = sent.tx.getInput(i).finalScriptWitness;
    assert.equal(hex.encode(witness.at(-2)), hex.encode(leaf), 'it spends through the normal leaf');
    const message = sent.tx.preimageWitnessV1(i, [vault.script], btc.SigHash.DEFAULT, [BigInt(amount)], undefined, leaf, LEAF_VERSION);
    const palmSig = witness.at(-3);
    assert.ok(schnorr.verify(palmSig, message, vault.palmKey), 'the palm key signed this exact transaction');
    // Signer slots sit below the palm signature, in reverse key order; empty slots are allowed.
    const slots = witness.slice(0, vault.keys.length).reverse();
    const valid = slots.filter((sig, k) => sig.length && schnorr.verify(sig, message, vault.keys[k])).length;
    assert.equal(valid, vault.required, `exactly ${vault.required} signer signature(s), each valid`);
  }
}

test('a vault of one locks to the palm: the address is the palm vault, and Bitcoin will need the palm key', async t => {
  const env = await start(t);
  const { asked, account } = await palmVaultOfOne(env);
  assert.equal(asked.quorum.palm, true);
  assert.match(asked.operation.statement, /Lock my Bitcoin to my palm on the chain and move/);
  assert.match(account.address, /^tb1p/, 'a Taproot address');
  assert.equal(account.quorum.required, 1);
  assert.equal(account.quorum.palm.recoveryDelayBlocks, 52560, 'the signers alone only after about a year');
  assert.match(account.quorum.palm.descriptor, /^tr\(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,\{and_v\(v:pk\(/,
    'the key path is closed and the palm key leads the normal path');
  assert.equal(vaultOf(account).address, account.address, 'the descriptor rebuilds exactly this address');
  const sweep = env.world.log.broadcast.at(-1);
  assert.equal(btc.Address(NETWORK).encode(btc.OutScript.decode(sweep.tx.getOutput(0).script)), account.address,
    'the coins moved into the palm vault');
});

test('spending from a palm vault of one: the palm approves, the browser signs, the palm key signs, Bitcoin gets both', async t => {
  const env = await start(t);
  const { alex, account } = await palmVaultOfOne(env);
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 250_000 }));
  await palmApprove(env, alex, operation.id);
  const { unlocked, result } = await addSignature(alex, operation.id, PHRASES.alex);
  assert.equal(unlocked.lockKind, 'palm');
  const { txid } = ok(result);
  assert.ok(txid, 'it went out');
  const sent = env.world.log.broadcast.at(-1);
  assert.equal(sent.txid, txid);
  checkPalmSpend(sent, vaultOf(account), 700_000);
});

test('a shared palm vault: two of three sign, then the palm key, and every signature checks out', async t => {
  const env = await start(t);
  const { alex, bea, account } = await palmVaultOfThree(env);
  assert.equal(account.quorum.required, 2);
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 250_000 }));
  await palmApprove(env, alex, operation.id);
  await palmApprove(env, bea, operation.id);

  const first = await addSignature(alex, operation.id, PHRASES.alex);
  assert.equal(ok(first.result).txid, null, 'one signer is not enough');
  const second = await addSignature(bea, operation.id, PHRASES.bea);
  const { txid } = ok(second.result);
  assert.ok(txid);
  checkPalmSpend(env.world.log.broadcast.at(-1), vaultOf(account), 700_000);
});

test('without Veyns\' own signed decisions the palm key does not sign, and nothing is sent; with them, a retry does', async t => {
  const env = await start(t);
  const { alex } = await palmVaultOfOne(env);
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 250_000 }));
  await palmApprove(env, alex, operation.id);

  const db = await env.app.db();
  const kept = (await db.query('SELECT id, decision_token FROM approvals WHERE operation_id = $1', [operation.id])).rows;
  assert.ok(kept.every(row => row.decision_token?.split('.').length === 3), 'the signed decision was kept with each approval');
  await db.query('UPDATE approvals SET decision_token = NULL WHERE operation_id = $1', [operation.id]);

  const before = env.world.log.broadcast.length;
  const { result } = await addSignature(alex, operation.id, PHRASES.alex);
  assert.equal(result.status, 409);
  assert.match(result.body.error, /palm key refused to sign: needs 1 palm approval/);
  assert.equal(env.world.log.broadcast.length, before, 'nothing went out');

  for (const row of kept) await db.query('UPDATE approvals SET decision_token = $1 WHERE id = $2', [row.decision_token, row.id]);
  const retried = ok(await alex.post(`/api/operations/${operation.id}/signature`, {}));
  assert.ok(retried.txid, 'the signer does not sign twice; the palm signer is simply asked again');
});

test('a decision that was tampered with does not count, so the palm key does not sign', async t => {
  const env = await start(t);
  const { alex } = await palmVaultOfOne(env);
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 250_000 }));
  await palmApprove(env, alex, operation.id);
  const db = await env.app.db();
  const [row] = (await db.query('SELECT id, decision_token FROM approvals WHERE operation_id = $1', [operation.id])).rows;
  const [h, p] = row.decision_token.split('.');
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  // The server claiming a palm approved a different payment: the signature no longer verifies.
  claims.veyns_action.digest = 'x'.repeat(43);
  const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${row.decision_token.split('.')[2]}`;
  await db.query('UPDATE approvals SET decision_token = $1 WHERE id = $2', [forged, row.id]);

  const { result } = await addSignature(alex, operation.id, PHRASES.alex);
  assert.equal(result.status, 409);
  assert.match(result.body.error, /signature does not verify/);
});

test('a palm vault needs every signer to have made a signing key first', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const refused = await alex.post('/api/accounts/lock', { required: 1, palm: true });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /signing key first/);
});

test('a vault of one still cannot lock to a plain quorum: that needs two signers', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await signingKey(env, alex, alex.id, PHRASES.alex);
  const refused = await alex.post('/api/accounts/lock', { required: 1 });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /at least two signers/);
});
