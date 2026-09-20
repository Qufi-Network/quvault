/*
 * The one property this product exists for: the transaction a person approved with their palm
 * is the transaction that gets signed and broadcast, or nothing happens at all.
 *
 * Every test here is an attack. Each one substitutes something after the approval — the
 * destination, the amount, the fee, the coins, the whole transaction, the authorisation
 * record — and each one must end with no broadcast.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { canonicalTransaction, canonicalJson } from '../src/canonical.js';
import { transactionDigest } from '../src/veyns.js';
import { attestationKeys, signAuthorization, verifyAuthorization } from '../src/authorization.js';
import { planDigest, signPlan as signInBrowser } from '../client/wallet.js';
import { makeMnemonic, jitterFrom, accountFrom } from '../client/wallet.js';
import { planSpend } from '../src/bitcoin.js';
import { DEST, SEED, start, ok, signedIn, palmApprove, walletFor, signAndSend } from './harness.js';
import crypto from 'node:crypto';

const coins = [{ txid: 'a'.repeat(64), vout: 0, value: 500_000 }];
const phrase = () => makeMnemonic({ serverRandom: new Uint8Array(crypto.randomBytes(32)), jitter: jitterFrom(['x']) });

/* ------------------------------------------------- the digest itself */

test('the digest covers every part of the transaction that can be substituted', () => {
  const plan = { inputs: [{ txid: 'b'.repeat(64), index: 0, value: 300_000 }], outputs: [{ address: DEST, sats: 100_000 }], feeSats: 300 };
  const base = { chain: 'bitcoin', network: 'testnet4', from: 'tb1qowner', plan };
  const digest = transactionDigest(canonicalTransaction(base));

  const moves = {
    'another destination': { ...plan, outputs: [{ address: 'tb1qsomeoneelse', sats: 100_000 }] },
    'another amount': { ...plan, outputs: [{ address: DEST, sats: 1_000_000 }] },
    'another fee': { ...plan, feeSats: 5_000 },
    'another coin': { ...plan, inputs: [{ txid: 'c'.repeat(64), index: 0, value: 300_000 }] },
    'an extra output': { ...plan, outputs: [...plan.outputs, { address: 'tb1qextra', sats: 1 }] },
  };
  for (const [what, altered] of Object.entries(moves)) {
    assert.notEqual(transactionDigest(canonicalTransaction({ ...base, plan: altered })), digest, what);
  }
  // And things that are not the transaction do move it too, because they bind it to one vault.
  assert.notEqual(transactionDigest(canonicalTransaction({ ...base, from: 'tb1qanother' })), digest);
  assert.notEqual(transactionDigest(canonicalTransaction({ ...base, network: 'mainnet' })), digest);

  // The same transaction, however the inputs are ordered, is the same transaction.
  const two = { inputs: [plan.inputs[0], { txid: 'd'.repeat(64), index: 1, value: 10 }], outputs: plan.outputs, feeSats: 300 };
  const swapped = { ...two, inputs: [...two.inputs].reverse() };
  assert.equal(
    transactionDigest(canonicalTransaction({ ...base, plan: two })),
    transactionDigest(canonicalTransaction({ ...base, plan: swapped })),
  );
});

test('the browser computes the same digest as the server', () => {
  const plan = { inputs: [{ txid: 'e'.repeat(64), index: 3, value: 250_000 }], outputs: [{ address: DEST, sats: 90_000 }], feeSats: 400 };
  const parts = { chain: 'bitcoin', network: 'testnet4', from: 'tb1qowner', plan };
  assert.equal(planDigest({ network: 'testnet4', from: 'tb1qowner', plan }), transactionDigest(canonicalTransaction(parts)));
});

/* ------------------------------------------- the device refuses to sign */

test('the device will not sign a plan that is not the one approved', () => {
  const mnemonic = phrase();
  const account = accountFrom(mnemonic);
  const plan = planSpend({ publicKey: Buffer.from(account.publicKey), utxos: coins, toAddress: DEST, amountSats: 120_000, feeRate: 2 });
  const approved = planDigest({ network: 'testnet4', from: account.address, plan });

  // The approved plan signs.
  assert.ok(signInBrowser(mnemonic, plan, account.address, { transactionHash: approved, network: 'testnet4' }).hex);

  const attacks = {
    'destination moved': { ...plan, outputs: plan.outputs.map(o => (o.address === DEST ? { ...o, address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'.replace('kxpjzsx', 'kxpjzsy') } : o)) },
    'amount raised': { ...plan, outputs: plan.outputs.map(o => (o.address === DEST ? { ...o, sats: o.sats * 10 } : o)) },
    'fee raised': { ...plan, feeSats: plan.feeSats + 10_000 },
  };
  for (const [what, altered] of Object.entries(attacks)) {
    assert.throws(
      () => signInBrowser(mnemonic, altered, account.address, { transactionHash: approved, network: 'testnet4' }),
      /not the transaction that was approved/,
      what,
    );
  }
  // A digest from another network does not authorise this one.
  assert.throws(
    () => signInBrowser(mnemonic, plan, account.address, { transactionHash: approved, network: 'mainnet' }),
    /not the transaction that was approved/,
  );
});

/* ------------------------------------------- the authorisation record */

test('an authorisation cannot be moved to another transaction or another vault', () => {
  const keys = attestationKeys(SEED);
  const publicKey = Buffer.from(keys.publicKey).toString('base64');
  const parts = {
    vaultId: 'tb1qvault', accountId: 'bitcoin', transactionHash: 'DIGEST-ONE', statementDigest: 'STATEMENT',
    approvalMethod: 'veyns:palm', approvals: '1 of 1', approvedBy: ['alex'], decisionIds: ['decision-1'], approvedAt: 1_800_000_000,
  };
  const authorization = signAuthorization(parts, keys);

  assert.ok(verifyAuthorization(authorization, publicKey, { transactionHash: 'DIGEST-ONE', vaultId: 'tb1qvault' }).ok);
  assert.match(verifyAuthorization(authorization, publicKey, { transactionHash: 'DIGEST-TWO' }).reason, /different transaction/);
  assert.match(verifyAuthorization(authorization, publicKey, { vaultId: 'tb1qother' }).reason, /different vault/);

  // Editing the record and keeping the signature fails, field by field.
  for (const field of ['transactionHash', 'vaultId', 'statementDigest', 'approvedAt', 'biometricVerified']) {
    const edited = { ...authorization, record: { ...authorization.record, [field]: 'CHANGED' } };
    assert.equal(verifyAuthorization(edited, publicKey).ok, false, field);
  }
  // Another vault's key does not vouch for this record.
  const other = attestationKeys(crypto.randomBytes(64).toString('base64'));
  assert.equal(verifyAuthorization(authorization, Buffer.from(other.publicKey).toString('base64')).ok, false);
  // And the record carries nothing about the biometric beyond that it happened.
  const text = canonicalJson(authorization.record);
  for (const word of ['template', 'image', 'palmData', 'score']) {
    assert.ok(!text.includes(word), `the record must not carry ${word}`);
  }
});

/* --------------------------------------------- end to end, through the API */

test('a withdrawal carries its digest from the sentence to the signature', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const wallet = await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation, transactionHash } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  // The person reads the digest as part of the sentence they approve.
  assert.equal(operation.details.transaction_hash, transactionHash);
  assert.match(transactionHash, /^[A-Za-z0-9_-]{43}$/);

  // Veyns digests the whole statement, so the transaction hash is inside what the palm signs.
  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.equal(unlocked.transactionHash, transactionHash);
  assert.equal(planDigest({ network: 'testnet4', from: wallet.address, plan: unlocked.plan }), transactionHash);

  // The authorisation record was signed before anything could be broadcast.
  const receipt = ok(await alex.get(`/api/operations/${operation.id}/receipt`));
  assert.equal(receipt.algorithm, 'ML-DSA-65');
  assert.equal(receipt.authorization.record.transactionHash, transactionHash);
  assert.equal(receipt.authorization.record.vaultId, wallet.address);
  assert.equal(receipt.authorization.record.biometricVerified, true);
  assert.ok(receipt.verified.ok);
  assert.ok(verifyAuthorization(receipt.authorization, receipt.publicKey, { transactionHash }).ok);

  const { txid } = await signAndSend(env, alex, operation.id);
  assert.ok(txid);
  assert.equal(env.world.log.broadcast.length, 1);
});

test('a plan swapped after the approval is never broadcast', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  await palmApprove(env, alex, operation.id);

  // Someone with the database changes where the money goes, after the palm.
  const db = await env.app.db();
  const before = JSON.parse((await db.query('SELECT payload FROM operations WHERE id = $1', [operation.id])).rows[0].payload);
  const attacker = accountFrom(phrase()).address;
  const moved = { ...before, outputs: before.outputs.map(o => (o.address === DEST ? { ...o, address: attacker } : o)) };
  await db.query('UPDATE operations SET payload = $1 WHERE id = $2', [JSON.stringify(moved), operation.id]);

  // The browser refuses first: the plan it is handed does not hash to what was approved.
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.notEqual(planDigest({ network: 'testnet4', from: unlocked.address, plan: unlocked.plan }), unlocked.transactionHash);

  // And if a compromised page signed it anyway, the server refuses to broadcast it.
  const signed = signAndSendRaw(unlocked, moved);
  const refused = await alex.post(`/api/operations/${operation.id}/broadcast`, { hex: signed });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /no longer matches the one that was approved/);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing was sent');
});

test('an authorisation for one transaction cannot release another', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  // One approved withdrawal.
  const first = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, first.operation.id);
  const db = await env.app.db();
  const stolen = (await db.query('SELECT human_authorization FROM operations WHERE id = $1', [first.operation.id])).rows[0].human_authorization;
  assert.ok(stolen, 'the first withdrawal has a record');

  // A second withdrawal, to somewhere else, with the first one's record pasted onto it.
  env.world.chain.utxos = [{ txid: 'f'.repeat(64), vout: 0, value: 400_000 }];
  const second = ok(await alex.post('/api/withdrawals', { to: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', amount: 200_000 }));
  await db.query(`UPDATE operations SET human_authorization = $1, status = 'running' WHERE id = $2`, [stolen, second.operation.id]);

  const unlocked = { plan: second.plan, address: (await db.query('SELECT address FROM wallets WHERE user_id = $1', [alex.id])).rows[0].address };
  const refused = await alex.post(`/api/operations/${second.operation.id}/broadcast`, { hex: signAndSendRaw(unlocked, second.plan) });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /different transaction/);
  assert.equal(env.world.log.broadcast.length, 0);
});

test('without a palm there is no authorisation and nothing to broadcast', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  assert.equal((await alex.get(`/api/operations/${operation.id}/receipt`)).status, 404, 'no record before the palm');
  assert.equal((await alex.post(`/api/operations/${operation.id}/unlock`, {})).status, 409, 'nothing to sign yet');
  assert.equal((await alex.post(`/api/operations/${operation.id}/broadcast`, { hex: '00' })).status, 409);
  assert.equal(env.world.log.broadcast.length, 0);
});

/** Signs a plan with a throwaway key: stands in for a page that has been taken over. */
function signAndSendRaw(unlocked, plan) {
  const mnemonic = phrase();
  const account = accountFrom(mnemonic);
  const script = btc.p2wpkh(account.publicKey, btc.TEST_NETWORK).script;
  const tx = new btc.Transaction({ allowUnknownOutputs: true });
  for (const input of plan.inputs) {
    tx.addInput({ txid: hex.decode(input.txid), index: input.index, witnessUtxo: { script, amount: BigInt(input.value) } });
  }
  for (const output of plan.outputs) tx.addOutputAddress(output.address, BigInt(output.sats), btc.TEST_NETWORK);
  tx.sign(account.privateKey);
  tx.finalize();
  return tx.hex;
}
