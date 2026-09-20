/*
 * The two properties this product exists for:
 *
 *   1. The transaction a person approved with their palm is the transaction that gets signed
 *      and broadcast, or nothing happens at all.
 *   2. The record proving that approval is signed by a key the server does not have, so the
 *      operator of a deployment cannot manufacture one.
 *
 * Every test here is an attack on one of those. Each must end with nothing broadcast.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { canonicalTransaction, canonicalJson } from '../src/canonical.js';
import { transactionDigest } from '../src/veyns.js';
import { deriveAttestationKeys, signAuthorization, verifyAuthorization } from '../src/authorization.js';
import { planDigest, signPlan as signInBrowser, makeMnemonic, jitterFrom, accountFrom, attestationKeys } from '../client/wallet.js';
import { planSpend, signPlan } from '../src/bitcoin.js';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend, attestFor, registrationFor } from './harness.js';

const coins = [{ txid: 'a'.repeat(64), vout: 0, value: 500_000 }];
const phrase = () => makeMnemonic({ serverRandom: new Uint8Array(crypto.randomBytes(32)), jitter: jitterFrom(['x']) });

/* ------------------------------------------------------- the digest itself */

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
  assert.notEqual(transactionDigest(canonicalTransaction({ ...base, from: 'tb1qanother' })), digest);
  assert.notEqual(transactionDigest(canonicalTransaction({ ...base, network: 'mainnet' })), digest);

  // The same transaction, however the inputs are ordered, is the same transaction.
  const two = { inputs: [plan.inputs[0], { txid: 'd'.repeat(64), index: 1, value: 10 }], outputs: plan.outputs, feeSats: 300 };
  assert.equal(
    transactionDigest(canonicalTransaction({ ...base, plan: two })),
    transactionDigest(canonicalTransaction({ ...base, plan: { ...two, inputs: [...two.inputs].reverse() } })),
  );
});

test('the browser computes the same digest as the server', () => {
  const plan = { inputs: [{ txid: 'e'.repeat(64), index: 3, value: 250_000 }], outputs: [{ address: DEST, sats: 90_000 }], feeSats: 400 };
  assert.equal(
    planDigest({ network: 'testnet4', from: 'tb1qowner', plan }),
    transactionDigest(canonicalTransaction({ chain: 'bitcoin', network: 'testnet4', from: 'tb1qowner', plan })),
  );
});

/* ----------------------------------------------- the key belongs to the vault */

test('the attestation key comes from the phrase, and the phrase never leaves the browser', () => {
  const mnemonic = phrase();
  const first = attestationKeys(mnemonic, 1);
  assert.equal(first.publicKey.length, 1952, 'ML-DSA-65 public key');
  assert.deepEqual(attestationKeys(mnemonic, 1).publicKeyBase64, first.publicKeyBase64, 'the same phrase restores the same key');
  assert.notEqual(attestationKeys(mnemonic, 2).publicKeyBase64, first.publicKeyBase64, 'a new epoch is a new key');
  assert.notEqual(attestationKeys(phrase(), 1).publicKeyBase64, first.publicKeyBase64, 'another phrase, another key');

  // Nothing derived from a server-side secret can produce this key.
  const serverSeed = new Uint8Array(crypto.randomBytes(64));
  assert.notEqual(deriveAttestationKeys(serverSeed, 1).publicKeyBase64, first.publicKeyBase64);
});

test('a record cannot be moved to another transaction, vault, statement or key', () => {
  const keys = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const publicKey = keys.publicKeyBase64;
  const authorization = signAuthorization({
    vaultId: 'tb1qvault', accountId: 'bitcoin', transactionHash: 'DIGEST-ONE', statementDigest: 'STATEMENT',
    approvalMethod: 'veyns:palm', approvals: '1 of 1', approvedBy: ['alex'], decisionIds: ['decision-1'], approvedAt: 1_800_000_000,
  }, keys);

  assert.ok(verifyAuthorization(authorization, publicKey, { transactionHash: 'DIGEST-ONE', vaultId: 'tb1qvault' }).ok);
  assert.match(verifyAuthorization(authorization, publicKey, { transactionHash: 'DIGEST-TWO' }).reason, /different transaction/);
  assert.match(verifyAuthorization(authorization, publicKey, { vaultId: 'tb1qother' }).reason, /different vault/);
  assert.match(verifyAuthorization(authorization, publicKey, { statementDigest: 'OTHER' }).reason, /different statement/);
  assert.match(verifyAuthorization(authorization, publicKey, { keyEpoch: 2 }).reason, /retired key/);
  assert.match(verifyAuthorization(authorization, publicKey, { approvedBy: ['someone-else'] }).reason, /different approvers/);
  assert.match(verifyAuthorization(authorization, publicKey, { decisionIds: ['another'] }).reason, /different palm decisions/);
  assert.match(verifyAuthorization(authorization, publicKey, { notBefore: 1_900_000_000 }).reason, /predates these approvals/);
  assert.match(verifyAuthorization(authorization, null).reason, /no registered attestation key/);

  for (const field of ['transactionHash', 'vaultId', 'statementDigest', 'approvedAt', 'biometricVerified']) {
    const edited = { ...authorization, record: { ...authorization.record, [field]: 'CHANGED' } };
    assert.equal(verifyAuthorization(edited, publicKey).ok, false, field);
  }
  const other = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  assert.match(verifyAuthorization(authorization, other.publicKeyBase64).reason, /not registered|does not verify/);

  // The record says nothing about the biometric beyond that it happened.
  const text = canonicalJson(authorization.record);
  for (const word of ['template', 'image', 'palmData', 'score']) {
    assert.ok(!text.includes(word), `the record must not carry ${word}`);
  }
});

/* --------------------------------------------- the device refuses to sign */

test('the device will not sign a plan that is not the one approved', () => {
  const mnemonic = phrase();
  const account = accountFrom(mnemonic);
  const plan = planSpend({ publicKey: Buffer.from(account.publicKey), utxos: coins, toAddress: DEST, amountSats: 120_000, feeRate: 2 });
  const approved = planDigest({ network: 'testnet4', from: account.address, plan });
  assert.ok(signInBrowser(mnemonic, plan, account.address, { transactionHash: approved, network: 'testnet4' }).hex);

  const attacks = {
    'destination moved': { ...plan, outputs: plan.outputs.map(o => (o.address === DEST ? { ...o, address: accountFrom(phrase()).address } : o)) },
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
});

/* ------------------------------------------------ end to end, through the API */

test('a withdrawal carries its digest from the sentence to the receipt', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const wallet = await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation, transactionHash } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  assert.equal(operation.details.transaction_hash, transactionHash, 'the person reads the digest');

  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.equal(unlocked.transactionHash, transactionHash);
  assert.equal(planDigest({ network: 'testnet4', from: wallet.address, plan: unlocked.plan }), transactionHash);
  // Nothing is written until the owner's device signs the record.
  assert.equal((await alex.get(`/api/operations/${operation.id}/receipt`)).status, 404);

  const { txid } = await signAndSend(env, alex, operation.id);
  assert.ok(txid);

  const receipt = ok(await alex.get(`/api/operations/${operation.id}/receipt`));
  assert.equal(receipt.signedBy, 'vault');
  assert.equal(receipt.publicKey, alex.attestation.publicKeyBase64);
  assert.equal(receipt.authorization.record.transactionHash, transactionHash);
  assert.equal(receipt.authorization.record.vaultId, wallet.address);
  assert.equal(receipt.authorization.record.biometricVerified, true);
  assert.ok(receipt.verified.ok);
  assert.ok(verifyAuthorization(receipt.authorization, receipt.publicKey, { transactionHash }).ok);
});

test('the server cannot forge a receipt: it has only the public key', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));

  // The secret that signs authorisations appears nowhere in the server's database.
  const db = await env.app.db();
  const secret = Buffer.from(alex.attestation.secretKey);
  // From the middle of the key: the first bytes of an ML-DSA secret key are also the first
  // bytes of its public key, so a prefix would match the public half that is stored on purpose.
  const probes = [secret.subarray(1000, 1060).toString('base64'), secret.subarray(1000, 1060).toString('hex')];
  for (const table of ['wallets', 'operations', 'approvals', 'accounts', 'members', 'users']) {
    const dump = JSON.stringify((await db.query(`SELECT * FROM ${table}`)).rows);
    for (const probe of probes) assert.ok(!dump.includes(probe), `${table} holds attestation key material`);
  }
  const row = (await db.query('SELECT * FROM wallets WHERE user_id = $1', [alex.id])).rows[0];
  const stored = JSON.parse(row.attestation_chain);
  assert.equal(stored.length, 1, 'the lineage is one link long');
  assert.equal(stored[0].record.publicKey, alex.attestation.publicKeyBase64, 'only the public half is stored');
  assert.equal(row.sealed_key, null, 'and no wallet key either');

  // The best the server can do is sign with a key of its own. It does not verify.
  const forged = attestFor(env, alex, unlocked, { keys: deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1) });
  const signed = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: unlocked.plan });
  const refused = await alex.post(`/api/operations/${operation.id}/broadcast`, { hex: signed.hex, authorization: forged });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /not registered|does not verify/);
  assert.equal(env.world.log.broadcast.length, 0);

  // Nor can it re-point the vault's registered key to one it controls without an approval.
  const impostor = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  assert.equal((await alex.post('/api/attestation/register', {
    operationId: operation.id,
    attestationRegistration: registrationFor({ vaultId: alex.address, keys: impostor, epoch: 2, previousKeys: impostor }),
  })).status, 409, 'a withdrawal is not an approved key replacement');
  assert.equal(ok(await alex.get('/api/wallet')).wallet.attestation.publicKey, alex.attestation.publicKeyBase64);
});

test('a record for the wrong transaction, vault or approvals is refused at broadcast', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  const signed = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: unlocked.plan });

  const attacks = {
    'another transaction': { transactionHash: 'someone-elses-digest' },
    'another vault': { vaultId: 'tb1qsomeoneelse' },
    'another statement': { statementDigest: 'another-statement' },
    'approvals it did not have': { approvedBy: ['nobody'] },
    'palm decisions it did not have': { decisionIds: ['invented'] },
    'a retired key': { keys: deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 2) },
    'a date in the future': { approvedAt: env.now() + 4000 },
  };
  for (const [what, tweak] of Object.entries(attacks)) {
    const refused = await alex.post(`/api/operations/${operation.id}/broadcast`, {
      hex: signed.hex, authorization: attestFor(env, alex, unlocked, tweak),
    });
    assert.equal(refused.status, 409, what);
    assert.equal(env.world.log.broadcast.length, 0, what);
  }

  // The honest record still works afterwards.
  assert.ok((await signAndSend(env, alex, operation.id)).txid);
});

test('an authorisation cannot be replayed onto another withdrawal', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const first = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, first.operation.id);
  const unlockedFirst = ok(await alex.post(`/api/operations/${first.operation.id}/unlock`, {}));
  const stolen = attestFor(env, alex, unlockedFirst);
  await signAndSend(env, alex, first.operation.id);

  // A second withdrawal, somewhere else, with the first one's record pasted onto it.
  env.world.chain.utxos = [{ txid: 'f'.repeat(64), vout: 0, value: 400_000 }];
  const second = ok(await alex.post('/api/withdrawals', { to: accountFrom(phrase()).address, amount: 200_000 }));
  await palmApprove(env, alex, second.operation.id);
  const unlockedSecond = ok(await alex.post(`/api/operations/${second.operation.id}/unlock`, {}));
  const signed = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: unlockedSecond.plan });

  const refused = await alex.post(`/api/operations/${second.operation.id}/broadcast`, { hex: signed.hex, authorization: stolen });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /different transaction/);
  assert.equal(env.world.log.broadcast.length, 1, 'only the first withdrawal was ever sent');
});

test('a plan swapped in the database is refused by the device and by the server', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  await palmApprove(env, alex, operation.id);

  const db = await env.app.db();
  const before = JSON.parse((await db.query('SELECT payload FROM operations WHERE id = $1', [operation.id])).rows[0].payload);
  const moved = { ...before, outputs: before.outputs.map(o => (o.address === DEST ? { ...o, address: accountFrom(phrase()).address } : o)) };
  await db.query('UPDATE operations SET payload = $1 WHERE id = $2', [JSON.stringify(moved), operation.id]);

  // The unlock itself refuses: the stored plan no longer hashes to what was approved.
  const refusedUnlock = await alex.post(`/api/operations/${operation.id}/unlock`, {});
  assert.equal(refusedUnlock.status, 409);
  assert.match(refusedUnlock.body.error, /no longer matches/);

  const signed = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: moved });
  const refused = await alex.post(`/api/operations/${operation.id}/broadcast`, {
    hex: signed.hex,
    authorization: attestFor(env, alex, { ...before, address: alex.address, transactionHash: before.transactionHash, statementDigest: 'x', approvals: '1 of 1', approvedBy: [alex.id], decisionIds: [] }),
  });
  assert.equal(refused.status, 409);
  assert.equal(env.world.log.broadcast.length, 0);
});

test('without a palm there is no authorisation and nothing to broadcast', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = coins;

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  assert.equal((await alex.get(`/api/operations/${operation.id}/receipt`)).status, 404);
  assert.equal((await alex.post(`/api/operations/${operation.id}/unlock`, {})).status, 409);
  assert.equal((await alex.post(`/api/operations/${operation.id}/broadcast`, { hex: '00' })).status, 409);
  assert.equal(env.world.log.broadcast.length, 0);
});

/* ------------------------------------------------------------- rotation */

test('replacing the attestation key takes a palm, and retires the old one', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const old = alex.attestation;

  const { operation, epoch } = ok(await alex.post('/api/attestation/approval', {}));
  assert.equal(operation.kind, 'attestation');
  assert.equal(epoch, 2);
  const next = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 2);

  // Not before the palm.
  assert.equal((await alex.post('/api/attestation/register', {
    operationId: operation.id, attestationRegistration: registrationFor({ vaultId: alex.address, keys: next, epoch: 2, previousKeys: old }),
  })).status, 409);

  await palmApprove(env, alex, operation.id);
  const registered = ok(await alex.post('/api/attestation/register', {
    operationId: operation.id, attestationRegistration: registrationFor({ vaultId: alex.address, keys: next, epoch: 2, previousKeys: old }),
  }));
  assert.equal(registered.attestation.publicKey, next.publicKeyBase64);
  assert.equal(registered.attestation.epoch, 2);

  // The old key no longer authorises anything.
  env.world.chain.utxos = coins;
  const { operation: spend } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, spend.id);
  const unlocked = ok(await alex.post(`/api/operations/${spend.id}/unlock`, {}));
  assert.equal(unlocked.attestationEpoch, 2, 'the device is told which key to use');
  const signed = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: unlocked.plan });

  const withOld = await alex.post(`/api/operations/${spend.id}/broadcast`, {
    hex: signed.hex, authorization: attestFor(env, alex, unlocked, { keys: old }),
  });
  assert.equal(withOld.status, 409);
  assert.equal(env.world.log.broadcast.length, 0);

  const withNew = ok(await alex.post(`/api/operations/${spend.id}/broadcast`, {
    hex: signed.hex, authorization: attestFor(env, alex, unlocked, { keys: next }),
  }));
  assert.ok(withNew.txid);
});

/** A browser signing a plan it was handed, for tests that need raw bytes. */
export function rawSignature(plan, account) {
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
