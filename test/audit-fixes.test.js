/*
 * The findings of the independent audit of 2026-11-04, each replayed against the fixed app.
 * The Ethereum ones (C1, H2, H4 on a Palm Wallet, the fee cap) are in contracts/test and
 * test/palm-wallet-app.test.js; these are the ones that cut across Bitcoin as well.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEST, ISSUER, CLIENT_ID, start, ok, signedIn, palmApprove, walletFor, signAndSend } from './harness.js';
import { cosignerFrom } from '../client/wallet.js';
import { signKeyProof } from '../src/key-proof.js';
import { checkPalmProof } from '../src/palm-proof.js';

const PHRASES = {
  alex: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  mallory: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
};
const hexKey = key => Buffer.from(key.publicKey).toString('hex');

async function signingKey(env, client, vaultOwnerId, phrase) {
  const started = ok(await client.post('/api/signing-key/approval', { vaultOwnerId }));
  await palmApprove(env, client, started.operation.id);
  const unlocked = ok(await client.post(`/api/operations/${started.operation.id}/unlock`, {}));
  const key = cosignerFrom(phrase, started.index);
  return { started, unlocked, key };
}

async function invite(env, owner, guest, label) {
  const { operation } = ok(await owner.post('/api/invites/approval', { network: 'bitcoin', label }));
  for (let i = 0; i < operation.required; i++) await palmApprove(env, owner, operation.id);
  const { invites } = ok(await owner.get('/api/invites'));
  const join = ok(await guest.post('/api/invites/join', { code: invites[0].code }));
  await palmApprove(env, guest, join.operation.id);
}

const register = (client, operationId, publicKey, proof) =>
  client.post('/api/signing-key/register', { operationId, publicKey, ...(proof ? { proof } : {}) });

async function trustFor(env, sub) {
  const { keys } = await (await env.world.fetchImpl(`${ISSUER}/jwks.json`)).json();
  return { issuer: ISSUER, audience: CLIENT_ID, keys, subjects: [sub, `pairwise:${CLIENT_ID}:${sub}`] };
}

test('audit H1: a signing key needs proof its holder registered it, and nobody can claim someone else\'s', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const mallory = await signedIn(env, 'sub-mallory');
  await walletFor(env, alex);
  await walletFor(env, mallory);
  await invite(env, alex, mallory, 'Mallory');

  // Alex registers his key, with the proof his browser makes.
  const mine = await signingKey(env, alex, alex.id, PHRASES.alex);
  assert.deepEqual(mine.unlocked.keyBinding, { vaultOwnerId: alex.id, memberId: alex.id }, 'the browser is told what its proof must name');
  ok(await register(alex, mine.started.operation.id, hexKey(mine.key),
    signKeyProof(mine.key.privateKey, { vaultOwnerId: alex.id, memberId: alex.id, publicKey: hexKey(mine.key) })));

  // Mallory tries to make Alex's key hers.
  const hers = await signingKey(env, mallory, alex.id, PHRASES.mallory);
  const alexKey = hexKey(mine.key);
  let refused = await register(mallory, hers.started.operation.id, alexKey);
  assert.equal(refused.status, 400, 'no proof');
  refused = await register(mallory, hers.started.operation.id, alexKey,
    signKeyProof(hers.key.privateKey, { vaultOwnerId: alex.id, memberId: mallory.id, publicKey: alexKey }));
  assert.equal(refused.status, 400, 'a proof made with her own key');
  // With Alex's stolen phrase she can make a proof that verifies; the key is still Alex's.
  refused = await register(mallory, hers.started.operation.id, alexKey,
    signKeyProof(mine.key.privateKey, { vaultOwnerId: alex.id, memberId: mallory.id, publicKey: alexKey }));
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /already belongs to someone else/);
  // A proof cannot be carried to another person: Alex's own proof, presented by Mallory.
  refused = await register(mallory, hers.started.operation.id, alexKey,
    signKeyProof(mine.key.privateKey, { vaultOwnerId: alex.id, memberId: alex.id, publicKey: alexKey }));
  assert.equal(refused.status, 400);

  // Her own key, with her own proof, is fine.
  ok(await register(mallory, hers.started.operation.id, hexKey(hers.key),
    signKeyProof(hers.key.privateKey, { vaultOwnerId: alex.id, memberId: mallory.id, publicKey: hexKey(hers.key) })));
});

test('audit H1: whose palm counts is fixed when a vault is locked, so a later duplicate key counts for nothing', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const mallory = await signedIn(env, 'sub-mallory');
  await walletFor(env, alex);
  await walletFor(env, mallory);
  const mine = await signingKey(env, alex, alex.id, PHRASES.alex);
  ok(await register(alex, mine.started.operation.id, hexKey(mine.key),
    signKeyProof(mine.key.privateKey, { vaultOwnerId: alex.id, memberId: alex.id, publicKey: hexKey(mine.key) })));
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 1, palm: true }));
  await palmApprove(env, alex, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);

  // Mallory is invited after the lock, and (say, by an old bug or a database edit) ends up
  // with Alex's key against her name.
  await invite(env, alex, mallory, 'Mallory');
  const db = await env.app.db();
  await db.query('UPDATE members SET public_key = $1 WHERE wallet_user_id = $2 AND member_id = $3', [hexKey(mine.key), alex.id, mallory.id]);

  const refused = await mallory.post('/api/withdrawals', { vaultOwnerId: alex.id, to: DEST, amount: 10_000 });
  assert.equal(refused.status, 403, 'she is not one of the people the vault was locked to');
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 10_000 }));
  const join = await mallory.post(`/api/operations/${operation.id}/approval`, {});
  assert.equal(join.status, 403, 'and her palm does not count towards moving its coins');
});

test('audit H3: the browser refuses a palm decision that is not its own person\'s, or not for what it is about to sign', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const mine = await signingKey(env, alex, alex.id, PHRASES.alex);
  ok(await register(alex, mine.started.operation.id, hexKey(mine.key),
    signKeyProof(mine.key.privateKey, { vaultOwnerId: alex.id, memberId: alex.id, publicKey: hexKey(mine.key) })));
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 1, palm: true }));
  await palmApprove(env, alex, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 700_000 }];

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 250_000 }));
  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.equal(unlocked.palmProof.decisions.length, 1, 'the browser is handed its person\'s own decision');

  const alexTrust = await trustFor(env, 'sub-alex');
  const mallorysTrust = await trustFor(env, 'sub-mallory');
  // Alex's browser, checking Veyns' word with Veyns' keys: it is his palm, for exactly this.
  assert.doesNotThrow(() => checkPalmProof(unlocked, alexTrust));
  // Someone else's browser, or Alex's handed someone else's decision: refused.
  assert.throws(() => checkPalmProof(unlocked, mallorysTrust), /made by someone else/);
  // A record whose words were changed after the palm: refused.
  const rewritten = { ...unlocked, palmProof: { ...unlocked.palmProof, details: { ...unlocked.palmProof.details, to: 'tb1qattacker' } } };
  assert.throws(() => checkPalmProof(rewritten, alexTrust), /approves a different action/);
  // A transaction other than the one the approval names: refused.
  assert.throws(() => checkPalmProof({ ...unlocked, transactionHash: 'x'.repeat(43) }, alexTrust), /different transaction/);
  // A decision with its signature tampered with: refused.
  const [h, p, s] = unlocked.palmProof.decisions[0].split('.');
  const forged = { ...unlocked, palmProof: { ...unlocked.palmProof, decisions: [`${h}.${p}.${s.slice(0, -4)}AAAA`] } };
  assert.throws(() => checkPalmProof(forged, alexTrust), /does not verify/);
});

test('audit H4: a vault cannot be erased while its Bitcoin palm vault holds coins', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const mine = await signingKey(env, alex, alex.id, PHRASES.alex);
  ok(await register(alex, mine.started.operation.id, hexKey(mine.key),
    signKeyProof(mine.key.privateKey, { vaultOwnerId: alex.id, memberId: alex.id, publicKey: hexKey(mine.key) })));
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 1, palm: true }));
  await palmApprove(env, alex, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);
  const refused = await alex.post('/api/wallet/reset/approval', {});
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /cannot be erased while coins are locked to the chain: Bitcoin at tb1p/);
});
