/*
 * The key a signer signs Bitcoin with, which is a different thing from the palm that says
 * they meant to. It comes from their own phrase, it is theirs alone, and the vault only ever
 * learns its public half.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { start, ok, signedIn, palmApprove, walletFor } from './harness.js';
import { cosignerFrom, accountFrom } from '../client/wallet.js';
import { multisigAddressOf } from '../src/bitcoin.js';

const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** What a browser does: palm, open the phrase, derive the branch, report the public half. */
async function makeSigningKey(env, client, vaultOwnerId, mnemonic = PHRASE) {
  const started = ok(await client.post('/api/signing-key/approval', { vaultOwnerId }));
  await palmApprove(env, client, started.operation.id);
  ok(await client.post(`/api/operations/${started.operation.id}/unlock`, {}));
  const key = cosignerFrom(mnemonic, started.index);
  const registered = ok(await client.post('/api/signing-key/register', {
    operationId: started.operation.id,
    publicKey: Buffer.from(key.publicKey).toString('hex'),
  }));
  return { ...registered, key, operation: started.operation, index: started.index };
}

test('a signing key is derived from the phrase and only its public half is reported', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);

  const made = await makeSigningKey(env, alex, alex.id);
  assert.equal(made.index, 0, 'the first vault a person signs for is branch 0');
  assert.equal(made.key.path, "m/48'/1'/0'/2'/0/0", 'the ordinary co-signing path, so other tools agree');

  const me = ok(await alex.get('/api/wallet')).members.find(m => m.id === alex.id);
  assert.equal(me.signingKey, Buffer.from(made.key.publicKey).toString('hex'));
  assert.ok(me.signingKeyAt > 0);

  // The key that signs money is not the key that holds it, and neither is the palm.
  assert.notEqual(me.signingKey, Buffer.from(accountFrom(PHRASE).publicKey).toString('hex'));
  assert.ok(me.palmId, 'the palm identity is still its own thing');
});

test('nothing is registered until the palm has landed', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);

  const started = ok(await alex.post('/api/signing-key/approval', { vaultOwnerId: alex.id }));
  const key = cosignerFrom(PHRASE, started.index);
  const early = await alex.post('/api/signing-key/register', {
    operationId: started.operation.id,
    publicKey: Buffer.from(key.publicKey).toString('hex'),
  });
  assert.equal(early.status, 409);
  assert.equal(ok(await alex.get('/api/wallet')).members[0].signingKey, null);

  // And the request cannot be used to open the phrase before then either.
  assert.equal((await alex.post(`/api/operations/${started.operation.id}/unlock`, {})).status, 409);
});

test('one phrase, one branch per vault, never the same key twice', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bea = await signedIn(env, 'sub-bea');
  await walletFor(env, alex);
  await walletFor(env, bea);

  // Alex signs for her own vault, and then joins Bea's.
  const first = await makeSigningKey(env, alex, alex.id);
  const { operation } = ok(await bea.post('/api/invites/approval', { network: 'bitcoin', label: 'Alex' }));
  await palmApprove(env, bea, operation.id);
  const { invites } = ok(await bea.get('/api/invites'));
  const join = ok(await alex.post('/api/invites/join', { code: invites[0].code }));
  await palmApprove(env, alex, join.operation.id);

  const second = await makeSigningKey(env, alex, bea.id);
  assert.equal(second.index, 1, 'the second vault gets the next branch');
  assert.notEqual(
    Buffer.from(second.key.publicKey).toString('hex'),
    Buffer.from(first.key.publicKey).toString('hex'),
    'the same person signing for two vaults uses two keys, so the chain does not link them',
  );

  // Both keys come back from the same twelve words, which is the only thing she has to keep.
  assert.deepEqual(cosignerFrom(PHRASE, 0).publicKey, first.key.publicKey);
  assert.deepEqual(cosignerFrom(PHRASE, 1).publicKey, second.key.publicKey);
});

test('a signing key cannot be made for a vault you do not sign for, or twice', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const mallory = await signedIn(env, 'sub-mallory');
  await walletFor(env, alex);
  await walletFor(env, mallory);

  const outside = await mallory.post('/api/signing-key/approval', { vaultOwnerId: alex.id });
  assert.equal(outside.status, 404);
  assert.equal(ok(await alex.get('/api/wallet')).members.length, 1);

  await makeSigningKey(env, alex, alex.id);
  const again = await alex.post('/api/signing-key/approval', { vaultOwnerId: alex.id });
  assert.equal(again.status, 409);
  assert.match(again.body.error, /already have a signing key/);
});

test('somebody with no vault of their own is told why, not handed more words to keep', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);

  const { operation } = ok(await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Bob' }));
  await palmApprove(env, alex, operation.id);
  const { invites } = ok(await alex.get('/api/invites'));
  const join = ok(await bob.post('/api/invites/join', { code: invites[0].code }));
  await palmApprove(env, bob, join.operation.id);

  // Bob signs for Alex's vault but has no phrase, so there is nothing to derive from.
  const attempt = await bob.post('/api/signing-key/approval', { vaultOwnerId: alex.id });
  assert.equal(attempt.status, 409);
  assert.match(attempt.body.error, /Create your own vault first/);
});

test('the keys a vault collects are what its address would be built from', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bea = await signedIn(env, 'sub-bea');
  await walletFor(env, alex);
  await walletFor(env, bea);

  const { operation } = ok(await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Bea' }));
  await palmApprove(env, alex, operation.id);
  const { invites } = ok(await alex.get('/api/invites'));
  const join = ok(await bea.post('/api/invites/join', { code: invites[0].code }));
  await palmApprove(env, bea, join.operation.id);

  const hers = await makeSigningKey(env, alex, alex.id);
  const theirs = await makeSigningKey(env, bea, alex.id, 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong');

  const members = ok(await alex.get('/api/wallet')).members;
  assert.equal(members.length, 2);
  const keys = members.map(m => m.signingKey);
  assert.ok(keys.every(Boolean), 'both signers have a key');

  // Two of two would lock the coins to exactly these keys, and to no others.
  const address = multisigAddressOf(keys, 2);
  assert.match(address, /^tb1q/);
  assert.equal(multisigAddressOf([keys[1], keys[0]], 2), address, 'whoever builds it gets the same answer');
  assert.notEqual(
    Buffer.from(hers.key.publicKey).toString('hex'),
    Buffer.from(theirs.key.publicKey).toString('hex'),
  );
});
