/*
 * Locking an account to the people who sign for it: the moment a threshold stops being a rule
 * this server remembers and becomes one the chain keeps.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { start, ok, signedIn, palmApprove, walletFor, signAndSend, setRules } from './harness.js';
import { cosignerFrom } from '../client/wallet.js';
import { multisigAddressOf } from '../src/bitcoin.js';

const PHRASES = {
  alex: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  bea: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  cara: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
};

/** A signer making the key they sign this vault's Bitcoin with. */
async function signingKey(env, client, vaultOwnerId, phrase) {
  const started = ok(await client.post('/api/signing-key/approval', { vaultOwnerId }));
  await palmApprove(env, client, started.operation.id);
  ok(await client.post(`/api/operations/${started.operation.id}/unlock`, {}));
  const key = cosignerFrom(phrase, started.index);
  ok(await client.post('/api/signing-key/register', {
    operationId: started.operation.id,
    publicKey: Buffer.from(key.publicKey).toString('hex'),
  }));
  return key;
}

/** Somebody joining a vault by invitation, the ordinary way. */
async function joins(env, owner, guest, label) {
  const { operation } = ok(await owner.post('/api/invites/approval', { network: 'bitcoin', label }));
  for (let i = 0; i < operation.required; i++) await palmApprove(env, owner, operation.id);
  const { invites } = ok(await owner.get('/api/invites'));
  const join = ok(await guest.post('/api/invites/join', { code: invites[0].code }));
  await palmApprove(env, guest, join.operation.id);
}

/** A vault with three signers, each holding their own key, and some coins in it. */
async function vaultOfThree(env, { coins = 900_000 } = {}) {
  const alex = await signedIn(env, 'sub-alex');
  const bea = await signedIn(env, 'sub-bea');
  const cara = await signedIn(env, 'sub-cara');
  await walletFor(env, alex);
  await walletFor(env, bea);
  await walletFor(env, cara);
  await joins(env, alex, bea, 'Bea');
  await joins(env, alex, cara, 'Cara');

  const keys = {
    alex: await signingKey(env, alex, alex.id, PHRASES.alex),
    bea: await signingKey(env, bea, alex.id, PHRASES.bea),
    cara: await signingKey(env, cara, alex.id, PHRASES.cara),
  };
  if (coins) env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: coins }];
  return { alex, bea, cara, keys };
}

test('locking moves the coins into a script that names every signer', async t => {
  const env = await start(t);
  const { alex, bea, keys } = await vaultOfThree(env);
  await setRules(env, alex, { rules: [{ upToSats: null, approvals: 2 }], approvers: [bea] });

  const expected = multisigAddressOf(Object.values(keys).map(k => Buffer.from(k.publicKey).toString('hex')), 2);
  const asked = ok(await alex.post('/api/accounts/lock', { required: 2 }));
  assert.equal(asked.quorum.address, expected, 'the address is the script, built from the three keys');
  assert.equal(asked.quorum.required, 2);
  assert.match(asked.operation.statement, /Lock my Bitcoin to 2 of 3 on the chain and move/);
  assert.equal(asked.plan.outputs[0].address, expected, 'and everything goes to it');

  // It takes the palms the account's own rules ask for before anything moves.
  assert.equal(asked.operation.required, 2);
  await palmApprove(env, alex, asked.operation.id);
  assert.equal(ok(await alex.get('/api/wallet')).accounts[0].quorum, null, 'one palm changes nothing');

  await palmApprove(env, bea, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);

  const account = ok(await alex.get('/api/wallet')).accounts.find(a => a.network === 'bitcoin');
  assert.equal(account.address, expected, 'the account now lives at the script');
  assert.equal(account.quorum.required, 2);
  assert.equal(account.quorum.keys.length, 3);
  assert.ok(account.quorum.previousAddress, 'and remembers where it used to be');
  assert.notEqual(account.quorum.previousAddress, account.address);

  // The coins really did move: one transaction, everything, to the new address.
  const sent = env.world.log.broadcast.at(-1);
  assert.ok(sent, 'a transaction was broadcast');
  assert.equal(sent.tx.outputsLength, 1);
});

test('nothing is locked until everyone has a key to be locked to', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bea = await signedIn(env, 'sub-bea');
  await walletFor(env, alex);
  await walletFor(env, bea);
  await joins(env, alex, bea, 'Bea');
  await signingKey(env, alex, alex.id, PHRASES.alex);

  const early = await alex.post('/api/accounts/lock', { required: 2 });
  assert.equal(early.status, 409);
  assert.match(early.body.error, /Still waiting for: Bea/);

  await signingKey(env, bea, alex.id, PHRASES.bea);
  const now = ok(await alex.post('/api/accounts/lock', { required: 2 }));
  assert.equal(now.quorum.signers, 2);
});

test('a threshold the chain cannot keep is refused before anybody approves it', async t => {
  const env = await start(t);
  const { alex } = await vaultOfThree(env);

  for (const required of [0, 4, 2.5, 'two', null]) {
    const attempt = await alex.post('/api/accounts/lock', { required });
    assert.equal(attempt.status, 400, `required=${required} should not be allowed`);
    assert.match(attempt.body.error, /between one and 3/);
  }

  // A vault with nobody else in it has no quorum to lock to.
  const solo = await signedIn(env, 'sub-solo');
  await walletFor(env, solo);
  await signingKey(env, solo, solo.id, PHRASES.cara);
  const alone = await solo.post('/api/accounts/lock', { required: 1 });
  assert.equal(alone.status, 409);
  assert.match(alone.body.error, /at least two signers/);
});

test('a lock that cannot be sent leaves the account exactly as it was', async t => {
  const env = await start(t);
  const { alex } = await vaultOfThree(env);
  const before = ok(await alex.get('/api/wallet')).accounts[0].address;

  const asked = ok(await alex.post('/api/accounts/lock', { required: 2 }));
  await palmApprove(env, alex, asked.operation.id);

  env.world.chain.broadcastError = 'min relay fee not met';
  await assert.rejects(() => signAndSend(env, alex, asked.operation.id));

  const account = ok(await alex.get('/api/wallet')).accounts[0];
  assert.equal(account.quorum, null, 'the account is not a quorum');
  assert.equal(account.address, before, 'and the coins are where they were');
});

test('an account with no coins locks without a transaction', async t => {
  const env = await start(t);
  const { alex } = await vaultOfThree(env, { coins: 0 });

  const asked = ok(await alex.post('/api/accounts/lock', { required: 2 }));
  assert.equal(asked.plan, null);
  assert.match(asked.operation.statement, /^Lock my Bitcoin to 2 of 3 on the chain$/);

  await palmApprove(env, alex, asked.operation.id);
  const account = ok(await alex.get('/api/wallet')).accounts[0];
  assert.equal(account.quorum.required, 2, 'there was nothing to move, so it is simply locked');
  assert.equal(env.world.log.broadcast.length, 0, 'and nothing was broadcast');
});

test('an account is locked once, and its coins are not spent the old way afterwards', async t => {
  const env = await start(t);
  const { alex, bea } = await vaultOfThree(env);
  await setRules(env, alex, { rules: [{ upToSats: null, approvals: 2 }], approvers: [bea] });

  const asked = ok(await alex.post('/api/accounts/lock', { required: 2 }));
  await palmApprove(env, alex, asked.operation.id);
  await palmApprove(env, bea, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);

  const again = await alex.post('/api/accounts/lock', { required: 3 });
  assert.equal(again.status, 409);
  assert.match(again.body.error, /already locked/);

  // And a spend from it is now planned against the script, not against the old single key.
  const account = ok(await alex.get('/api/wallet')).accounts[0];
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 500_000 }];
  const spend = ok(await alex.post('/api/withdrawals', { to: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', amount: 100_000 }));
  assert.equal(spend.operation.required, 2, 'the threshold is the one the chain keeps');
  assert.equal(spend.plan.outputs.find(o => o.sats === spend.plan.changeSats).address, account.address,
    'and the change comes back to the script');
});

test('the statement the palms approve names the transaction, the keys and the threshold', async t => {
  const env = await start(t);
  const { alex } = await vaultOfThree(env);
  const asked = ok(await alex.post('/api/accounts/lock', { required: 2 }));

  const view = ok(await alex.get('/api/wallet')).pending.find(op => op.id === asked.operation.id);
  const shown = view.details;
  assert.equal(shown.action, 'lock to a quorum on the chain');
  assert.equal(shown.approvals_required, '2 of 3 signatures');
  assert.equal(shown.signers, 'Owner, Bea, Cara');
  assert.equal(shown.to, asked.quorum.address);
  assert.ok(shown.transaction_hash, 'the exact transaction is part of what is approved');
  assert.equal(shown.amount_sats, asked.plan.sentSats);
});
