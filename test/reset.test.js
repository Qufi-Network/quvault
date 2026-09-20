/*
 * Erasing a vault and starting over. It takes the same palms as any other change to the
 * account, it will not quietly strand coins, and afterwards nothing of the old vault is left.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import * as btc from '@scure/btc-signer';
import { DEST, start, ok, signedIn, palmApprove, walletFor, setRules, legacyWallet } from './harness.js';

test('a vault holding coins is not erased until they are dealt with', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 310_000 }];

  const { operation, holding } = ok(await alex.post('/api/wallet/reset/approval', {}));
  assert.equal(operation.kind, 'reset');
  assert.equal(holding, 310_000);
  assert.equal(operation.details.holds, '0.00310000 tBTC');

  // Not approved yet.
  assert.equal((await alex.post('/api/wallet/reset', { operationId: operation.id })).status, 409);
  await palmApprove(env, alex, operation.id);

  // Approved, but the coins have nowhere to go.
  const refused = await alex.post('/api/wallet/reset', { operationId: operation.id });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /still holds 0.00310000 tBTC/);
  assert.ok(ok(await alex.get('/api/wallet')).wallet, 'the vault is still here');

  // A bad address is caught before anything is deleted.
  assert.equal((await alex.post('/api/wallet/reset', { operationId: operation.id, sweepTo: 'not-an-address' })).status, 400);
  assert.ok(ok(await alex.get('/api/wallet')).wallet);

  const done = ok(await alex.post('/api/wallet/reset', { operationId: operation.id, sweepTo: DEST }));
  assert.equal(env.world.log.broadcast.length, 1);
  const tx = env.world.log.broadcast[0].tx;
  assert.equal(btc.Address(btc.TEST_NETWORK).encode(btc.OutScript.decode(tx.getOutput(0).script)), DEST);
  assert.equal(Number(tx.getOutput(0).amount), done.sweptSats);
  assert.equal(done.txid, tx.id);

  // Nothing of the old vault is left, and a new one can be made.
  const view = ok(await alex.get('/api/wallet'));
  assert.equal(view.wallet, null);
  assert.deepEqual(view.accounts, []);
  assert.deepEqual(view.members, []);
  assert.deepEqual(view.history, []);
  assert.equal(ok(await alex.post('/api/wallet/approval', { label: 'Alex' })).operation.kind, 'create');
});

test('an empty vault is erased without ceremony, and coins can be let go on purpose', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);

  const first = ok(await alex.post('/api/wallet/reset/approval', {}));
  await palmApprove(env, alex, first.operation.id);
  ok(await alex.post('/api/wallet/reset', { operationId: first.operation.id }));
  assert.equal(ok(await alex.get('/api/wallet')).wallet, null);

  // Again, this time with coins the owner deliberately abandons.
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 90_000 }];
  const second = ok(await alex.post('/api/wallet/reset/approval', {}));
  await palmApprove(env, alex, second.operation.id);
  assert.equal((await alex.post('/api/wallet/reset', { operationId: second.operation.id })).status, 409);
  ok(await alex.post('/api/wallet/reset', { operationId: second.operation.id, acceptLoss: true }));
  assert.equal(ok(await alex.get('/api/wallet')).wallet, null);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing was spent');
});

test('erasing takes the account\'s full quorum, and only its own signers', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  const omar = await signedIn(env, 'sub-omar');
  await walletFor(env, alex);
  await setRules(env, alex, {
    add: [{ code: bob.id, label: 'Bob', client: bob }],
    rules: [{ upToSats: null, approvals: 2 }],
  });

  const { operation } = ok(await alex.post('/api/wallet/reset/approval', {}));
  assert.equal(operation.required, 2);
  assert.equal((await omar.post(`/api/operations/${operation.id}/approval`, {})).status, 404, 'strangers cannot help');

  await palmApprove(env, alex, operation.id);
  assert.equal((await alex.post('/api/wallet/reset', { operationId: operation.id })).status, 409, 'one palm is not enough');
  assert.ok(ok(await alex.get('/api/wallet')).wallet);

  await palmApprove(env, bob, operation.id);
  ok(await alex.post('/api/wallet/reset', { operationId: operation.id }));
  assert.equal(ok(await alex.get('/api/wallet')).wallet, null);
  // Bob's own view no longer shows a vault he signs for.
  assert.deepEqual(ok(await bob.get('/api/wallet')).pending, []);
});

test('a browser-held vault is told to send its coins itself', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 120_000 }];

  const { operation } = ok(await alex.post('/api/wallet/reset/approval', {}));
  await palmApprove(env, alex, operation.id);
  const refused = await alex.post('/api/wallet/reset', { operationId: operation.id, sweepTo: DEST });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /signs in your browser/);
  assert.equal(env.world.log.broadcast.length, 0);
  assert.ok(ok(await alex.get('/api/wallet')).wallet, 'still here until the owner decides');
});
