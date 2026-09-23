/*
 * Vaults made before the key moved into the browser. They sign on the server, have no
 * recovery phrase, and can be moved in with a palm quorum — taking their coins with them.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import * as btc from '@scure/btc-signer';
import { start, ok, signedIn, palmApprove, legacyWallet, browserKey , startWithMigration } from './harness.js';

test('an older vault still shows its Bitcoin account, and says why it has no others', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-legacy');
  const legacy = await legacyWallet(env, alex);

  const view = ok(await alex.get('/api/wallet'));
  assert.equal(view.wallet.custody, 'server');
  assert.equal(view.accounts.length, 1, 'the Bitcoin account is filled in from the wallet');
  assert.equal(view.accounts[0].network, 'bitcoin');
  assert.equal(view.accounts[0].address, legacy.address);

  const refused = await alex.post('/api/accounts/approval', { network: 'ethereum' });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /no recovery phrase/);
  assert.match((await alex.post('/api/recovery', {})).body.error, /no recovery phrase/);
});

test('an older vault moves into the browser, sweeping its coins to the new address', async t => {
  const env = await startWithMigration(t);
  const alex = await signedIn(env, 'sub-move');
  const legacy = await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 240_000 }];

  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  assert.equal(operation.kind, 'upgrade');
  assert.equal(operation.details.from, legacy.address);
  // Nothing can be unlocked until the palm approval is in.
  assert.equal((await alex.post(`/api/operations/${operation.id}/unlock`, {})).status, 409);

  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.ok(unlocked.unlock && unlocked.salt, 'the browser gets a secret for the key it is about to make');

  const fresh = browserKey();
  const moved = ok(await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: fresh.publicKey, attestationRegistration: fresh.attestationRegistration }));
  assert.equal(moved.wallet.address, fresh.address);
  assert.equal(moved.wallet.custody, 'client');

  // The coins went to the new address, in one transaction, with nothing left behind.
  assert.equal(env.world.log.broadcast.length, 1);
  const tx = env.world.log.broadcast[0].tx;
  assert.equal(tx.outputsLength, 1);
  assert.equal(btc.Address(btc.TEST_NETWORK).encode(btc.OutScript.decode(tx.getOutput(0).script)), fresh.address);
  assert.equal(moved.txid, tx.id);
  assert.equal(Number(tx.getOutput(0).amount), moved.sweptSats);
  assert.ok(moved.sweptSats > 230_000 && moved.sweptSats < 240_000, 'everything but the fee');

  // The server has forgotten the old key, and the vault now behaves like any other.
  const db = await env.app.db();
  const { rows } = await db.query('SELECT sealed_key, unlock_sealed FROM wallets WHERE user_id = $1', [alex.id]);
  assert.equal(rows[0].sealed_key, null);
  assert.ok(rows[0].unlock_sealed);

  const view = ok(await alex.get('/api/wallet'));
  assert.equal(view.accounts[0].address, fresh.address, 'the Bitcoin account followed the vault');
  assert.equal(view.history.find(op => op.kind === 'upgrade').txid, tx.id);
  assert.equal(ok(await alex.post('/api/accounts/approval', { network: 'ethereum' })).operation.kind, 'account');
  assert.equal((await alex.post('/api/wallet/upgrade/approval', {})).status, 409, 'it can only be moved once');
});

test('a vault with an unconfirmed payment waits, and keeps its key until it is safe', async t => {
  const env = await startWithMigration(t);
  const alex = await signedIn(env, 'sub-pending');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 120_000 }];
  env.world.chain.pending = 50_000;

  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  await palmApprove(env, alex, operation.id);
  const fresh = browserKey();
  const refused = await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: fresh.publicKey, attestationRegistration: fresh.attestationRegistration });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /first confirmation/);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing was spent');
  assert.equal(ok(await alex.get('/api/wallet')).wallet.custody, 'server', 'the old key is still there');

  // Once it confirms, the same approved request goes through.
  env.world.chain.pending = 0;
  env.world.chain.utxos.push({ txid: 'c'.repeat(64), vout: 1, value: 50_000 });
  const moved = ok(await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: fresh.publicKey, attestationRegistration: fresh.attestationRegistration }));
  assert.equal(moved.wallet.custody, 'client');
  assert.equal(env.world.log.broadcast[0].tx.inputsLength, 2, 'both coins came along');
});

test('a move needs its own palm approval, and an address that matches its key', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-guard');
  const omar = await signedIn(env, 'sub-guard-2');
  await legacyWallet(env, alex);
  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  const fresh = browserKey();

  // Not approved yet.
  assert.equal((await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: fresh.publicKey, attestationRegistration: fresh.attestationRegistration })).status, 409);
  // Nobody else can drive it.
  assert.equal((await omar.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: fresh.publicKey, attestationRegistration: fresh.attestationRegistration })).status, 404);

  await palmApprove(env, alex, operation.id);
  const mismatched = await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: browserKey().publicKey, attestationRegistration: fresh.attestationRegistration });
  assert.equal(mismatched.status, 400);
  assert.match(mismatched.body.error, /does not match/);
  assert.equal(ok(await alex.get('/api/wallet')).wallet.custody, 'server');
  assert.equal(env.world.log.broadcast.length, 0);
});

test('a vault with nobody on its roster cannot approve anything', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-rosterless');
  await legacyWallet(env, alex);

  // As the first version left them: a wallet, and nobody able to approve for it. The cure is
  // the migration backfill, proved in migrate.test.js; this pins the symptom it cured.
  const db = await env.app.db();
  await db.query('DELETE FROM members WHERE wallet_user_id = $1', [alex.id]);

  const { operation } = ok(await alex.post('/api/wallet/reset/approval', {}));
  const refused = await alex.post(`/api/operations/${operation.id}/approval`, {});
  assert.equal(refused.status, 403);
  assert.match(refused.body.error, /not an approver/);
});
