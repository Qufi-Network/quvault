/*
 * Payments on notice. A payment to an address the vault has never paid, or past the daily limit,
 * waits 24 hours after notice is given; everyone on the vault hears of it and any of them can
 * cancel it. Paying a known address within the limit goes straight ahead, as before.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend } from './harness.js';

const DAY = 24 * 3600;
const withNotices = t => start(t, { paymentNotices: true });

async function owner(env) {
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 20_000_000 }];
  return alex;
}

async function pay(env, who, amount, to = DEST) {
  const { operation } = ok(await who.post('/api/withdrawals', { to, amount }));
  await palmApprove(env, who, operation.id);
  await signAndSend(env, who, operation.id);
  return operation;
}

test('a first payment to an address waits a day after notice, and the phone says notice was given', async t => {
  const env = await withNotices(t);
  const alex = await owner(env);

  const refused = await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 });
  assert.equal(refused.status, 409);
  assert.equal(refused.body.code, 'notice_needed');
  assert.match(refused.body.error, /never paid that address/);

  const { notice } = ok(await alex.post('/api/notices', { network: 'bitcoin', to: DEST, amount: '100000' }));
  assert.equal(notice.readyAt, env.now() + DAY);
  assert.equal(ok(await alex.get('/api/wallet')).notices.length, 1);

  // Not before the day is up.
  env.advance(DAY - 60);
  const early = await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 });
  assert.equal(early.body.code, 'notice_waiting');
  // Nor for more than notice was given of.
  env.advance(120);
  assert.equal((await alex.post('/api/withdrawals', { to: DEST, amount: 100_001 })).body.code, 'notice_needed');

  const operation = await pay(env, alex, 100_000);
  assert.equal(operation.details.notice_id, notice.id, 'the phone shows the payment was announced');
  assert.match(operation.details.notice, /everyone on the vault was told/);
  // The notice is used up, and the address is known from now on.
  assert.equal(ok(await alex.get('/api/wallet')).notices.length, 0);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 20_000_000 }];
  ok(await alex.post('/api/withdrawals', { to: DEST, amount: 50_000 }));
});

test('a known address within the daily limit goes straight ahead; past the limit it needs notice', async t => {
  const env = await withNotices(t);
  const alex = await owner(env);
  ok(await alex.post('/api/notices', { network: 'bitcoin', to: DEST, amount: '1000000' }));
  env.advance(DAY + 1);
  await pay(env, alex, 1_000_000);
  env.advance(DAY + 1); // that payment was on notice, and is a day old anyway

  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 20_000_000 }];
  await pay(env, alex, 3_000_000);
  // 0.03 already today; another 0.03 takes it past 0.05 tBTC.
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 20_000_000 }];
  const over = await alex.post('/api/withdrawals', { to: DEST, amount: 3_000_000 });
  assert.equal(over.body.code, 'notice_needed');
  assert.match(over.body.error, /past 0\.05000000 tBTC in 24 hours/);
  // Under the limit is still fine, and a day later the limit is clear again.
  ok(await alex.post('/api/withdrawals', { to: DEST, amount: 1_000_000 }));
  env.advance(DAY + 1);
  ok(await alex.post('/api/withdrawals', { to: DEST, amount: 3_000_000 }));
});

test('anyone on the vault can cancel a notice; a stranger cannot see or touch it; a freeze cancels them all', async t => {
  const env = await withNotices(t);
  const alex = await owner(env);
  const bea = await signedIn(env, 'sub-bea');
  const eve = await signedIn(env, 'sub-eve');
  await walletFor(env, bea);
  const made = ok(await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Bea' }));
  await palmApprove(env, alex, made.operation.id);
  const [invite] = ok(await alex.get('/api/invites')).invites;
  const join = ok(await bea.post('/api/invites/join', { code: invite.code }));
  await palmApprove(env, bea, join.operation.id);

  const { notice } = ok(await alex.post('/api/notices', { network: 'bitcoin', to: DEST, amount: '100000' }));
  // Bea sees it, from her own dashboard; Eve neither sees it nor can cancel it.
  assert.equal(ok(await bea.get('/api/wallet')).notices[0].id, notice.id);
  assert.equal(ok(await eve.get('/api/wallet')).notices.length, 0);
  assert.equal((await eve.post('/api/notices/cancel', { id: notice.id })).status, 404);
  assert.equal((await eve.post('/api/notices', { vaultOwnerId: alex.id, network: 'bitcoin', to: DEST, amount: '1' })).status, 404);

  ok(await bea.post('/api/notices/cancel', { id: notice.id }));
  assert.equal(ok(await alex.get('/api/wallet')).notices.length, 0, 'a cancelled notice is gone for everyone');
  assert.equal((await alex.post('/api/notices/cancel', { id: notice.id })).status, 404, 'and cannot be cancelled twice');

  // A freeze stops every notice with everything else.
  ok(await alex.post('/api/notices', { network: 'bitcoin', to: DEST, amount: '100000' }));
  ok(await bea.post('/api/vault/freeze', { vaultOwnerId: alex.id }));
  assert.equal(ok(await alex.get('/api/wallet')).notices.length, 0);
});

test('a notice that is never used lapses three days after it is ready', async t => {
  const env = await withNotices(t);
  const alex = await owner(env);
  ok(await alex.post('/api/notices', { network: 'bitcoin', to: DEST, amount: '100000' }));
  env.advance(DAY + 3 * DAY + 1);
  assert.equal(ok(await alex.get('/api/wallet')).notices.length, 0);
  assert.equal((await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 })).body.code, 'notice_needed');
});
