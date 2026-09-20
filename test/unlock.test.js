/*
 * One palm approval opens the key once. These are the ways somebody would try to make an
 * approval that has already done its work open the key a second time.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend } from './harness.js';

/** A withdrawal with its palms already on it, ready for the owner's device to sign. */
async function approved(env, owner, amount = 200_000) {
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 600_000 }];
  const { operation } = ok(await owner.post('/api/withdrawals', { to: DEST, amount }));
  await palmApprove(env, owner, operation.id);
  return operation;
}

test('a request that has sent its transaction never opens the key again', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);

  const opened = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  await signAndSend(env, alex, operation.id);

  // The same request, the same session, seconds later: the transaction is gone, so is the key.
  const again = await alex.post(`/api/operations/${operation.id}/unlock`, {});
  assert.equal(again.status, 409);
  assert.match(again.body.error, /been used/);
  assert.notEqual(again.body.unlock, opened.unlock);
});

test('the key stays open long enough to try the broadcast again, and no longer', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);

  // The broadcast fails, so the device asks for the key again. That is the same opening.
  env.world.chain.broadcastError = 'min relay fee not met';
  const first = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  env.advance(60);
  const retry = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.equal(retry.unlock, first.unlock, 'a retry inside the window is the same opening');

  // Five minutes on, the approval has done its work whether or not anything was sent.
  env.advance(300);
  const late = await alex.post(`/api/operations/${operation.id}/unlock`, {});
  assert.equal(late.status, 409);
  assert.match(late.body.error, /been used/);
});

test('an approval nobody opened still goes stale', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);

  // Approved, then left alone for longer than a quorum has to come together.
  env.advance(1800 + 301);
  const late = await alex.post(`/api/operations/${operation.id}/unlock`, {});
  assert.equal(late.status, 409);
  assert.match(late.body.error, /been used/);
});

test('a stolen session cannot walk back through old requests', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);

  // Three ordinary days of use: the vault is made, a payment goes out, the phrase is read.
  const spend = await approved(env, alex);
  await signAndSend(env, alex, spend.id);
  const { operation: look } = ok(await alex.post('/api/recovery', {}));
  await palmApprove(env, alex, look.id); // the phrase takes two scans, one per hand
  await palmApprove(env, alex, look.id);
  ok(await alex.post(`/api/operations/${look.id}/unlock`, {}));
  env.advance(3 * 24 * 3600);

  // Somebody now holds the cookie. Every request that ever opened the key is closed to them,
  // and the session itself is still valid, which is the point: only a palm opens the key.
  for (const id of [spend.id, look.id]) {
    const attempt = await alex.post(`/api/operations/${id}/unlock`, {});
    assert.equal(attempt.status, 409, `request ${id} still opens the key`);
  }
  assert.equal(ok(await alex.get('/api/wallet')).me.id, alex.id, 'the session is genuinely still live');
});

test('the first opening is what starts the clock, not the last', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);

  // Asking repeatedly does not keep the window open: it is one opening, not a rolling one.
  ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  for (let i = 0; i < 4; i++) {
    env.advance(90);
    const step = await alex.post(`/api/operations/${operation.id}/unlock`, {});
    if (i < 3) assert.equal(step.status, 200, `${(i + 1) * 90} seconds in, it should still be open`);
    else assert.equal(step.status, 409, 'past five minutes it is shut');
  }
});
