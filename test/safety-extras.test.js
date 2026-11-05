/*
 * Three small layers against a compromised computer: a vault anyone on it can freeze at once,
 * payees shown plainly on the phone (new, or by a name a palm saved), and an alert to every other
 * signer whenever something is asked for.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend } from './harness.js';

const FCM = 'https://fcm.googleapis.com/fcm/send/';
const subscription = id => ({
  endpoint: `${FCM}${id}`,
  keys: { p256dh: 'B'.repeat(87), auth: 'a'.repeat(22) },
});

async function joins(env, owner, guest, label, approvers = [owner]) {
  const { operation } = ok(await owner.post('/api/invites/approval', { network: 'bitcoin', label }));
  for (let i = 0; i < operation.required; i++) await palmApprove(env, approvers[i], operation.id);
  const { invites } = ok(await owner.get('/api/invites'));
  const join = ok(await guest.post('/api/invites/join', { code: invites[0].code }));
  await palmApprove(env, guest, join.operation.id);
}

async function owner(env, coins = 900_000) {
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: coins }];
  return alex;
}

/* ------------------------------------------------------------------ freeze */

test('a frozen vault refuses everything in flight and anything new, until a palm unfreezes it', async t => {
  const env = await start(t);
  const alex = await owner(env);
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, operation.id);

  const frozen = ok(await alex.post('/api/vault/freeze', {}));
  assert.ok(frozen.frozen.at, 'frozen at once, with no palm');
  assert.equal(ok(await alex.get('/api/wallet')).wallet.frozen.by, alex.id);

  // What was already approved cannot be signed or sent now.
  assert.equal((await alex.post(`/api/operations/${operation.id}/unlock`, {})).status, 423);
  assert.equal((await alex.post(`/api/operations/${operation.id}/broadcast`, {})).status, 423);
  const before = ok(await alex.get('/api/wallet'));
  assert.equal(before.history.find(op => op.id === operation.id).status, 'cancelled', 'the pending payment was stopped');
  // Nothing new can start.
  const refused = await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 });
  assert.equal(refused.status, 423);
  assert.match(refused.body.error, /frozen/);

  const unfreezing = ok(await alex.post('/api/vault/unfreeze/approval', {}));
  assert.equal(unfreezing.operation.statement, 'Unfreeze my vault');
  await palmApprove(env, alex, unfreezing.operation.id);
  assert.equal(ok(await alex.get('/api/wallet')).wallet.frozen, null, 'one palm, for a vault of one');

  const again = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, again.operation.id);
  const sent = await signAndSend(env, alex, again.operation.id);
  assert.ok(sent.txid, 'and payments work again');
});

test('a cosigner can freeze the vault; a stranger cannot; the owner’s palm alone unfreezes it, and a freeze lifts by itself', async t => {
  const env = await start(t);
  const alex = await owner(env);
  const bea = await signedIn(env, 'sub-bea');
  const eve = await signedIn(env, 'sub-eve');
  await walletFor(env, bea);
  await joins(env, alex, bea, 'Bea');

  assert.equal((await eve.post('/api/vault/freeze', { vaultOwnerId: alex.id })).status, 404, 'not theirs to freeze');
  const frozen = ok(await bea.post('/api/vault/freeze', { vaultOwnerId: alex.id })).frozen;
  assert.equal(frozen.until, frozen.at + 72 * 3600, 'a freeze says when it lifts');
  assert.ok(ok(await alex.get('/api/wallet')).wallet.frozen);

  // So a signer cannot hold the vault hostage: the owner's palm alone lifts it.
  const unfreezing = ok(await alex.post('/api/vault/unfreeze/approval', {}));
  assert.equal(unfreezing.operation.required, 1, 'the owner alone');
  await palmApprove(env, alex, unfreezing.operation.id);
  assert.equal(ok(await alex.get('/api/wallet')).wallet.frozen, null);

  // Nor freeze it over and over: once lifted, the same person waits before freezing it again.
  assert.equal((await bea.post('/api/vault/freeze', { vaultOwnerId: alex.id })).status, 429);

  // The owner can freeze it too, and when nobody lifts it, it lifts itself after 72 hours.
  ok(await alex.post('/api/vault/freeze', {}));
  assert.ok(ok(await alex.get('/api/wallet')).wallet.frozen);
  env.advance(72 * 3600 + 1);
  assert.equal(ok(await alex.get('/api/wallet')).wallet.frozen, null);
});

/* ------------------------------------------------- the payee, as the phone shows it */

test('a payee the vault has paid before is no longer marked new', async t => {
  const env = await start(t);
  const alex = await owner(env);
  const first = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  assert.match(first.operation.statement, /to a new address tb1q/);
  await palmApprove(env, alex, first.operation.id);
  await signAndSend(env, alex, first.operation.id);

  const second = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  assert.match(second.operation.statement, new RegExp(String.raw`^Send 0\.00100000 tBTC to ${DEST}, network fee 0\.\d{8} tBTC$`));
  assert.equal(second.operation.details.first_payment, 'no, paid 1 time before');
});

test('a saved name takes a palm, and then shows on the phone with the address beside it', async t => {
  const env = await start(t);
  const alex = await owner(env);
  const asked = ok(await alex.post('/api/addresses/approval', { network: 'bitcoin', address: DEST, name: 'Savings' }));
  assert.equal(asked.operation.statement, `Save ${DEST} as “Savings”`);
  assert.equal(ok(await alex.get('/api/wallet')).addressBook.length, 0, 'nothing is saved before the palm');
  await palmApprove(env, alex, asked.operation.id);
  const book = ok(await alex.get('/api/wallet')).addressBook;
  assert.deepEqual(book.map(a => [a.address, a.name]), [[DEST, 'Savings']]);

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  assert.match(operation.statement, new RegExp(String.raw`^Send 0\.00100000 tBTC to Savings \(${DEST}\), network fee 0\.\d{8} tBTC$`));
  assert.equal(operation.details.saved_as, 'Savings');
});

test('names and addresses that are not plain are refused', async t => {
  const env = await start(t);
  const alex = await owner(env);
  assert.equal((await alex.post('/api/addresses/approval', { network: 'bitcoin', address: 'not-an-address', name: 'X' })).status, 400);
  assert.equal((await alex.post('/api/addresses/approval', { network: 'bitcoin', address: DEST, name: '<script>' })).status, 400);
  assert.equal((await alex.post('/api/addresses/approval', { network: 'bitcoin', address: DEST, name: 'x'.repeat(41) })).status, 400);
});

/* ------------------------------------------------------------------ alerts */

test('alerts go only to browser push services', async t => {
  const env = await start(t);
  const alex = await owner(env);
  for (const endpoint of ['https://evil.example/hook', 'http://fcm.googleapis.com/fcm/send/x', 'https://fcm.googleapis.com.evil.example/x']) {
    const refused = await alex.post('/api/push/subscribe', { ...subscription('x'), endpoint });
    assert.equal(refused.status, 400, `${endpoint} is refused`);
  }
  assert.equal(ok(await alex.post('/api/push/subscribe', subscription('alex-phone'))).alerts, 1);
});

test('when one signer asks for something, every other signer gets a signed, empty alert', async t => {
  const env = await start(t);
  const alex = await owner(env);
  const bea = await signedIn(env, 'sub-bea');
  await walletFor(env, bea);
  await joins(env, alex, bea, 'Bea');
  ok(await alex.post('/api/push/subscribe', subscription('alex-phone')));
  ok(await bea.post('/api/push/subscribe', subscription('bea-phone')));
  env.world.log.push.length = 0;

  // Any request will do; a shared vault cannot send until it is locked, so this one saves a name.
  ok(await alex.post('/api/addresses/approval', { network: 'bitcoin', address: DEST, name: 'Savings' }));
  const pushed = env.world.log.push;
  assert.deepEqual(pushed.map(p => p.url), [`${FCM}bea-phone`], 'Bea is told; Alex, who asked, is not');
  assert.ok(!pushed[0].body, 'the alert carries nothing');

  // The VAPID token verifies against the key the page is given.
  const { vapidPublicKey } = ok(await alex.get('/api/config'));
  const [, token, key] = pushed[0].headers.authorization.match(/^vapid t=([^,]+), k=(.+)$/);
  assert.equal(key, vapidPublicKey);
  const [h, p, s] = token.split('.');
  const raw = Buffer.from(vapidPublicKey, 'base64url');
  const publicKey = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: raw.subarray(1, 33).toString('base64url'), y: raw.subarray(33).toString('base64url') },
    format: 'jwk',
  });
  assert.ok(crypto.verify('sha256', Buffer.from(`${h}.${p}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url')));
  assert.equal(JSON.parse(Buffer.from(p, 'base64url')).aud, 'https://fcm.googleapis.com');
});

test('a freeze alerts the others too, and a subscription the push service has dropped is forgotten', async t => {
  const env = await start(t);
  const alex = await owner(env);
  const bea = await signedIn(env, 'sub-bea');
  await walletFor(env, bea);
  await joins(env, alex, bea, 'Bea');
  ok(await alex.post('/api/push/subscribe', subscription('gone-phone')));
  env.world.log.push.length = 0;

  ok(await bea.post('/api/vault/freeze', { vaultOwnerId: alex.id }));
  assert.deepEqual(env.world.log.push.map(p => p.url), [`${FCM}gone-phone`]);
  assert.equal(ok(await alex.get('/api/wallet')).alerts, 0, 'the push service said 410, so it was removed');
});
