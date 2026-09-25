/*
 * Rate limiting: the window arithmetic, and the behaviour through a real HTTP server.
 *
 * The suite passing with limiting switched on proves only that ordinary use stays under the
 * line. These tests are the other half — they deliberately go over it, and check the things
 * that are easy to get wrong: that one caller's limit is not everybody's, that a new window
 * starts fresh, that a broken limiter lets traffic through rather than taking the site down,
 * and that the routes the page polls were left alone.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { RATE, bucketFor, isOverLimit, clientAddress, refusalMessage } from '../src/rate-limit.js';
import { EVENT } from '../src/events.js';
import { DEST, start, ok, signedIn, palmApprove, walletFor } from './harness.js';

/* ------------------------------------------------------------- the arithmetic */

test('a bucket names the policy, the caller and the window it belongs to', () => {
  const policy = { name: 'spend', limit: 3, seconds: 100, by: 'user' };

  const a = bucketFor({ policy, key: 'alex', now: 1_000_000_042 });
  assert.equal(a.bucket, 'spend:alex:1000000000', 'the window start is floored, and is in the key');
  assert.equal(a.expiresAt, 1_000_000_100);
  assert.equal(a.retryAfter, 58, 'the time left in this window');

  // Same window, same bucket — that is what makes the count accumulate.
  assert.equal(bucketFor({ policy, key: 'alex', now: 1_000_000_099 }).bucket, a.bucket);
  // Next second is the next window, and a different row.
  assert.notEqual(bucketFor({ policy, key: 'alex', now: 1_000_000_100 }).bucket, a.bucket);
  // A different caller is never the same bucket.
  assert.notEqual(bucketFor({ policy, key: 'sam', now: 1_000_000_042 }).bucket, a.bucket);
  // And a different policy on the same caller counts separately.
  assert.notEqual(
    bucketFor({ policy: { ...policy, name: 'palm' }, key: 'alex', now: 1_000_000_042 }).bucket,
    a.bucket,
  );

  // retryAfter is never zero: telling a caller to retry in 0 seconds invites a hot loop.
  assert.equal(bucketFor({ policy, key: 'alex', now: 1_000_000_099.9 }).retryAfter >= 1, true);
});

test('the limit is the number allowed, not the number before refusing', () => {
  const policy = { name: 'x', limit: 3, seconds: 60, by: 'user' };
  assert.equal(isOverLimit(3, policy), false, 'the third request is allowed');
  assert.equal(isOverLimit(4, policy), true, 'the fourth is not');
  assert.match(refusalMessage(1), /1 second\b/, 'singular reads correctly');
  assert.match(refusalMessage(42), /42 seconds/);
});

test('the client address comes from the proxy only when the proxy is trusted', () => {
  const req = {
    headers: { 'x-forwarded-for': '203.0.113.7, 70.41.3.18' },
    socket: { remoteAddress: '10.0.0.1' },
  };
  assert.equal(clientAddress(req, { trustProxy: true }), '203.0.113.7', 'the first hop');
  assert.equal(clientAddress(req, { trustProxy: false }), '10.0.0.1', 'the socket, when the header cannot be believed');
  assert.equal(clientAddress({ headers: {}, socket: {} }), 'unknown', 'and something stable when neither exists');
});

/* --------------------------------------------------- through a real HTTP server */

test('an unauthenticated caller is refused after the login limit, with retry-after', async t => {
  const env = await start(t);
  const c = env.client();

  let refused = null;
  for (let i = 0; i < RATE.login.limit + 1; i++) {
    const response = await c.post('/api/login/start');
    if (response.status === 429) { refused = response; break; }
    assert.equal(response.status, 200, `request ${i + 1} should be allowed`);
  }
  assert.ok(refused, `the caller was refused within ${RATE.login.limit + 1} attempts`);
  assert.match(refused.body.error, /Too many requests/);
  assert.match(refused.body.error, /Try again in \d+ seconds?/);

  // And the machine-readable half: a client that respects retry-after backs off without
  // having to parse an English sentence.
  const retryAfter = Number(refused.headers['retry-after']);
  assert.ok(Number.isInteger(retryAfter) && retryAfter > 0, 'retry-after is on the response');
  assert.ok(retryAfter <= RATE.login.seconds, 'and never longer than the window');
});

test('one caller going over does not refuse everybody else', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const sam = await signedIn(env, 'sub-sam');
  await walletFor(env, alex);
  await walletFor(env, sam);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];

  // Alex spends their whole allowance on the spend-planning route.
  let alexRefused = false;
  for (let i = 0; i < RATE.spend.limit + 1; i++) {
    const response = await alex.post('/api/withdrawals', { to: DEST, amount: 10_000 });
    if (response.status === 429) { alexRefused = true; break; }
  }
  assert.ok(alexRefused, 'alex is over the line');

  // Sam has touched nothing, and is unaffected. This is the property that makes a user-keyed
  // limit usable at all: one noisy account cannot deny the service to anyone else.
  const forSam = await sam.post('/api/withdrawals', { to: DEST, amount: 10_000 });
  assert.notEqual(forSam.status, 429, 'sam is not refused for what alex did');
});

test('a new window starts the count again', async t => {
  const env = await start(t);
  const c = env.client();

  for (let i = 0; i < RATE.login.limit + 1; i++) await c.post('/api/login/start');
  assert.equal((await c.post('/api/login/start')).status, 429, 'over the line');

  // Past the end of the window, the bucket is a different row and the count is gone.
  env.advance(RATE.login.seconds + 1);
  assert.equal((await c.post('/api/login/start')).status, 200, 'the next window is fresh');
});

test('the routes the page polls are deliberately not limited', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);

  /*
   * The page polls /api/wallet while a request is open, and /api/approvals/:id while a palm is
   * being scanned. Limiting either of those would break the waiting screen — the thing the
   * limiter is nominally protecting — so they carry no policy, and this test says so out loud
   * rather than leaving it to be "fixed" later by someone tidying up.
   */
  for (let i = 0; i < RATE.spend.limit + 20; i++) {
    const response = await alex.get('/api/wallet');
    assert.equal(response.status, 200, `poll ${i + 1} is still served`);
  }
});

test('a broken limiter lets traffic through instead of taking the site down', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 900_000 }];

  // The limiter's own table goes away underneath it.
  const db = await env.app.db();
  await db.query('DROP TABLE rate_limits');

  /*
   * Fails open, on purpose. Rate limiting protects availability; it decides how often, never
   * whether. A limiter that refused everything when its own storage broke would be a worse
   * outage than the one it exists to prevent — and it is not a gate anyone was being held at,
   * so opening it lets nobody past an authorisation check.
   */
  const response = await alex.post('/api/withdrawals', { to: DEST, amount: 10_000 });
  assert.notEqual(response.status, 429, 'not refused');
  assert.notEqual(response.status, 500, 'and not an error either — the request simply proceeds');
});

test('a refusal is recorded without the caller address or anything secret', async t => {
  const seen = [];
  const env = await start(t, { securitySink: record => seen.push(record) });
  const c = env.client();

  for (let i = 0; i < RATE.login.limit + 2; i++) await c.post('/api/login/start');

  const limited = seen.filter(e => e.event === EVENT.RATE_LIMITED);
  assert.ok(limited.length >= 1, 'the refusal was recorded');
  assert.equal(limited[0].kind, RATE.login.name, 'and says which policy tripped');
  assert.match(limited[0].reason, /over \d+ requests in \d+s/);

  for (const record of limited) {
    const line = JSON.stringify(record);
    // An IP is personal data. The policy name and, where there is one, the user id are enough
    // to act on a refusal, so the address is deliberately not carried.
    assert.ok(!/127\.0\.0\.1|::1|\bx-forwarded/.test(line), 'no caller address in the event');
    assert.ok(!/"(mnemonic|privateKey|seed|secretKey|unlock)"/.test(line), 'and no secret field');
  }
});
