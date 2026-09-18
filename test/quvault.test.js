import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { createApp } from '../src/app.js';
import { actionDigest } from '../src/veyns.js';
import { serverKeys, seal, open as openSealed } from '../src/vault.js';
import { createKey, publicKeyOf, addressOf, planSpend, signPlan } from '../src/bitcoin.js';

const ISSUER = 'https://issuer.test';
const CHAIN = 'https://chain.test/api';
const ORIGIN = 'https://quvault.test';
const CLIENT_ID = 'quvault-test';
const SECRET = 'backend-secret';
const SEED = crypto.randomBytes(64).toString('base64');
const DEST = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const quiet = { error() {}, warn() {}, log() {} };

/** Stands in for Veyns (real ES256 tokens) and for the Bitcoin API (coins, fees, broadcast). */
function mockWorld(clock) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'ES256', use: 'sig' };
  const requests = new Map();
  const log = { created: [], acks: [], cancelled: [], broadcast: [] };
  const chain = { utxos: [], feeRate: 2, broadcastError: null };
  const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  function token(claims) {
    const t = clock();
    const input = `${b64({ alg: 'ES256', kid: 'k1', typ: 'JWT' })}.${b64({
      iss: ISSUER, aud: CLIENT_ID, iat: t, exp: t + 300, auth_time: t,
      veyns_presence: true, amr: ['veyns:browser'], ...claims,
    })}`;
    const signature = crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
    return `${input}.${signature.toString('base64url')}`;
  }

  async function fetchImpl(url, init = {}) {
    const { pathname } = new URL(url);
    const method = init.method || 'GET';
    const body = init.body;

    if (String(url).startsWith(CHAIN)) {
      const rest = String(url).slice(CHAIN.length);
      if (rest.endsWith('/utxo')) {
        return json(200, chain.utxos.map(u => ({ ...u, status: { confirmed: true, block_height: 100 } })));
      }
      if (rest.endsWith('/txs')) return json(200, []);
      if (rest === '/v1/fees/recommended') return json(200, { halfHourFee: chain.feeRate, hourFee: chain.feeRate });
      if (rest.startsWith('/address/')) {
        const funded = chain.utxos.reduce((sum, u) => sum + u.value, 0);
        return json(200, { chain_stats: { funded_txo_sum: funded, spent_txo_sum: 0, tx_count: chain.utxos.length }, mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 } });
      }
      if (rest === '/tx' && method === 'POST') {
        if (chain.broadcastError) return new Response(chain.broadcastError, { status: 400 });
        const tx = btc.Transaction.fromRaw(hex.decode(body), { allowUnknownOutputs: true });
        log.broadcast.push({ hex: body, txid: tx.id, tx });
        return new Response(tx.id, { status: 200 });
      }
      return json(404, { error: 'not_found' });
    }

    if (pathname === '/jwks.json') return json(200, { keys: [jwk] });
    if (init.headers?.authorization !== 'Basic ' + Buffer.from(`${CLIENT_ID}:${SECRET}`).toString('base64')) {
      return json(401, { error: 'invalid_client' });
    }
    const parsed = body ? JSON.parse(body) : undefined;
    if (method === 'POST' && pathname === '/v1/approvals') {
      const id = crypto.randomBytes(18).toString('base64url');
      const record = {
        request_id: id, subject: parsed.subject, status: 'pending', required_method: 'palm',
        challenge: crypto.randomBytes(18).toString('base64url'),
        action: { ...parsed.action, digest: actionDigest(parsed.action.statement, parsed.action.details) },
        approval_url: `${ISSUER}/approve#${id}.${'v'.repeat(32)}`,
      };
      requests.set(id, record);
      log.created.push(record);
      return json(201, record);
    }
    let m;
    if (method === 'GET' && (m = pathname.match(/^\/v1\/approvals\/([^/]+)$/))) return json(200, requests.get(m[1]));
    if ((m = pathname.match(/^\/v1\/approvals\/([^/]+)\/cancel$/))) {
      log.cancelled.push(m[1]);
      return json(200, requests.get(m[1]) ?? {});
    }
    if ((m = pathname.match(/^\/v1\/approvals\/([^/]+)\/ack$/))) {
      log.acks.push({ request_id: m[1], ...parsed });
      return json(200, { acknowledged: true });
    }
    return json(404, { error: 'not_found' });
  }

  function approvePalm(requestId, overrides = {}) {
    const r = requests.get(requestId);
    r.status = 'approved';
    r.decision_id = crypto.randomBytes(12).toString('base64url');
    r.decision = token({
      sub: r.subject, veyns_intent: 'action', amr: ['veyns:palm'], request_id: r.request_id,
      request_nonce: r.challenge, veyns_action: { statement: r.action.statement, digest: r.action.digest },
      ...overrides,
    });
    return r;
  }

  return { fetchImpl, token, approvePalm, log, chain, requests };
}

async function start(t, overrides = {}) {
  let time = 1_800_000_000;
  const clock = () => time;
  const world = mockWorld(clock);
  const app = createApp({
    publicOrigin: ORIGIN, issuer: ISSUER, chainApi: CHAIN, clientId: CLIENT_ID, backendSecret: SECRET,
    walletSeed: SEED, now: clock, fetchImpl: world.fetchImpl, log: quiet, ...overrides,
  });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  t.after(() => app.close());
  const { port } = app.server.address();

  function client() {
    const jar = new Map();
    const call = (method, path, body) => new Promise((resolve, reject) => {
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const req = http.request({
        host: '127.0.0.1', port, method, path,
        headers: {
          origin: ORIGIN,
          cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
          ...(payload ? { 'content-type': 'application/json' } : {}),
        },
      }, res => {
        for (const cookie of res.headers['set-cookie'] || []) {
          const pair = cookie.split(';')[0];
          const i = pair.indexOf('=');
          if (/Max-Age=0\b/.test(cookie)) jar.delete(pair.slice(0, i));
          else jar.set(pair.slice(0, i), pair.slice(i + 1));
        }
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null }));
      });
      req.on('error', reject);
      req.end(payload);
    });
    return { get: path => call('GET', path), post: (path, body = {}) => call('POST', path, body) };
  }

  return { world, client, advance: seconds => { time += seconds; } };
}

function ok(response) {
  assert.equal(response.status, 200, JSON.stringify(response.body));
  return response.body;
}

async function signedIn(env, sub = 'sub-alex') {
  const c = env.client();
  const { nonce } = ok(await c.post('/api/login/start'));
  ok(await c.post('/api/login/finish', { token: env.world.token({ sub, nonce, veyns_intent: 'login' }) }));
  return c;
}

/** Runs one approval all the way through a palm scan. */
async function palmApprove(env, c, approvalId, overrides) {
  ok(await c.post(`/api/approvals/${approvalId}/palm`, {}));
  env.world.approvePalm(env.world.log.created.at(-1).request_id, overrides);
  return ok(await c.get(`/api/approvals/${approvalId}`)).approval;
}

async function walletFor(env, c) {
  const { approval } = ok(await c.post('/api/wallet/approval', {}));
  await palmApprove(env, c, approval.id);
  return ok(await c.get('/api/wallet')).wallet;
}

test('the vault seals a key so only this server seed can open it', () => {
  const keys = serverKeys(SEED);
  const secret = crypto.randomBytes(32);
  const sealed = seal(secret, keys);
  assert.deepEqual(openSealed(sealed, keys), secret);
  assert.notEqual(seal(secret, keys), seal(secret, keys), 'every sealing is different');
  assert.throws(() => openSealed(sealed, serverKeys(crypto.randomBytes(64).toString('base64'))));
  const tampered = Buffer.from(sealed, 'base64');
  tampered[tampered.length - 5] ^= 1;
  assert.throws(() => openSealed(tampered.toString('base64'), keys));
});

test('creating the wallet needs a palm scan, and binds the key to that account', async t => {
  const env = await start(t);
  const c = await signedIn(env);
  assert.equal(ok(await c.get('/api/wallet')).wallet, null);

  const { approval } = ok(await c.post('/api/wallet/approval', {}));
  assert.equal(approval.statement, 'Create a testnet4 Bitcoin wallet that only my palm can spend from');
  assert.equal(ok(await c.get('/api/wallet')).wallet, null, 'no wallet until the palm scan');

  const settled = await palmApprove(env, c, approval.id);
  assert.equal(settled.status, 'approved');
  const wallet = ok(await c.get('/api/wallet')).wallet;
  assert.match(wallet.address, /^tb1q/);
  assert.equal(env.world.log.acks.at(-1).operation_id, approval.id);

  // A second wallet is refused, and another account gets its own address.
  assert.equal((await c.post('/api/wallet/approval', {})).status, 409);
  const other = await signedIn(env, 'sub-omar');
  const otherWallet = await walletFor(env, other);
  assert.notEqual(otherWallet.address, wallet.address);
});

test('a decision that is not a palm scan never creates a wallet', async t => {
  const env = await start(t);
  const c = await signedIn(env);
  const { approval } = ok(await c.post('/api/wallet/approval', {}));
  const settled = await palmApprove(env, c, approval.id, { amr: ['veyns:browser'] });
  assert.equal(settled.status, 'failed');
  assert.match(settled.error, /not a palm scan/);
  assert.equal(ok(await c.get('/api/wallet')).wallet, null);
});

test('a withdrawal is planned, signed only after the palm scan, and broadcast exactly once', async t => {
  const env = await start(t);
  const c = await signedIn(env);
  const wallet = await walletFor(env, c);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 200_000 }];

  const view = ok(await c.get('/api/wallet'));
  assert.equal(view.balance.confirmed, 200_000);
  assert.equal(view.coins, 1);
  assert.ok(view.qr.startsWith('<svg'));

  const { approval, plan } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  assert.equal(approval.statement, `Send 0.00120000 tBTC to ${DEST}`);
  assert.equal(approval.details.amount_sats, 120_000);
  assert.equal(plan.inputs.length, 1);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing is broadcast before the palm scan');

  const settled = await palmApprove(env, c, approval.id);
  assert.equal(settled.status, 'approved');
  assert.ok(settled.txid);
  assert.equal(env.world.log.broadcast.length, 1);

  // What was broadcast is exactly what was approved.
  const sent = env.world.log.broadcast[0].tx;
  assert.equal(sent.id, settled.txid);
  const outputs = [...Array(sent.outputsLength).keys()].map(i => ({
    address: btc.Address(btc.TEST_NETWORK).encode(btc.OutScript.decode(sent.getOutput(i).script)),
    sats: Number(sent.getOutput(i).amount),
  }));
  assert.deepEqual(outputs, plan.outputs);
  assert.equal(outputs.find(o => o.address === DEST).sats, 120_000);
  assert.equal(outputs.find(o => o.address === wallet.address).sats, 200_000 - 120_000 - plan.feeSats);

  // Polling again must not send it a second time.
  ok(await c.get(`/api/approvals/${approval.id}`));
  assert.equal(env.world.log.broadcast.length, 1);
  assert.deepEqual(env.world.log.acks.map(a => a.operation_id).filter(id => id === approval.id).length, 1);
});

test('a withdrawal approved for a different action is refused', async t => {
  const env = await start(t);
  const c = await signedIn(env);
  await walletFor(env, c);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 200_000 }];
  const { approval } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 50_000 }));

  // Veyns answers with a decision whose action digest is for something else.
  ok(await c.post(`/api/approvals/${approval.id}/palm`, {}));
  const request = env.world.requests.get(env.world.log.created.at(-1).request_id);
  request.action.digest = actionDigest('Send everything to someone else', {});
  env.world.approvePalm(request.request_id);

  const settled = ok(await c.get(`/api/approvals/${approval.id}`)).approval;
  assert.equal(settled.status, 'failed');
  assert.match(settled.error, /different action/);
  assert.equal(env.world.log.broadcast.length, 0);
});

test('bad withdrawals are refused before any approval is created', async t => {
  const env = await start(t);
  const c = await signedIn(env);
  await walletFor(env, c);
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 1, value: 60_000 }];
  const before = env.world.log.created.length;

  assert.match((await c.post('/api/withdrawals', { to: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', amount: 1000 })).body.error, /not a valid testnet4 address/);
  assert.match((await c.post('/api/withdrawals', { to: DEST, amount: 500_000 })).body.error, /Not enough coins/);
  assert.match((await c.post('/api/withdrawals', { to: DEST, amount: 100 })).body.error, /at least/);
  assert.match((await c.post('/api/withdrawals', { to: DEST, amount: 0 })).body.error, /amount in satoshis/);
  assert.equal(env.world.log.created.length, before, 'no palm request was made for any of them');

  // Sweeping everything pays the fee out of the amount.
  const { plan } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 'max' }));
  assert.equal(plan.sentSats + plan.feeSats, 60_000);
  assert.equal(plan.changeSats, 0);
});

test('a failed broadcast is reported and never marked as sent', async t => {
  const env = await start(t);
  const c = await signedIn(env);
  await walletFor(env, c);
  env.world.chain.utxos = [{ txid: 'd'.repeat(64), vout: 0, value: 150_000 }];
  env.world.chain.broadcastError = 'sendrawtransaction RPC error: txn-mempool-conflict';

  const { approval } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 40_000 }));
  const settled = await palmApprove(env, c, approval.id);
  assert.equal(settled.status, 'failed');
  assert.match(settled.error, /txn-mempool-conflict/);
  assert.equal(settled.txid, null);
  assert.equal(ok(await c.get('/api/wallet')).withdrawals[0].status, 'failed');
});

test('one person cannot touch another person\'s approval or wallet', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const omar = await signedIn(env, 'sub-omar');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'e'.repeat(64), vout: 0, value: 100_000 }];
  const { approval } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 30_000 }));

  assert.equal((await omar.get(`/api/approvals/${approval.id}`)).status, 404);
  assert.equal((await omar.post(`/api/approvals/${approval.id}/palm`, {})).status, 404);
  assert.equal((await omar.post(`/api/approvals/${approval.id}/cancel`, {})).status, 404);
  assert.equal((await omar.post('/api/withdrawals', { to: DEST, amount: 1000 })).status, 409, 'omar has no wallet');
  assert.equal(env.world.log.broadcast.length, 0);
});

test('the signed transaction always matches the stored plan', () => {
  const key = createKey();
  const publicKey = publicKeyOf(key);
  const utxos = [{ txid: 'f'.repeat(64), vout: 2, value: 90_000 }];
  const plan = planSpend({ publicKey, utxos, toAddress: DEST, amountSats: 30_000, feeRate: 3 });
  const signed = signPlan({ privateKey: key, publicKey, plan });
  const tx = btc.Transaction.fromRaw(hex.decode(signed.hex));
  assert.equal(tx.id, signed.txid);
  assert.equal(Number(tx.getOutput(0).amount), 30_000);
  assert.ok(Math.abs(plan.feeSats / signed.vsize - 3) < 0.25, 'fee rate is close to the one asked for');
  assert.throws(() => signPlan({ privateKey: key, publicKey, plan: { ...plan, feeSats: plan.feeSats + 500 } }),
    /does not match the approved plan/);
  assert.equal(addressOf(publicKey), plan.outputs.find(o => o.address !== DEST).address, 'change comes home');
});
