/*
 * Vaults made before the key moved into the browser. They sign on the server, have no
 * recovery phrase, and can be moved in with a palm quorum — taking their coins with them.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { createApp } from '../src/app.js';
import { actionDigest } from '../src/veyns.js';
import { serverKeys, seal } from '../src/vault.js';
import { createKey, publicKeyOf, addressOf } from '../src/bitcoin.js';
import { DEFAULT_POLICY } from '../src/policy.js';

const ISSUER = 'https://issuer.test';
const CHAIN = 'https://chain.test/api';
const ORIGIN = 'https://quvault.test';
const CLIENT_ID = 'quvault-test';
const SECRET = 'backend-secret';
const SEED = crypto.randomBytes(64).toString('base64');
const quiet = { error() {}, warn() {}, log() {} };

function mockWorld(clock) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'ES256', use: 'sig' };
  const requests = new Map();
  const log = { created: [], broadcast: [] };
  const chain = { utxos: [], feeRate: 2, pending: 0, broadcastError: null };
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
    if (String(url).startsWith(CHAIN)) {
      const rest = String(url).slice(CHAIN.length);
      if (rest.endsWith('/utxo')) return json(200, chain.utxos.map(u => ({ ...u, status: { confirmed: true, block_height: 100 } })));
      if (rest.endsWith('/txs')) return json(200, []);
      if (rest === '/v1/fees/recommended') return json(200, { halfHourFee: chain.feeRate, hourFee: chain.feeRate });
      if (rest.startsWith('/address/')) {
        const funded = chain.utxos.reduce((sum, u) => sum + u.value, 0);
        return json(200, {
          chain_stats: { funded_txo_sum: funded, spent_txo_sum: 0, tx_count: chain.utxos.length },
          mempool_stats: { funded_txo_sum: chain.pending, spent_txo_sum: 0, tx_count: chain.pending ? 1 : 0 },
        });
      }
      if (rest === '/tx' && method === 'POST') {
        if (chain.broadcastError) return new Response(chain.broadcastError, { status: 400 });
        const tx = btc.Transaction.fromRaw(hex.decode(init.body), { allowUnknownOutputs: true });
        log.broadcast.push({ txid: tx.id, tx });
        return new Response(tx.id, { status: 200 });
      }
      return json(404, { error: 'not_found' });
    }
    if (pathname === '/jwks.json') return json(200, { keys: [jwk] });
    const parsed = init.body ? JSON.parse(init.body) : undefined;
    if (method === 'POST' && pathname === '/v1/approvals') {
      const id = crypto.randomBytes(18).toString('base64url');
      const record = {
        request_id: id, subject: parsed.subject, status: 'pending', required_method: 'palm',
        challenge: crypto.randomBytes(18).toString('base64url'),
        action: { ...parsed.action, digest: actionDigest(parsed.action.statement, parsed.action.details) },
        approval_url: `${ISSUER}/approve#${id}`,
      };
      requests.set(id, record);
      log.created.push(record);
      return json(201, record);
    }
    let m;
    if (method === 'GET' && (m = pathname.match(/^\/v1\/approvals\/([^/]+)$/))) return json(200, requests.get(m[1]));
    if (pathname.match(/^\/v1\/approvals\/([^/]+)\/(ack|cancel)$/)) return json(200, { acknowledged: true });
    return json(404, { error: 'not_found' });
  }

  function approvePalm(requestId) {
    const r = requests.get(requestId);
    r.status = 'approved';
    r.decision_id = crypto.randomBytes(12).toString('base64url');
    r.decision = token({
      sub: r.subject, veyns_intent: 'action', amr: ['veyns:palm'], request_id: r.request_id,
      request_nonce: r.challenge, veyns_action: { statement: r.action.statement, digest: r.action.digest },
    });
    return r;
  }

  return { fetchImpl, token, approvePalm, log, chain };
}

async function start(t) {
  let time = 1_800_000_000;
  const clock = () => time;
  const world = mockWorld(clock);
  const app = createApp({
    publicOrigin: ORIGIN, issuer: ISSUER, chainApi: CHAIN, clientId: CLIENT_ID, backendSecret: SECRET,
    walletSeed: SEED, now: clock, fetchImpl: world.fetchImpl, log: quiet,
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
          jar.set(pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1));
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
  return { world, client, app };
}

const ok = response => {
  assert.equal(response.status, 200, JSON.stringify(response.body));
  return response.body;
};

async function signedIn(env, sub) {
  const c = env.client();
  const { nonce } = ok(await c.post('/api/login/start'));
  ok(await c.post('/api/login/finish', { token: env.world.token({ sub, nonce, veyns_intent: 'login' }) }));
  c.id = ok(await c.get('/api/wallet')).me.id;
  return c;
}

async function palmApprove(env, c, operationId) {
  const { approval } = ok(await c.post(`/api/operations/${operationId}/approval`, {}));
  ok(await c.post(`/api/approvals/${approval.id}/palm`, {}));
  env.world.approvePalm(env.world.log.created.at(-1).request_id);
  return ok(await c.get(`/api/approvals/${approval.id}`));
}

/** A wallet exactly as the first version of QuVault made them: the key sealed on the server. */
async function legacyWallet(env, owner, time = 1_700_000_000) {
  const key = createKey();
  const publicKey = publicKeyOf(key);
  const address = addressOf(publicKey);
  const db = await env.app.db();
  await db.query(
    `INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, policy, created_at)
     VALUES ($1, 'testnet4', $2, $3, $4, $5, 'legacy-decision', $6, $7)`,
    [owner.id, address, publicKey.toString('hex'), seal(key, serverKeys(SEED)), `sub-${owner.id}`, JSON.stringify(DEFAULT_POLICY), time],
  );
  await db.query('INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at) VALUES ($1, $1, $2, true, $3)',
    [owner.id, 'Owner', time]);
  key.fill(0);
  return { address, publicKey };
}

/** Stands in for the browser: it makes its own key and reports only the public parts. */
function browserKey() {
  const key = createKey();
  const publicKey = publicKeyOf(key);
  return { key, publicKey: publicKey.toString('hex'), address: addressOf(publicKey) };
}

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
  const env = await start(t);
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
  const moved = ok(await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: fresh.publicKey }));
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
  const env = await start(t);
  const alex = await signedIn(env, 'sub-pending');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 120_000 }];
  env.world.chain.pending = 50_000;

  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  await palmApprove(env, alex, operation.id);
  const fresh = browserKey();
  const refused = await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: fresh.publicKey });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /first confirmation/);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing was spent');
  assert.equal(ok(await alex.get('/api/wallet')).wallet.custody, 'server', 'the old key is still there');

  // Once it confirms, the same approved request goes through.
  env.world.chain.pending = 0;
  env.world.chain.utxos.push({ txid: 'c'.repeat(64), vout: 1, value: 50_000 });
  const moved = ok(await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: fresh.publicKey }));
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
  assert.equal((await alex.post('/api/wallet/upgrade', { operationId: operation.id, ...fresh })).status, 409);
  // Nobody else can drive it.
  assert.equal((await omar.post('/api/wallet/upgrade', { operationId: operation.id, ...fresh })).status, 404);

  await palmApprove(env, alex, operation.id);
  const mismatched = await alex.post('/api/wallet/upgrade', { operationId: operation.id, address: fresh.address, publicKey: browserKey().publicKey });
  assert.equal(mismatched.status, 400);
  assert.match(mismatched.body.error, /does not match/);
  assert.equal(ok(await alex.get('/api/wallet')).wallet.custody, 'server');
  assert.equal(env.world.log.broadcast.length, 0);
});
