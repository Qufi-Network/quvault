/*
 * The world these tests run in: a Veyns that signs real ES256 decisions, a Bitcoin API that
 * holds coins and takes broadcasts, and a client that keeps its cookies.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { createApp } from '../src/app.js';
import { actionDigest } from '../src/veyns.js';
import { serverKeys, seal, open as openSealed } from '../src/vault.js';
import { createKey, publicKeyOf, addressOf, planSpend, signPlan } from '../src/bitcoin.js';
import { DEFAULT_POLICY } from '../src/policy.js';
import { deriveAttestationKeys, signAuthorization, signRegistration } from '../src/authorization.js';
import { accountsFrom } from '../client/wallet.js';

export const ISSUER = 'https://issuer.test';
export const CHAIN = 'https://chain.test/api';
export const ORIGIN = 'https://quvault.test';
export const CLIENT_ID = 'quvault-test';
export const SECRET = 'backend-secret';
export const SEED = crypto.randomBytes(64).toString('base64');
export const DEST = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const quiet = { error() {}, warn() {}, log() {} };

/** Stands in for Veyns (real ES256 tokens) and for the Bitcoin API (coins, fees, broadcast). */
export function mockWorld(clock) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'ES256', use: 'sig' };
  const requests = new Map();
  const log = { created: [], acks: [], cancelled: [], broadcast: [] };
  const chain = { utxos: [], feeRate: 2, broadcastError: null, pending: 0 };
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
      if (rest.endsWith('/utxo')) return json(200, chain.utxos.map(u => ({ ...u, status: { confirmed: true, block_height: 100 } })));
      if (rest.endsWith('/txs')) return json(200, []);
      if (rest === '/v1/fees/recommended') return json(200, { halfHourFee: chain.feeRate, hourFee: chain.feeRate });
      if (rest.startsWith('/address/')) {
        const funded = chain.utxos.reduce((sum, u) => sum + u.value, 0);
        return json(200, { chain_stats: { funded_txo_sum: funded, spent_txo_sum: 0, tx_count: chain.utxos.length }, mempool_stats: { funded_txo_sum: chain.pending, spent_txo_sum: 0, tx_count: chain.pending ? 1 : 0 } });
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

export async function start(t, overrides = {}) {
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

  return { world, client, app, now: () => time, advance: seconds => { time += seconds; } };
}

export function ok(response) {
  assert.equal(response.status, 200, JSON.stringify(response.body));
  return response.body;
}

export async function signedIn(env, sub) {
  const c = env.client();
  const { nonce } = ok(await c.post('/api/login/start'));
  ok(await c.post('/api/login/finish', { token: env.world.token({ sub, nonce, veyns_intent: 'login' }) }));
  c.id = ok(await c.get('/api/wallet')).me.id;
  return c;
}

/** One person putting their palm to a pending request. */
export async function palmApprove(env, c, operationId, overrides) {
  const { approval } = ok(await c.post(`/api/operations/${operationId}/approval`, {}));
  ok(await c.post(`/api/approvals/${approval.id}/palm`, {}));
  env.world.approvePalm(env.world.log.created.at(-1).request_id, overrides);
  return ok(await c.get(`/api/approvals/${approval.id}`));
}

/**
 * Stands in for the owner's browser: after the palm scan it takes the unlock secret,
 * makes its own key, and registers only the address and public key.
 */
export async function walletFor(env, c) {
  const { operation } = ok(await c.post('/api/wallet/approval', { label: 'Owner' }));
  await palmApprove(env, c, operation.id);
  const unlocked = ok(await c.post(`/api/operations/${operation.id}/unlock`, {}));
  c.unlock = unlocked.unlock;
  c.salt = unlocked.salt;
  c.key = createKey();
  c.publicKey = publicKeyOf(c.key);
  c.address = addressOf(c.publicKey);
  c.attestation = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  ok(await c.post('/api/wallet/register', {
    operationId: operation.id, address: c.address, publicKey: c.publicKey.toString('hex'),
    attestationRegistration: registrationFor({ vaultId: c.address, keys: c.attestation, at: env.now() }),
  }));
  return ok(await c.get('/api/wallet')).wallet;
}

/**
 * The browser signing an approved plan, and signing the authorisation record with the key
 * only it holds. The server gets a transaction and a record, and no secret of either kind.
 */
export async function signAndSend(env, c, operationId, tweak = {}) {
  const unlocked = ok(await c.post(`/api/operations/${operationId}/unlock`, {}));
  const signed = signPlan({ privateKey: c.key, publicKey: c.publicKey, plan: unlocked.plan });
  const authorization = attestFor(env, c, unlocked, tweak);
  return ok(await c.post(`/api/operations/${operationId}/broadcast`, { hex: signed.hex, authorization }));
}

/** The record a browser would sign for an unlocked withdrawal, with anything overridden. */
export function attestFor(env, c, unlocked, tweak = {}) {
  const { keys = c.attestation, ...fields } = tweak;
  return signAuthorization({
    vaultId: unlocked.address,
    accountId: 'bitcoin',
    transactionHash: unlocked.transactionHash,
    statementDigest: unlocked.statementDigest,
    approvalMethod: 'veyns:palm',
    approvals: unlocked.approvals,
    approvedBy: unlocked.approvedBy,
    decisionIds: unlocked.decisionIds,
    approvedAt: env.now(),
    ...fields,
  }, keys);
}

/**
 * Sets an account's signers and thresholds, through the palm-approved change. The approvals
 * come from whoever signs for it today, which is the point of the rule.
 */
export async function setRules(env, owner, { network = 'bitcoin', add = [], remove = [], rules, approvers = [] }) {
  const { operation } = ok(await owner.post('/api/policy', { network, add, remove, rules }));
  const palms = [owner, ...approvers, ...add.map(a => a.client).filter(Boolean)];
  for (let i = 0; i < operation.required; i++) await palmApprove(env, palms[i], operation.id);
  return ok(await owner.get('/api/wallet'));
}

/** Adds an account on another network the way the wizard does, and derives its address. */
export async function addAccount(env, owner, { network, add = [], signers = [], rules, approvers = [] }) {
  const { operation } = ok(await owner.post('/api/accounts/approval', { network, add, signers, rules }));
  const palms = [owner, ...approvers];
  for (let i = 0; i < operation.required; i++) await palmApprove(env, palms[i], operation.id);
  const derived = ADDRESSES[network];
  ok(await owner.post('/api/accounts/register', { operationId: operation.id, ...derived }));
  return ok(await owner.get('/api/wallet'));
}

/** The addresses a browser really would derive, from the phrase every wallet tests with. */
export const ADDRESSES = Object.fromEntries(
  Object.entries(accountsFrom('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'))
    .map(([id, account]) => [id, { address: account.address, publicKey: account.publicKey }]),
);

/** A wallet exactly as the first version of QuVault made them: the key sealed on the server. */
export async function legacyWallet(env, owner, time = 1_700_000_000) {
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

/** The registration a browser signs: by the key itself at epoch 1, by the previous key after. */
export function registrationFor({ vaultId, keys, epoch = 1, previousKeys = null, at = 1_800_000_000 }) {
  return signRegistration({
    vaultId,
    publicKey: keys.publicKey,
    epoch,
    previousKeyId: previousKeys ? previousKeys.keyId : null,
    registeredAt: at,
  }, previousKeys ?? keys);
}

/** Stands in for a browser making its own key and reporting only the public parts. */
export function browserKey() {
  const key = createKey();
  const publicKey = publicKeyOf(key);
  const attestation = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const address = addressOf(publicKey);
  return {
    key,
    publicKey: publicKey.toString('hex'),
    address,
    attestation,
    attestationRegistration: registrationFor({ vaultId: address, keys: attestation }),
  };
}


/**
 * A deployment that has the legacy migration capability switched on.
 *
 * `legacySeed` is absent by default, and where it is absent nothing served by the app can open
 * a legacy wallet's private key. Only a test that is exercising the migration itself supplies
 * it, which is why this is a separate helper rather than a default in `start`: every call site
 * that needs the capability says so.
 */
export const startWithMigration = (t, overrides = {}) => start(t, { legacySeed: SEED, ...overrides });
