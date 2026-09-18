import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import QRCode from 'qrcode';
import { openDb } from './db.js';
import { createVeyns, actionDigest, isFresh, randomId, HttpError } from './veyns.js';
import { serverKeys, seal, open as openSealed } from './vault.js';
import { createChain, ChainError } from './chain.js';
import { createKey, publicKeyOf, addressOf, planSpend, signPlan, isValidAddress, toBtc, WalletError } from './bitcoin.js';

const SESSION_COOKIE = 'palmsafe_sid';
const LOGIN_COOKIE = 'palmsafe_login';
const SESSION_SECONDS = 7 * 24 * 3600;
const LOGIN_SECONDS = 300;
const PALM_REQUEST_SECONDS = 300;

const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
};

const SQL = {
  userBySub: 'SELECT * FROM users WHERE sub = $1',
  insertUser: 'INSERT INTO users (id, sub, created_at) VALUES ($1, $2, $3) ON CONFLICT (sub) DO NOTHING',

  insertSession: 'INSERT INTO sessions (id_hash, user_id, expires_at) VALUES ($1, $2, $3)',
  sessionUser: 'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = $1 AND s.expires_at > $2',
  deleteSession: 'DELETE FROM sessions WHERE id_hash = $1',
  purgeSessions: 'DELETE FROM sessions WHERE expires_at <= $1',
  insertLogin: 'INSERT INTO login_nonces (id, nonce, expires_at) VALUES ($1, $2, $3)',
  takeLogin: 'DELETE FROM login_nonces WHERE id = $1 RETURNING nonce, expires_at',
  purgeLogins: 'DELETE FROM login_nonces WHERE expires_at <= $1',

  walletOf: 'SELECT * FROM wallets WHERE user_id = $1',
  insertWallet: `INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (user_id) DO NOTHING`,

  approvalById: 'SELECT * FROM approvals WHERE id = $1',
  ownApproval: 'SELECT * FROM approvals WHERE id = $1 AND user_id = $2',
  openApprovalOf: `SELECT * FROM approvals WHERE user_id = $1 AND kind = $2 AND status = 'open' ORDER BY created_at DESC LIMIT 1`,
  insertApproval: `INSERT INTO approvals (id, user_id, kind, statement, details, digest, plan, status, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, 'open', $8)`,
  cancelOpenApprovals: `UPDATE approvals SET status = 'cancelled', closed_at = $1
                        WHERE user_id = $2 AND kind = $3 AND status = 'open' RETURNING id, request_id`,
  closeApproval: `UPDATE approvals SET status = $1, error = $2, closed_at = $3 WHERE id = $4 AND status = 'open'`,
  claimApproval: `UPDATE approvals SET status = 'approved', proof_id = $1, closed_at = $2 WHERE id = $3 AND status = 'open'`,
  setPalmRequest: `UPDATE approvals SET request_id = $1, challenge = $2, approval_url = $3 WHERE id = $4 AND status = 'open'`,
  setDecision: 'UPDATE approvals SET decision_id = $1 WHERE id = $2',
  markAcked: 'UPDATE approvals SET acked = true WHERE id = $1',
  setTxid: 'UPDATE approvals SET txid = $1 WHERE id = $2',
  setFailure: `UPDATE approvals SET status = 'failed', error = $1 WHERE id = $2`,
  recentWithdrawals: `SELECT id, statement, status, txid, error, plan, created_at FROM approvals
                      WHERE user_id = $1 AND kind = 'withdraw' AND status IN ('approved', 'failed')
                      ORDER BY created_at DESC LIMIT 10`,
};

const sha256 = value => crypto.createHash('sha256').update(value).digest('base64url');

function parseCookies(header = '') {
  const cookies = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) cookies[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return cookies;
}

const asObject = value => (value && typeof value === 'object' && !Array.isArray(value) ? value : {});

async function readJson(req) {
  if ('body' in req) { // Vercel's Node runtime may already have parsed the body.
    let body;
    try {
      body = req.body;
    } catch {
      throw new HttpError(400, 'Invalid JSON.');
    }
    if (body !== undefined) return asObject(body);
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 32_768) throw new HttpError(413, 'Request too large.');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return asObject(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  } catch {
    throw new HttpError(400, 'Invalid JSON.');
  }
}

export function createApp(options) {
  const {
    publicOrigin,
    issuer,
    databaseUrl = '',
    dataDir = null,
    publicDir = null,
    backendSecret = '',
    walletSeed = '',
    network = 'testnet4',
    chainApi = 'https://mempool.space/testnet4/api',
    requirePalmSignin = false,
    now = () => Math.floor(Date.now() / 1000),
    fetchImpl = globalThis.fetch,
    log = console,
  } = options;

  const clientId = options.clientId || '';
  let dbPromise = null;
  const database = () => {
    if (!databaseUrl && options.requireDatabaseUrl) {
      return Promise.reject(new HttpError(503, 'No database yet: add Postgres to this project, then redeploy.'));
    }
    dbPromise ??= openDb({ url: databaseUrl, dir: dataDir && path.join(dataDir, 'pgdata') })
      .catch(error => {
        dbPromise = null;
        log.error(error);
        throw new HttpError(503, 'The database is not reachable right now.');
      });
    return dbPromise;
  };

  const veyns = createVeyns({ issuer, getClientId: () => clientId, backendSecret, now, fetchImpl });
  const chain = createChain({ apiUrl: chainApi, fetchImpl });

  let vaultKeys = null;
  const vault = () => {
    if (!vaultKeys) {
      try {
        vaultKeys = serverKeys(walletSeed);
      } catch (error) {
        throw new HttpError(503, error.message);
      }
    }
    return vaultKeys;
  };

  const secureCookies = publicOrigin.startsWith('https:');
  const publicHost = new URL(publicOrigin).host;
  const csp = [
    "default-src 'self'",
    `script-src 'self' ${issuer}`,
    `connect-src 'self' ${issuer}`,
    `img-src 'self' data: ${issuer}`,
    "style-src 'self' https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com',
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
  ].join('; ');

  /* ------------------------------------------------------------- queries */

  async function query(name, ...params) {
    return (await database()).query(SQL[name], params);
  }
  const one = async (name, ...params) => (await query(name, ...params)).rows[0];
  const all = async (name, ...params) => (await query(name, ...params)).rows;
  async function transaction(fn) {
    return (await database()).transaction(raw => fn((name, ...params) => raw(SQL[name], params)));
  }

  /* --------------------------------------------------------------- views */

  const approvalView = (a, remoteStatus = null) => ({
    id: a.id,
    kind: a.kind,
    statement: a.statement,
    details: JSON.parse(a.details),
    status: a.status,
    error: a.error,
    txid: a.txid,
    remoteStatus,
    approvalUrl: a.status === 'open' ? a.approval_url : null,
  });

  const walletView = w => ({
    address: w.address,
    network: w.network,
    createdAt: w.created_at,
    explorer: chain.explorerAddress(w.address),
    protection: 'ML-KEM-768 + X25519 + AES-256-GCM',
  });

  /* ------------------------------------------------------------- helpers */

  const requireConfigured = () => {
    if (!clientId) throw new HttpError(409, 'Set VEYNS_CLIENT_ID first.');
  };

  const requirePalmReady = () => {
    if (!veyns.palmEnabled()) throw new HttpError(503, 'Palm approvals are not set up: add VEYNS_BACKEND_SECRET.');
  };

  async function requireUser(cookies) {
    const sid = cookies[SESSION_COOKIE];
    const user = sid && await one('sessionUser', sha256(sid), now());
    if (!user) throw new HttpError(401, 'Please sign in.');
    return user;
  }

  function cancelRemote(rows) {
    for (const row of rows) {
      if (!row.request_id) continue;
      veyns.backend(`/v1/approvals/${encodeURIComponent(row.request_id)}/cancel`, {})
        .catch(error => log.warn(`Could not cancel Veyns request: ${error.message}`));
    }
  }

  const approvalSubject = sub => (sub.startsWith('pairwise:') ? sub : `pairwise:${clientId}:${sub}`);
  const failApproval = (id, message) => query('closeApproval', 'failed', message, now(), id);

  /** Builds the exact action a palm scan will sign, replacing any earlier open one of the same kind. */
  async function newApproval(user, kind, statement, details, plan = null) {
    const id = randomId(16);
    const time = now();
    const replaced = await transaction(async q => {
      const closed = (await q('cancelOpenApprovals', time, user.id, kind)).rows;
      await q('insertApproval', id, user.id, kind, statement, JSON.stringify(details),
        actionDigest(statement, details), plan && JSON.stringify(plan), time);
      return closed;
    });
    cancelRemote(replaced);
    return one('approvalById', id);
  }

  /* -------------------------------------------------- the two palm actions */

  /** Creates the wallet key, sealed to this server, and binds it to the palm-verified account. */
  async function createWallet(a, user, decisionId) {
    if (await one('walletOf', user.id)) throw new HttpError(409, 'This account already has a wallet.');
    const keys = vault();
    const privateKey = createKey();
    const publicKey = publicKeyOf(privateKey);
    const address = addressOf(publicKey);
    await query('insertWallet', user.id, network, address, publicKey.toString('hex'),
      seal(privateKey, keys), user.sub, decisionId, now());
    privateKey.fill(0);
    return one('walletOf', user.id);
  }

  /** Signs exactly the approved plan with the unsealed key and broadcasts it. */
  async function broadcastApproved(a, user) {
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    const plan = JSON.parse(a.plan);
    const privateKey = openSealed(wallet.sealed_key, vault());
    let signed;
    try {
      signed = signPlan({ privateKey, publicKey: Buffer.from(wallet.public_key, 'hex'), plan });
    } finally {
      privateKey.fill(0);
    }
    const txid = await chain.broadcast(signed.hex);
    await query('setTxid', txid, a.id);
    return txid;
  }

  /* ------------------------------------------------------------ handlers */

  function getConfig() {
    return {
      configured: Boolean(clientId),
      clientId,
      issuer,
      publicOrigin,
      redirectUri: `${publicOrigin}/`,
      palmEnabled: veyns.palmEnabled(),
      requirePalmSignin,
      network,
      vaultReady: Boolean(walletSeed),
    };
  }

  async function loginStart({ setCookie }) {
    requireConfigured();
    const time = now();
    const id = randomId(24);
    const nonce = randomId(32);
    await query('purgeLogins', time);
    await query('insertLogin', id, nonce, time + LOGIN_SECONDS);
    setCookie(LOGIN_COOKIE, id, LOGIN_SECONDS);
    return { nonce };
  }

  async function loginFinish({ body, cookies, setCookie }) {
    requireConfigured();
    const pending = cookies[LOGIN_COOKIE] ? await one('takeLogin', cookies[LOGIN_COOKIE]) : undefined;
    setCookie(LOGIN_COOKIE, '', 0);
    const time = now();
    if (!pending || pending.expires_at <= time) throw new HttpError(401, 'That sign-in expired. Please try again.');

    const claims = await veyns.verifyToken(body.token);
    if (claims.nonce !== pending.nonce) throw new HttpError(401, 'That sign-in did not start in this browser. Please try again.');
    if (claims.veyns_intent !== 'login') throw new HttpError(401, 'That token is not a sign-in.');
    if (!isFresh(claims.auth_time, time - LOGIN_SECONDS, time)) throw new HttpError(401, 'That sign-in is too old. Please try again.');
    if (requirePalmSignin && !(claims.amr || []).includes('veyns:palm')) throw new HttpError(401, 'This wallet requires palm sign-in.');

    await query('insertUser', randomId(12), claims.sub, time);
    const user = await one('userBySub', claims.sub);
    const sid = randomId(32);
    await query('purgeSessions', time);
    await query('insertSession', sha256(sid), user.id, time + SESSION_SECONDS);
    setCookie(SESSION_COOKIE, sid, SESSION_SECONDS);
    return { ok: true };
  }

  async function logout({ cookies, setCookie }) {
    if (cookies[SESSION_COOKIE]) await query('deleteSession', sha256(cookies[SESSION_COOKIE]));
    setCookie(SESSION_COOKIE, '', 0);
    return { ok: true };
  }

  /** Wallet, balance, coins and history. Bitcoin service trouble is reported, never fatal. */
  async function getWallet({ user }) {
    const wallet = await one('walletOf', user.id);
    const openCreate = await one('openApprovalOf', user.id, 'create');
    const withdrawals = (await all('recentWithdrawals', user.id)).map(w => ({
      id: w.id,
      statement: w.statement,
      status: w.status,
      txid: w.txid,
      error: w.error,
      at: w.created_at,
      explorer: w.txid ? chain.explorerTx(w.txid) : null,
    }));
    if (!wallet) {
      return { wallet: null, openApproval: openCreate ? approvalView(openCreate) : null, withdrawals };
    }

    const view = { wallet: walletView(wallet), openApproval: null, withdrawals };
    const openWithdraw = await one('openApprovalOf', user.id, 'withdraw');
    if (openWithdraw) view.openApproval = approvalView(openWithdraw);
    try {
      const [balance, utxos, history, feeRate, qr] = await Promise.all([
        chain.balance(wallet.address),
        chain.spendableUtxos(wallet.address),
        chain.history(wallet.address),
        chain.feeRate(),
        QRCode.toString(`bitcoin:${wallet.address}`, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' }),
      ]);
      view.balance = balance;
      view.spendable = utxos.reduce((sum, u) => sum + u.value, 0);
      view.coins = utxos.length;
      view.history = history.map(h => ({ ...h, explorer: chain.explorerTx(h.txid) }));
      view.feeRate = feeRate;
      view.qr = qr;
    } catch (error) {
      if (!(error instanceof ChainError)) throw error;
      view.chainError = error.message;
    }
    return view;
  }

  /** Step one of owning a wallet: a palm scan that creates and binds the key. */
  async function requestWallet({ user }) {
    requirePalmReady();
    vault();
    if (await one('walletOf', user.id)) throw new HttpError(409, 'This account already has a wallet.');
    const statement = `Create a ${network} Bitcoin wallet that only my palm can spend from`;
    const details = { action: 'create wallet', network, spending_rule: 'palm approval required for every withdrawal' };
    return { approval: approvalView(await newApproval(user, 'create', statement, details)) };
  }

  /** Step two: plan an exact spend, to be signed only after a palm scan. */
  async function requestWithdrawal({ user, body }) {
    requirePalmReady();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');

    const to = String(body.to ?? '').trim();
    if (!isValidAddress(to)) throw new HttpError(400, `That is not a valid ${network} address.`);
    const max = body.amount === 'max';
    const amountSats = max ? 'max' : Number(body.amount);
    if (!max && (!Number.isInteger(amountSats) || amountSats <= 0)) throw new HttpError(400, 'Enter an amount in satoshis.');

    let plan;
    try {
      const [utxos, suggested] = await Promise.all([chain.spendableUtxos(wallet.address), chain.feeRate()]);
      const feeRate = Number(body.feeRate) > 0 ? Number(body.feeRate) : suggested;
      plan = planSpend({ publicKey: Buffer.from(wallet.public_key, 'hex'), utxos, toAddress: to, amountSats, feeRate });
    } catch (error) {
      if (error instanceof WalletError || error instanceof ChainError) throw new HttpError(400, error.message);
      throw error;
    }

    const statement = `Send ${toBtc(plan.sentSats)} tBTC to ${to}`;
    const details = {
      action: 'withdraw',
      network,
      to,
      amount_sats: plan.sentSats,
      fee_sats: plan.feeSats,
      fee_rate: `${plan.feeRate} sat/vB`,
      spends: plan.inputs.map(i => `${i.txid}:${i.index}`).join(' '),
      change_sats: plan.changeSats,
    };
    return { approval: approvalView(await newApproval(user, 'withdraw', statement, details, plan)), plan };
  }

  /** Sends the request to the person's Veyns app; only a palm scan can approve it. */
  async function startPalm({ user, params: [id] }) {
    requirePalmReady();
    const a = await ownApproval(id, user);
    if (a.status !== 'open') throw new HttpError(409, 'This approval is already closed.');
    if (a.request_id) return { approval: approvalView(a) };

    const remote = await veyns.backend('/v1/approvals', {
      subject: approvalSubject(user.sub),
      idempotency_key: a.id,
      expires_in: PALM_REQUEST_SECONDS,
      action: { statement: a.statement, details: JSON.parse(a.details) },
    }, { 'idempotency-key': a.id });
    if (remote.action?.digest !== a.digest) {
      await failApproval(a.id, 'Veyns described a different action.');
      cancelRemote([remote]);
      throw new HttpError(502, 'Veyns described a different action. Nothing was approved.');
    }
    await query('setPalmRequest', remote.request_id, remote.challenge, remote.approval_url, a.id);
    return { approval: approvalView(await one('approvalById', a.id)) };
  }

  async function ownApproval(id, user) {
    const a = await one('ownApproval', id, user.id);
    if (!a) throw new HttpError(404, 'Approval not found.');
    return a;
  }

  async function cancelApproval({ user, params: [id] }) {
    const a = await ownApproval(id, user);
    if (a.status === 'open') {
      await query('closeApproval', 'cancelled', null, now(), a.id);
      cancelRemote([a]);
    }
    return { approval: approvalView(await one('approvalById', a.id)) };
  }

  async function readApproval({ user, params: [id] }) {
    let a = await ownApproval(id, user);
    let remoteStatus = null;

    if (a.status === 'open' && a.request_id) {
      const remote = await veyns.backend(`/v1/approvals/${encodeURIComponent(a.request_id)}`);
      remoteStatus = remote.status;
      if (remote.status === 'approved') {
        await settlePalm(a, user, remote);
      } else if (!['pending', 'verifying'].includes(remote.status)) {
        await failApproval(a.id, `The palm approval was ${remote.status}.`);
      }
      a = await one('approvalById', a.id);
    }
    if (a.decision_id && !a.acked) await acknowledge(a);
    return { approval: approvalView(await one('approvalById', a.id), remoteStatus) };
  }

  /** Checks the signed palm decision, then performs the action it authorised. */
  async function settlePalm(a, user, remote) {
    const fail = reason => failApproval(a.id, `Palm decision rejected: ${reason}.`);
    let claims;
    try {
      claims = await veyns.verifyToken(remote.decision);
    } catch (error) {
      if (error.status === 400 || error.status === 401) return fail(error.message.replace(/\.$/, ''));
      throw error; // Keys unreachable: leave it open and try again on the next poll.
    }
    const problem =
      claims.sub !== user.sub && claims.sub !== approvalSubject(user.sub) ? 'different account'
      : claims.request_id !== a.request_id ? 'different request'
      : claims.request_nonce !== a.challenge ? 'different challenge'
      : claims.veyns_intent !== 'action' ? 'not an approval'
      : !(claims.amr || []).includes('veyns:palm') ? 'not a palm scan'
      : claims.veyns_action?.digest !== a.digest ? 'different action'
      : !isFresh(claims.auth_time, a.created_at, now()) ? 'not fresh'
      : typeof remote.decision_id !== 'string' ? 'missing decision id'
      : null;
    if (problem) return fail(problem);

    await query('setDecision', remote.decision_id, a.id);
    // One decision, one action: whoever claims the approval row performs it.
    if ((await query('claimApproval', `decision:${remote.decision_id}`, now(), a.id)).count !== 1) return;
    try {
      if (a.kind === 'create') await createWallet(a, user, remote.decision_id);
      else await broadcastApproved(a, user);
    } catch (error) {
      const message = error instanceof HttpError || error instanceof ChainError || error instanceof WalletError
        ? error.message : 'The action could not be completed.';
      if (!(error instanceof HttpError || error instanceof ChainError || error instanceof WalletError)) log.error(error);
      await query('setFailure', message, a.id);
    }
  }

  async function acknowledge(a) {
    try {
      await veyns.backend(`/v1/approvals/${encodeURIComponent(a.request_id)}/ack`,
        { decision_id: a.decision_id, operation_id: a.id });
      await query('markAcked', a.id);
    } catch (error) {
      log.warn(`Veyns acknowledgement will be retried: ${error.message}`);
    }
  }

  /* -------------------------------------------------------------- server */

  const routes = [
    { method: 'GET', path: '/api/config', handler: getConfig },
    { method: 'POST', path: '/api/login/start', handler: loginStart },
    { method: 'POST', path: '/api/login/finish', handler: loginFinish },
    { method: 'POST', path: '/api/logout', handler: logout },
    { method: 'GET', path: '/api/wallet', handler: getWallet, auth: true },
    { method: 'POST', path: '/api/wallet/approval', handler: requestWallet, auth: true },
    { method: 'POST', path: '/api/withdrawals', handler: requestWithdrawal, auth: true },
    { method: 'GET', path: /^\/api\/approvals\/([\w-]{8,64})$/, handler: readApproval, auth: true },
    { method: 'POST', path: /^\/api\/approvals\/([\w-]{8,64})\/palm$/, handler: startPalm, auth: true },
    { method: 'POST', path: /^\/api\/approvals\/([\w-]{8,64})\/cancel$/, handler: cancelApproval, auth: true },
  ];

  function matchRoute(method, pathname) {
    for (const route of routes) {
      if (route.method !== method) continue;
      if (typeof route.path === 'string') {
        if (route.path === pathname) return { ...route, params: [] };
      } else {
        const m = pathname.match(route.path);
        if (m) return { ...route, params: m.slice(1) };
      }
    }
    return null;
  }

  const cookieString = (name, value, maxAge) =>
    `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secureCookies ? '; Secure' : ''}`;

  function sendJson(res, status, body, cookies = []) {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...(cookies.length ? { 'set-cookie': cookies } : {}),
    });
    res.end(JSON.stringify(body));
  }

  function serveStatic(req, res, url) {
    if (!publicDir) return sendJson(res, 404, { error: 'Not found.' });
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'Method not allowed.' });
    if (req.headers.host && req.headers.host !== publicHost) {
      res.writeHead(302, { location: publicOrigin + url.pathname + url.search });
      return res.end();
    }
    let file;
    try {
      const root = path.resolve(publicDir);
      file = path.resolve(root, url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1)));
      if (!file.startsWith(root + path.sep)) throw new Error('outside public dir');
    } catch {
      res.writeHead(404, { 'content-type': 'text/plain' });
      return res.end('Not found');
    }
    fs.readFile(file, (error, data) => {
      if (error) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        return res.end('Not found');
      }
      const type = STATIC_TYPES[path.extname(file)] || 'application/octet-stream';
      res.writeHead(200, {
        'content-type': type,
        'cache-control': 'no-cache',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        ...(type.startsWith('text/html') ? { 'content-security-policy': csp } : {}),
      });
      res.end(req.method === 'HEAD' ? undefined : data);
    });
  }

  async function handle(req, res) {
    const url = new URL(req.url, publicOrigin);
    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url);

    const outCookies = [];
    try {
      const route = matchRoute(req.method, url.pathname);
      if (!route) throw new HttpError(404, 'Not found.');
      if (req.method !== 'GET' && req.headers.origin !== publicOrigin) {
        throw new HttpError(403, `Open the wallet at ${publicOrigin}.`);
      }
      const cookies = parseCookies(req.headers.cookie);
      const ctx = {
        params: route.params,
        cookies,
        body: req.method === 'POST' ? await readJson(req) : {},
        setCookie: (name, value, maxAge) => outCookies.push(cookieString(name, value, maxAge)),
        user: route.auth ? await requireUser(cookies) : null,
      };
      sendJson(res, 200, await route.handler(ctx), outCookies);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : error instanceof ChainError ? 502 : 500;
      if (status === 500) log.error(error);
      sendJson(res, status, { error: status === 500 ? 'Something went wrong on the server.' : error.message }, outCookies);
    }
  }

  async function safeHandle(req, res) {
    try {
      await handle(req, res);
    } catch (error) {
      log.error(error);
      if (!res.headersSent) sendJson(res, 500, { error: 'Something went wrong on the server.' });
    }
  }

  const server = http.createServer(safeHandle);

  return {
    server,
    handle: safeHandle,
    async close() {
      await new Promise(resolve => {
        server.close(resolve);
        server.closeAllConnections();
      });
      if (dbPromise) await (await dbPromise.catch(() => null))?.close();
    },
  };
}
