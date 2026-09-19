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
import { DEFAULT_POLICY, PolicyError, describePolicy, requiredFor, requiredToChange, validatePolicy } from './policy.js';

const SESSION_COOKIE = 'palmsafe_sid';
const LOGIN_COOKIE = 'palmsafe_login';
const SESSION_SECONDS = 7 * 24 * 3600;
const LOGIN_SECONDS = 300;
const PALM_REQUEST_SECONDS = 300;
const OPERATION_SECONDS = 1800; // how long a quorum has to come together

const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
};

const SQL = {
  userBySub: 'SELECT * FROM users WHERE sub = $1',
  userById: 'SELECT * FROM users WHERE id = $1',
  insertUser: 'INSERT INTO users (id, sub, created_at) VALUES ($1, $2, $3) ON CONFLICT (sub) DO NOTHING',

  insertSession: 'INSERT INTO sessions (id_hash, user_id, expires_at) VALUES ($1, $2, $3)',
  sessionUser: 'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = $1 AND s.expires_at > $2',
  deleteSession: 'DELETE FROM sessions WHERE id_hash = $1',
  purgeSessions: 'DELETE FROM sessions WHERE expires_at <= $1',
  insertLogin: 'INSERT INTO login_nonces (id, nonce, expires_at) VALUES ($1, $2, $3)',
  takeLogin: 'DELETE FROM login_nonces WHERE id = $1 RETURNING nonce, expires_at',
  purgeLogins: 'DELETE FROM login_nonces WHERE expires_at <= $1',

  walletOf: 'SELECT * FROM wallets WHERE user_id = $1',
  insertWallet: `INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, policy, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (user_id) DO NOTHING`,
  setPolicy: 'UPDATE wallets SET policy = $1 WHERE user_id = $2',

  membersOf: 'SELECT * FROM members WHERE wallet_user_id = $1 ORDER BY is_owner DESC, added_at',
  memberIn: 'SELECT * FROM members WHERE wallet_user_id = $1 AND member_id = $2',
  walletsForMember: 'SELECT wallet_user_id FROM members WHERE member_id = $1',
  insertMember: `INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (wallet_user_id, member_id) DO UPDATE SET label = EXCLUDED.label`,
  deleteMember: 'DELETE FROM members WHERE wallet_user_id = $1 AND member_id = $2 AND is_owner = false',

  insertOperation: `INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest, payload, required, status, created_at, expires_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'collecting', $10, $11)`,
  operationById: 'SELECT * FROM operations WHERE id = $1',
  openOperationsFor: `SELECT * FROM operations WHERE wallet_user_id = ANY($1) AND status IN ('collecting', 'running') ORDER BY seq`,
  closedOperationsFor: `SELECT * FROM operations WHERE wallet_user_id = ANY($1) AND status IN ('done', 'failed', 'cancelled')
                        ORDER BY seq DESC LIMIT 12`,
  openOperationOfKind: `SELECT * FROM operations WHERE wallet_user_id = $1 AND kind = $2 AND status = 'collecting' ORDER BY seq DESC LIMIT 1`,
  startRunning: `UPDATE operations SET status = 'running' WHERE id = $1 AND status = 'collecting'`,
  finishOperation: 'UPDATE operations SET status = $1, txid = $2, error = $3, closed_at = $4 WHERE id = $5',
  cancelOperation: `UPDATE operations SET status = 'cancelled', error = $1, closed_at = $2 WHERE id = $3 AND status = 'collecting'`,
  expireOperations: `UPDATE operations SET status = 'failed', error = 'Not enough palm approvals in time.', closed_at = $1
                     WHERE status = 'collecting' AND expires_at <= $1 RETURNING id`,

  approvalsOf: `SELECT a.*, u.id AS member_id FROM approvals a JOIN users u ON u.id = a.user_id WHERE a.operation_id = $1`,
  approvalById: 'SELECT * FROM approvals WHERE id = $1',
  myApproval: 'SELECT * FROM approvals WHERE operation_id = $1 AND user_id = $2',
  ownApproval: 'SELECT * FROM approvals WHERE id = $1 AND user_id = $2',
  insertApproval: `INSERT INTO approvals (id, operation_id, user_id, status, created_at) VALUES ($1, $2, $3, 'open', $4)`,
  countApproved: `SELECT count(*)::int AS n FROM approvals WHERE operation_id = $1 AND status = 'approved'`,
  closeApproval: `UPDATE approvals SET status = $1, error = $2, closed_at = $3 WHERE id = $4 AND status = 'open'`,
  claimApproval: `UPDATE approvals SET status = 'approved', proof_id = $1, closed_at = $2 WHERE id = $3 AND status = 'open'`,
  cancelApprovalsOf: `UPDATE approvals SET status = 'cancelled', closed_at = $1 WHERE operation_id = $2 AND status = 'open' RETURNING request_id`,
  setPalmRequest: `UPDATE approvals SET request_id = $1, challenge = $2, approval_url = $3 WHERE id = $4 AND status = 'open'`,
  setDecision: 'UPDATE approvals SET decision_id = $1 WHERE id = $2',
  markAcked: 'UPDATE approvals SET acked = true WHERE id = $1',
};

const sha256 = value => crypto.createHash('sha256').update(value).digest('base64url');
const fmtSats = n => Number(n).toLocaleString('en-US');

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
      const seen = options.databaseCandidates?.length
        ? ` The deployment has ${options.databaseCandidates.join(', ')}, but none holds a postgres:// URL.`
        : ' This deployment has no database variable at all — connect Neon to Production, then redeploy.';
      return Promise.reject(new HttpError(503, `No database yet.${seen}`));
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

  const policyOf = wallet => (wallet?.policy ? JSON.parse(wallet.policy) : DEFAULT_POLICY);

  /* --------------------------------------------------------------- views */

  const walletView = w => ({
    address: w.address,
    network: w.network,
    createdAt: w.created_at,
    explorer: chain.explorerAddress(w.address),
    protection: 'ML-KEM-768 + X25519 + AES-256-GCM',
  });

  const memberView = m => ({ id: m.member_id, label: m.label, owner: m.is_owner });

  const operationView = (op, approvals, me) => ({
    id: op.id,
    kind: op.kind,
    statement: op.statement,
    details: JSON.parse(op.details),
    status: op.status,
    required: op.required,
    approvedBy: approvals.filter(a => a.status === 'approved').map(a => a.user_id),
    approvals: approvals.map(a => ({ id: a.id, userId: a.user_id, status: a.status, error: a.error })),
    mine: approvals.find(a => a.user_id === me?.id) ? {
      id: approvals.find(a => a.user_id === me.id).id,
      status: approvals.find(a => a.user_id === me.id).status,
      approvalUrl: approvals.find(a => a.user_id === me.id).status === 'open'
        ? approvals.find(a => a.user_id === me.id).approval_url : null,
    } : null,
    txid: op.txid,
    error: op.error,
    startedBy: op.started_by,
    walletOwner: op.wallet_user_id,
    createdAt: op.created_at,
    expiresAt: op.expires_at,
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
  let subjectForm = null; // which naming Veyns accepted, remembered per instance

  /** Asks Veyns for a palm request, trying both ways the service has accepted a subject. */
  async function createPalmRequest(a, user, op) {
    const forms = [
      { name: 'pairwise', subject: approvalSubject(user.sub), key: a.id },
      { name: 'plain', subject: user.sub, key: `${a.id}-plain` },
    ].filter(form => (subjectForm ? form.name === subjectForm : true));
    if (forms.length === 2 && forms[0].subject === forms[1].subject) forms.pop();

    const refusals = [];
    for (const form of forms) {
      try {
        const remote = await veyns.backend('/v1/approvals', {
          subject: form.subject,
          idempotency_key: form.key,
          expires_in: PALM_REQUEST_SECONDS,
          action: { statement: op.statement, details: JSON.parse(op.details) },
        }, { 'idempotency-key': form.key });
        subjectForm = form.name;
        return remote;
      } catch (error) {
        if (error.status !== 400) throw error;
        refusals.push(`${form.name} (${form.subject.length} characters): ${error.message}`);
      }
    }
    subjectForm = null;
    throw new HttpError(400, `Veyns refused the palm request both ways. ${refusals.join(' — ')} `
      + 'Check that this account has its palm scanner connected and is admitted to the palm pilot.');
  }

  /** Ends operations whose quorum never arrived. Runs before every signed-in request. */
  async function expireOperations() {
    const time = now();
    const closed = await transaction(async q => {
      const rows = [];
      for (const op of (await q('expireOperations', time)).rows) {
        rows.push(...(await q('cancelApprovalsOf', time, op.id)).rows);
      }
      return rows;
    });
    cancelRemote(closed);
  }

  async function walletsVisibleTo(user) {
    const memberships = await all('walletsForMember', user.id);
    const ids = new Set(memberships.map(m => m.wallet_user_id));
    ids.add(user.id); // your own wallet, even before any member row exists
    return [...ids];
  }

  /** The people who may approve for this wallet, and what a spend of `sats` needs. */
  async function quorumFor(walletOwnerId, sats) {
    const wallet = await one('walletOf', walletOwnerId);
    const members = await all('membersOf', walletOwnerId);
    const policy = policyOf(wallet);
    const { approvals, rule } = requiredFor(policy, sats);
    return { wallet, members, policy, required: Math.min(approvals, Math.max(1, members.length)), rule };
  }

  async function newOperation({ walletOwnerId, user, kind, statement, details, payload = null, required = 1 }) {
    const id = randomId(16);
    const time = now();
    const replaced = await transaction(async q => {
      const previous = (await q('openOperationOfKind', walletOwnerId, kind)).rows[0];
      let closed = [];
      if (previous) {
        await q('cancelOperation', 'Replaced by a newer request.', time, previous.id);
        closed = (await q('cancelApprovalsOf', time, previous.id)).rows;
      }
      await q('insertOperation', id, walletOwnerId, user.id, kind, statement, JSON.stringify(details),
        actionDigest(statement, details), payload && JSON.stringify(payload), required, time, time + OPERATION_SECONDS);
      return closed;
    });
    cancelRemote(replaced);
    return one('operationById', id);
  }

  /* ------------------------------------------ what a finished quorum does */

  async function createWallet(op, decisionId) {
    const owner = await one('userById', op.wallet_user_id);
    if (await one('walletOf', owner.id)) throw new HttpError(409, 'This account already has a wallet.');
    const keys = vault();
    const privateKey = createKey();
    const publicKey = publicKeyOf(privateKey);
    const address = addressOf(publicKey);
    await query('insertWallet', owner.id, network, address, publicKey.toString('hex'),
      seal(privateKey, keys), owner.sub, decisionId, JSON.stringify(DEFAULT_POLICY), now());
    privateKey.fill(0);
    await query('insertMember', owner.id, owner.id, JSON.parse(op.details).owner_label || 'Owner', true, now());
    return { txid: null };
  }

  async function applyPolicy(op) {
    const payload = JSON.parse(op.payload);
    const time = now();
    await transaction(async q => {
      await q('setPolicy', JSON.stringify({ rules: payload.rules }), op.wallet_user_id);
      for (const member of payload.members) {
        await q('insertMember', op.wallet_user_id, member.id, member.label, member.owner, time);
      }
      for (const id of payload.removed ?? []) await q('deleteMember', op.wallet_user_id, id);
    });
    return { txid: null };
  }

  async function broadcastPlan(op) {
    const wallet = await one('walletOf', op.wallet_user_id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    const plan = JSON.parse(op.payload);
    const privateKey = openSealed(wallet.sealed_key, vault());
    let signed;
    try {
      signed = signPlan({ privateKey, publicKey: Buffer.from(wallet.public_key, 'hex'), plan });
    } finally {
      privateKey.fill(0);
    }
    return { txid: await chain.broadcast(signed.hex) };
  }

  /** Runs the operation once the last needed approval has landed. */
  async function runOperation(op, decisionId) {
    const time = now();
    try {
      const { txid } = op.kind === 'create' ? await createWallet(op, decisionId)
        : op.kind === 'policy' ? await applyPolicy(op)
        : await broadcastPlan(op);
      await query('finishOperation', 'done', txid, null, time, op.id);
    } catch (error) {
      const known = error instanceof HttpError || error instanceof ChainError || error instanceof WalletError;
      if (!known) log.error(error);
      await query('finishOperation', 'failed', null, known ? error.message : 'The action could not be completed.', time, op.id);
    }
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
      databaseVariable: options.databaseVariable ?? (databaseUrl ? 'local' : null),
      databaseCandidates: options.databaseCandidates ?? [],
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

  /** Everything the page shows: the wallet you own, what you can approve for, and the rules. */
  async function getWallet({ user }) {
    const visible = await walletsVisibleTo(user);
    const [wallet, members, open, closed] = await Promise.all([
      one('walletOf', user.id),
      all('membersOf', user.id),
      all('openOperationsFor', visible),
      all('closedOperationsFor', visible),
    ]);

    const withApprovals = async op => operationView(op, await all('approvalsOf', op.id), user);
    const labels = {};
    for (const id of visible) {
      for (const m of await all('membersOf', id)) labels[m.member_id] = m.label;
    }

    const view = {
      me: { id: user.id, code: user.id },
      wallet: wallet ? walletView(wallet) : null,
      policy: wallet ? policyOf(wallet) : null,
      members: members.map(memberView),
      labels,
      pending: await Promise.all(open.map(withApprovals)),
      history: await Promise.all(closed.map(withApprovals)),
    };

    if (!wallet) return view;
    try {
      const [balance, utxos, txs, feeRate, qr] = await Promise.all([
        chain.balance(wallet.address),
        chain.spendableUtxos(wallet.address),
        chain.history(wallet.address),
        chain.feeRate(),
        QRCode.toString(`bitcoin:${wallet.address}`, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' }),
      ]);
      view.balance = balance;
      view.spendable = utxos.reduce((sum, u) => sum + u.value, 0);
      view.coins = utxos.length;
      view.chainHistory = txs.map(h => ({ ...h, explorer: chain.explorerTx(h.txid) }));
      view.feeRate = feeRate;
      view.qr = qr;
    } catch (error) {
      if (!(error instanceof ChainError)) throw error;
      view.chainError = error.message;
    }
    return view;
  }

  async function requestWallet({ user, body }) {
    requirePalmReady();
    vault();
    if (await one('walletOf', user.id)) throw new HttpError(409, 'This account already has a wallet.');
    const label = String(body.label ?? 'Owner').replace(/\s+/g, ' ').trim().slice(0, 40) || 'Owner';
    const statement = `Create a ${network} Bitcoin wallet that only my palm can spend from`;
    const details = { action: 'create wallet', network, owner_label: label, spending_rule: 'palm approval required for every withdrawal' };
    const op = await newOperation({ walletOwnerId: user.id, user, kind: 'create', statement, details, required: 1 });
    return { operation: operationView(op, [], user) };
  }

  /** Proposes new rules and/or approvers. The change itself is palm-approved. */
  async function requestPolicy({ user, body }) {
    requirePalmReady();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    const current = await all('membersOf', user.id);

    const keep = new Map(current.map(m => [m.member_id, { id: m.member_id, label: m.label, owner: m.is_owner }]));
    for (const id of body.remove ?? []) {
      const member = keep.get(String(id));
      if (!member) continue;
      if (member.owner) throw new HttpError(400, 'The owner cannot be removed.');
      keep.delete(String(id));
    }
    for (const entry of body.add ?? []) {
      const code = String(entry.code ?? '').trim();
      const label = String(entry.label ?? '').replace(/\s+/g, ' ').trim().slice(0, 40);
      if (!label) throw new HttpError(400, 'Give each approver a name.');
      const person = await one('userById', code);
      if (!person) throw new HttpError(400, `No one has the approver code "${code}". They must sign in to QuVault once first.`);
      keep.set(person.id, { id: person.id, label, owner: person.id === user.id });
    }

    const members = [...keep.values()];
    if (!members.some(m => m.owner)) throw new HttpError(400, 'The owner must stay an approver.');
    let policy;
    try {
      // Accept either a bare list of rules or a whole policy object.
      const proposed = Array.isArray(body.rules) ? { rules: body.rules } : body.rules ?? policyOf(wallet);
      policy = validatePolicy(proposed, members.length);
    } catch (error) {
      if (error instanceof PolicyError) throw new HttpError(400, error.message);
      throw error;
    }

    const removed = current.filter(m => !keep.has(m.member_id)).map(m => m.member_id);
    const summary = describePolicy(policy, members);
    const statement = `Change the spending rules of my ${network} wallet`;
    const details = { action: 'change spending rules', network, rules: summary, approvers: members.length };
    const required = requiredToChange(policyOf(wallet), current.length);
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'policy', statement, details,
      payload: { rules: policy.rules, members, removed }, required,
    });
    return { operation: operationView(op, [], user), policy, members };
  }

  /** Plans an exact spend and works out how many palms it needs. */
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

    const leaving = plan.sentSats + plan.feeSats;
    const { members, required, rule } = await quorumFor(user.id, leaving);
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
      approvals_required: `${required} of ${members.length} approver${members.length === 1 ? '' : 's'}`,
    };
    const op = await newOperation({ walletOwnerId: user.id, user, kind: 'withdraw', statement, details, payload: plan, required });
    return { operation: operationView(op, [], user), plan, rule };
  }

  async function ownOperation(id, user) {
    const op = await one('operationById', id);
    if (!op) throw new HttpError(404, 'Request not found.');
    const allowed = op.wallet_user_id === user.id || await one('memberIn', op.wallet_user_id, user.id);
    if (!allowed) throw new HttpError(404, 'Request not found.');
    return op;
  }

  /** Puts your name to a pending request: creates your own approval row. */
  async function joinOperation({ user, params: [id] }) {
    requirePalmReady();
    const op = await ownOperation(id, user);
    if (op.status !== 'collecting') throw new HttpError(409, 'This request is no longer collecting approvals.');
    if (op.expires_at <= now()) throw new HttpError(409, 'This request has expired.');
    if (op.kind !== 'create') {
      const member = await one('memberIn', op.wallet_user_id, user.id);
      if (!member) throw new HttpError(403, 'You are not an approver for this wallet.');
    } else if (op.wallet_user_id !== user.id) {
      throw new HttpError(403, 'Only the owner can create this wallet.');
    }

    const existing = await one('myApproval', op.id, user.id);
    if (existing) {
      if (existing.status === 'approved') throw new HttpError(409, 'You have already approved this.');
      if (existing.status === 'open') return { approval: { id: existing.id, status: existing.status } };
    }
    const approvalId = randomId(16);
    await query('insertApproval', approvalId, op.id, user.id, now());
    return { approval: { id: approvalId, status: 'open' } };
  }

  async function ownApproval(id, user) {
    const a = await one('ownApproval', id, user.id);
    if (!a) throw new HttpError(404, 'Approval not found.');
    return a;
  }

  async function startPalm({ user, params: [id] }) {
    requirePalmReady();
    const a = await ownApproval(id, user);
    if (a.status !== 'open') throw new HttpError(409, 'This approval is already closed.');
    if (a.request_id) return { approval: { id: a.id, status: a.status, approvalUrl: a.approval_url } };
    const op = await one('operationById', a.operation_id);
    if (op.status !== 'collecting') throw new HttpError(409, 'This request is no longer collecting approvals.');

    const remote = await createPalmRequest(a, user, op);
    if (remote.action?.digest !== op.digest) {
      await query('closeApproval', 'failed', 'Veyns described a different action.', now(), a.id);
      cancelRemote([remote]);
      throw new HttpError(502, 'Veyns described a different action. Nothing was approved.');
    }
    await query('setPalmRequest', remote.request_id, remote.challenge, remote.approval_url, a.id);
    return { approval: { id: a.id, status: 'open', approvalUrl: remote.approval_url } };
  }

  async function cancelApproval({ user, params: [id] }) {
    const a = await ownApproval(id, user);
    if (a.status === 'open') {
      await query('closeApproval', 'cancelled', null, now(), a.id);
      cancelRemote([a]);
    }
    return { ok: true };
  }

  async function cancelOperation({ user, params: [id] }) {
    const op = await ownOperation(id, user);
    if (op.started_by !== user.id && op.wallet_user_id !== user.id) {
      throw new HttpError(403, 'Only the person who started this, or the wallet owner, can cancel it.');
    }
    const time = now();
    const closed = await transaction(async q => {
      await q('cancelOperation', 'Cancelled.', time, op.id);
      return (await q('cancelApprovalsOf', time, op.id)).rows;
    });
    cancelRemote(closed);
    return { ok: true };
  }

  async function readApproval({ user, params: [id] }) {
    let a = await ownApproval(id, user);
    let remoteStatus = null;

    if (a.status === 'open' && a.request_id) {
      const remote = await veyns.backend(`/v1/approvals/${encodeURIComponent(a.request_id)}`);
      remoteStatus = remote.status;
      if (remote.status === 'approved') await settlePalm(a, user, remote);
      else if (!['pending', 'verifying'].includes(remote.status)) {
        await query('closeApproval', 'failed', `The palm approval was ${remote.status}.`, now(), a.id);
      }
      a = await one('approvalById', a.id);
    }
    if (a.decision_id && !a.acked) await acknowledge(a);

    const op = await one('operationById', a.operation_id);
    return {
      approval: { id: a.id, status: a.status, error: a.error, remoteStatus, approvalUrl: a.status === 'open' ? a.approval_url : null },
      operation: operationView(op, await all('approvalsOf', op.id), user),
    };
  }

  /** Checks the signed palm decision, records it, and runs the operation when the quorum is complete. */
  async function settlePalm(a, user, remote) {
    const fail = reason => query('closeApproval', 'failed', `Palm decision rejected: ${reason}.`, now(), a.id);
    const op = await one('operationById', a.operation_id);
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
      : claims.veyns_action?.digest !== op.digest ? 'different action'
      : !isFresh(claims.auth_time, a.created_at, now()) ? 'not fresh'
      : typeof remote.decision_id !== 'string' ? 'missing decision id'
      : null;
    if (problem) return fail(problem);
    if (op.status !== 'collecting') return fail('the request is no longer collecting approvals');

    await query('setDecision', remote.decision_id, a.id);
    // Record this approval and, if it completes the quorum, claim the right to run the operation.
    const mine = await transaction(async q => {
      if ((await q('claimApproval', `decision:${remote.decision_id}`, now(), a.id)).count !== 1) return false;
      const { n } = (await q('countApproved', op.id)).rows[0];
      if (n < op.required) return false;
      return (await q('startRunning', op.id)).count === 1;
    });
    if (mine) await runOperation(op, remote.decision_id);
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
    { method: 'POST', path: '/api/policy', handler: requestPolicy, auth: true },
    { method: 'POST', path: '/api/withdrawals', handler: requestWithdrawal, auth: true },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/approval$/, handler: joinOperation, auth: true },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/cancel$/, handler: cancelOperation, auth: true },
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
      if (route.auth && cookies[SESSION_COOKIE]) await expireOperations();
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
