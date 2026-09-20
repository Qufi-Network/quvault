import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import QRCode from 'qrcode';
import { openDb, describeDbError } from './db.js';
import { createVeyns, actionDigest, isFresh, randomId, HttpError, canonicalTransaction, transactionDigest } from './veyns.js';
import { verifyAuthorization, verifyChain, keyIdOf } from './authorization.js';
import { serverKeys, seal, open as openSealed, sealRoot, rootSealMatches } from './vault.js';
import { createChain, createPrices, ChainError } from './chain.js';
import {
  createKey, publicKeyOf, addressOf, planSpend, signPlan, isValidAddress, toBtc, verifyAgainstPlan, WalletError,
} from './bitcoin.js';
import { DEFAULT_POLICY, PolicyError, describePolicy, requiredFor, requiredToChange, validatePolicy } from './policy.js';
import { NETWORKS, createBalances, format, networkList } from './networks.js';

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
  insertClientWallet: `INSERT INTO wallets (user_id, network, address, public_key, custody, unlock_sealed, salt, bound_sub, bound_decision, policy, created_at, attestation_chain, attestation_root_seal, attestation_at)
                       VALUES ($1, $2, $3, $4, 'client', $5, $6, $7, $8, $9, $10, $11, $12, $10) ON CONFLICT (user_id) DO NOTHING`,
  setAttestationChain: 'UPDATE wallets SET attestation_chain = $1, attestation_at = $2 WHERE user_id = $3',
  setAttestationRoot: 'UPDATE wallets SET attestation_chain = $1, attestation_root_seal = $2, attestation_at = $3 WHERE user_id = $4',
  setPolicy: 'UPDATE wallets SET policy = $1 WHERE user_id = $2',
  moveWalletToBrowser: `UPDATE wallets SET address = $1, public_key = $2, custody = 'client', unlock_sealed = $3,
                        salt = $4, sealed_key = NULL WHERE user_id = $5 AND custody = 'server'`,
  setBitcoinAccount: `UPDATE accounts SET address = $1, public_key = $2 WHERE wallet_user_id = $3 AND network = 'bitcoin'`,

  accountsOf: 'SELECT * FROM accounts WHERE wallet_user_id = $1 ORDER BY created_at',
  accountOn: 'SELECT * FROM accounts WHERE wallet_user_id = $1 AND network = $2',
  insertAccount: `INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at)
                  VALUES ($1, $2, $3, $4, $5) ON CONFLICT (wallet_user_id, network) DO NOTHING`,
  insertAccountFull: `INSERT INTO accounts (wallet_user_id, network, address, public_key, policy, signers, created_at)
                      VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (wallet_user_id, network) DO NOTHING`,
  setAccountPolicy: 'UPDATE accounts SET policy = $1, signers = $2 WHERE wallet_user_id = $3 AND network = $4',

  membersOf: 'SELECT * FROM members WHERE wallet_user_id = $1 ORDER BY is_owner DESC, added_at',
  memberIn: 'SELECT * FROM members WHERE wallet_user_id = $1 AND member_id = $2',
  walletsForMember: 'SELECT wallet_user_id FROM members WHERE member_id = $1',
  insertMember: `INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (wallet_user_id, member_id) DO UPDATE SET label = EXCLUDED.label`,
  // The first palm a signer puts to this vault is the identity everyone can point at afterwards.
  bindPalm: `UPDATE members SET palm_id = COALESCE(palm_id, $1), palm_at = COALESCE(palm_at, $2)
             WHERE wallet_user_id = $3 AND member_id = $4`,
  bindPalmId: 'UPDATE members SET palm_id = $1 WHERE wallet_user_id = $2 AND member_id = $3 AND palm_id IS NULL',
  deleteMember: 'DELETE FROM members WHERE wallet_user_id = $1 AND member_id = $2 AND is_owner = false',
  // Erasing a vault: approvals hang off operations, so they go first.
  deleteApprovalsOfWallet: 'DELETE FROM approvals WHERE operation_id IN (SELECT id FROM operations WHERE wallet_user_id = $1)',
  deleteOperationsOfWallet: 'DELETE FROM operations WHERE wallet_user_id = $1',
  deleteAccountsOfWallet: 'DELETE FROM accounts WHERE wallet_user_id = $1',
  deleteMembersOfWallet: 'DELETE FROM members WHERE wallet_user_id = $1',
  deleteWallet: 'DELETE FROM wallets WHERE user_id = $1',

  insertOperation: `INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest, payload, required, status, network, created_at, expires_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'collecting', $10, $11, $12)`,
  operationById: 'SELECT * FROM operations WHERE id = $1',
  openOperationsFor: `SELECT * FROM operations WHERE wallet_user_id = ANY($1) AND status IN ('collecting', 'running') ORDER BY seq`,
  closedOperationsFor: `SELECT * FROM operations WHERE wallet_user_id = ANY($1) AND status IN ('done', 'failed', 'cancelled')
                        ORDER BY seq DESC LIMIT 12`,
  openOperationOfKind: `SELECT * FROM operations WHERE wallet_user_id = $1 AND kind = $2 AND status = 'collecting' ORDER BY seq DESC LIMIT 1`,
  startRunning: `UPDATE operations SET status = 'running' WHERE id = $1 AND status = 'collecting'`,
  finishOperation: 'UPDATE operations SET status = $1, txid = $2, error = $3, closed_at = $4 WHERE id = $5',
  setOperationTxid: 'UPDATE operations SET txid = $1 WHERE id = $2 AND txid IS NULL',
  cancelOperation: `UPDATE operations SET status = 'cancelled', error = $1, closed_at = $2 WHERE id = $3 AND status = 'collecting'`,
  expireOperations: `UPDATE operations SET status = 'failed', error = 'Not enough palm approvals in time.', closed_at = $1
                     WHERE status = 'collecting' AND expires_at <= $1 RETURNING id`,
  // Approved, but the owner's device never came back to sign.
  expireUnsigned: `UPDATE operations SET status = 'failed', error = 'Approved, but never signed on the owner''s device.', closed_at = $1
                   WHERE status = 'running' AND kind = 'withdraw' AND expires_at + 3600 <= $1 RETURNING id`,
  setPayload: 'UPDATE operations SET payload = $1 WHERE id = $2',
  setAuthorization: 'UPDATE operations SET human_authorization = $1 WHERE id = $2',

  approvalsOf: `SELECT a.*, u.id AS member_id FROM approvals a JOIN users u ON u.id = a.user_id WHERE a.operation_id = $1`,
  approvalById: 'SELECT * FROM approvals WHERE id = $1',
  myApprovals: 'SELECT * FROM approvals WHERE operation_id = $1 AND user_id = $2 ORDER BY slot',
  ownApproval: 'SELECT * FROM approvals WHERE id = $1 AND user_id = $2',
  insertApproval: `INSERT INTO approvals (id, operation_id, user_id, slot, status, created_at) VALUES ($1, $2, $3, $4, 'open', $5)`,
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
// A short, stable name for one person's palm inside this vault, from their pairwise subject.
const palmId = sub => `PALM-${sha256(`palm:${sub}`).replace(/[-_]/g, '').slice(0, 12).toUpperCase()}`;

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
        // The reason, in Postgres's own terms, so this is diagnosable without the server log.
        throw new HttpError(503, `The database is not reachable right now (${describeDbError(error)}).`);
      });
    return dbPromise;
  };

  const veyns = createVeyns({ issuer, getClientId: () => clientId, backendSecret, now, fetchImpl });
  const chain = createChain({ apiUrl: chainApi, fetchImpl });
  const balances = createBalances({ fetchImpl });
  const prices = createPrices({ apiUrl: options.priceApi ?? 'https://mempool.space/api', fetchImpl, now });

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

  /**
   * The exact movement of coins, and the hash of it. This digest is what the person reads,
   * what the palm decision covers, what the ML-DSA authorisation names, and what the browser
   * checks before it signs. One value, computed one way.
   */
  const bindPlan = (wallet, plan) => {
    const transaction = canonicalTransaction({ chain: 'bitcoin', network, from: wallet.address, plan });
    return { transaction, digest: transactionDigest(transaction) };
  };

  const secureCookies = publicOrigin.startsWith('https:');
  const publicHost = new URL(publicOrigin).host;
  // Nothing third-party runs on the wallet page: no outside scripts, no frames. Market data
  // is fetched by this server and drawn here, so a compromised widget cannot reach a session.
  const csp = [
    "default-src 'self'",
    `script-src 'self' ${issuer}`,
    `connect-src 'self' ${issuer}`,
    `img-src 'self' data: ${issuer}`,
    "style-src 'self' https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com',
    "frame-src 'none'",
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

  /*
   * Signers and thresholds belong to an account. An account made before that, or one whose
   * row has not been written yet, falls back to what the vault as a whole was set to.
   */
  const policyOfAccount = (account, wallet) => (account?.policy ? JSON.parse(account.policy) : policyOf(wallet));

  const signersOf = (account, members) => {
    const roster = members.map(m => m.member_id);
    const stored = account?.signers ? JSON.parse(account.signers) : null;
    const kept = (stored ?? roster).filter(id => roster.includes(id));
    return kept.length ? kept : roster;
  };

  /* --------------------------------------------------------------- views */

  /**
   * The key this vault's records must be signed by, derived by verifying its registration
   * chain. A chain that does not walk — rewritten, truncated, or rooted somewhere else —
   * produces no key at all, and nothing verifies against it.
   */
  const attestationOf = wallet => {
    if (!wallet?.attestation_chain) return { ok: false, reason: 'this vault has no attestation key' };
    let chain;
    try {
      chain = JSON.parse(wallet.attestation_chain);
    } catch {
      return { ok: false, reason: 'the attestation chain is unreadable' };
    }
    const walked = verifyChain(chain, { vaultId: wallet.address });
    if (!walked.ok) return walked;
    // A chain that walks can still be a chain someone else rooted. The seal says whether this
    // server ever saw that root registered, and a database alone cannot produce one.
    if (!rootSealMatches(walletSeed, { vaultId: wallet.address, rootKeyId: walked.rootKeyId }, wallet.attestation_root_seal)) {
      return { ok: false, reason: 'this is not the key lineage the vault registered' };
    }
    return walked;
  };

  const walletView = w => ({
    address: w.address,
    network: w.network,
    createdAt: w.created_at,
    explorer: chain.explorerAddress(w.address),
    custody: w.custody,
    // The public half of the owner's attestation key, and the lineage it descends from.
    // The server has never had the other half, and cannot extend the lineage itself.
    attestation: attestationView(w),
    protection: w.custody === 'client'
      ? 'Key in the owner’s browser; its unlock secret sealed with ML-KEM-768 + X25519'
      : 'ML-KEM-768 + X25519 + AES-256-GCM',
  });

  /** What a page needs to check a vault's key lineage against what its own device pinned. */
  function attestationView(wallet) {
    const lineage = attestationOf(wallet);
    if (!lineage.ok) return wallet?.attestation_chain ? { algorithm: 'ML-DSA-65', broken: lineage.reason } : null;
    return {
      algorithm: 'ML-DSA-65',
      keyId: lineage.keyId,
      publicKey: lineage.publicKey,
      epoch: lineage.epoch,
      rootKeyId: lineage.rootKeyId,
      chainLength: lineage.length,
      registeredAt: wallet.attestation_at,
    };
  }

  const memberView = m => ({
    id: m.member_id,
    label: m.label,
    owner: m.is_owner,
    // Assigned the first time that person put their palm to this vault.
    palmId: m.palm_id || null,
    palmAt: m.palm_at || null,
  });

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
    // Whether a signed record of the human authorisation exists for this request.
    humanVerified: Boolean(op.human_authorization),
    // Which account the request is about, so the browser knows what to derive or to sign with.
    network: op.network ?? (op.kind === 'account' && op.payload ? JSON.parse(op.payload).network : null),
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

  /** Ends operations whose quorum never arrived, or that were approved but never signed. */
  async function expireOperations() {
    const time = now();
    const closed = await transaction(async q => {
      const rows = [];
      for (const op of (await q('expireOperations', time)).rows) {
        rows.push(...(await q('cancelApprovalsOf', time, op.id)).rows);
      }
      await q('expireUnsigned', time);
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

  /** Who may approve for one account, and what a movement of `sats` from it needs. */
  async function quorumFor(walletOwnerId, networkId, sats) {
    const [wallet, members, account] = await Promise.all([
      one('walletOf', walletOwnerId), all('membersOf', walletOwnerId), one('accountOn', walletOwnerId, networkId),
    ]);
    const policy = policyOfAccount(account, wallet);
    const signers = signersOf(account, members);
    const { approvals, rule } = requiredFor(policy, sats);
    return { wallet, account, members, signers, policy, required: Math.min(approvals, Math.max(1, signers.length)), rule };
  }

  /** What it takes to change an account's signers or thresholds: its own quorum, as it stands now. */
  async function changeQuorum(walletOwnerId, networkId) {
    const { policy, signers, members, account, wallet } = await quorumFor(walletOwnerId, networkId, 0);
    return { required: requiredToChange(policy, signers.length), policy, signers, members, account, wallet };
  }

  async function newOperation({ walletOwnerId, user, kind, statement, details, payload = null, required = 1, networkId = null }) {
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
        actionDigest(statement, details), payload && JSON.stringify(payload), required, networkId, time, time + OPERATION_SECONDS);
      return closed;
    });
    cancelRemote(replaced);
    return one('operationById', id);
  }

  /* ------------------------------------------ what a finished quorum does */

  /**
   * The key itself is made in the owner's browser. All this does is mint the unlock secret
   * that the browser's encrypted copy will need, seal it, and note the palm decision that
   * authorised the wallet. The server never sees a phrase or a private key.
   */
  async function createWallet(op, decisionId) {
    const owner = await one('userById', op.wallet_user_id);
    if (await one('walletOf', owner.id)) throw new HttpError(409, 'This account already has a wallet.');
    const unlock = crypto.randomBytes(32);
    const payload = {
      unlockSealed: seal(unlock, vault()),
      salt: crypto.randomBytes(16).toString('base64'),
      decisionId,
      label: JSON.parse(op.details).owner_label || 'Owner',
    };
    unlock.fill(0);
    await query('setPayload', JSON.stringify(payload), op.id);
    return { txid: null };
  }

  /**
   * Moving a vault made before the key lived in the browser: the palm quorum is in, so mint
   * the unlock secret the browser's new encrypted copy will need. The old key is only retired
   * once the browser has reported its new address and the coins have been swept to it.
   */
  async function prepareUpgrade(op) {
    const unlock = crypto.randomBytes(32);
    const payload = { unlockSealed: seal(unlock, vault()), salt: crypto.randomBytes(16).toString('base64') };
    unlock.fill(0);
    await query('setPayload', JSON.stringify(payload), op.id);
    return { txid: null };
  }

  async function applyPolicy(op) {
    const payload = JSON.parse(op.payload);
    const networkId = payload.network || 'bitcoin';
    const time = now();
    await transaction(async q => {
      for (const member of payload.members) {
        await q('insertMember', op.wallet_user_id, member.id, member.label, member.owner, time);
      }
      await q('setAccountPolicy', JSON.stringify({ rules: payload.rules }),
        JSON.stringify(payload.members.map(m => m.id)), op.wallet_user_id, networkId);
    });
    for (const member of payload.members) await assignPalmId(op.wallet_user_id, member.id);
    await pruneRoster(op.wallet_user_id);
    return { txid: null };
  }

  /** A signer carries the same palm identity everywhere in this vault, from their pairwise subject. */
  async function assignPalmId(ownerId, memberId) {
    const person = await one('userById', memberId);
    if (person) await query('bindPalmId', palmId(person.sub), ownerId, memberId);
  }

  /** The roster exists so signers can see the vault: drop anyone who now signs for nothing. */
  async function pruneRoster(ownerId) {
    const [accounts, members] = await Promise.all([all('accountsOf', ownerId), all('membersOf', ownerId)]);
    const signing = new Set(accounts.flatMap(account => signersOf(account, members)));
    for (const member of members) {
      if (!member.is_owner && !signing.has(member.member_id)) await query('deleteMember', ownerId, member.member_id);
    }
  }

  /** Resolves the people a request names into signer entries, by approver code or by id. */
  async function collectSigners({ user, roster, keep, add = [], include = [] }) {
    const chosen = new Map(keep);
    for (const id of include) {
      const member = roster.find(m => m.member_id === String(id));
      if (!member) throw new HttpError(400, 'That signer is not part of this vault.');
      chosen.set(member.member_id, { id: member.member_id, label: member.label, owner: member.is_owner });
    }
    for (const entry of add) {
      const code = String(entry.code ?? '').trim();
      const label = String(entry.label ?? '').replace(/\s+/g, ' ').trim().slice(0, 40);
      if (!label) throw new HttpError(400, 'Give each signer a name.');
      const person = await one('userById', code);
      if (!person) throw new HttpError(400, `No one has the approver code "${code}". They must sign in to QuVault once first.`);
      chosen.set(person.id, { id: person.id, label, owner: person.id === user.id });
    }
    return chosen;
  }

  function readRules(proposed, fallback, signerCount) {
    try {
      const value = Array.isArray(proposed) ? { rules: proposed } : proposed ?? fallback;
      return validatePolicy(value, signerCount);
    } catch (error) {
      if (error instanceof PolicyError) throw new HttpError(400, error.message);
      throw error;
    }
  }

  /** Only for wallets made before the key moved into the browser. */
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

  /**
   * What the owner's device has to put its name to, drawn from what actually happened here.
   *
   * The server builds this expectation and checks the signed record against it; it cannot
   * produce the record itself, because the key that signs one lives in the browser.
   */
  async function expectedAuthorization(op, wallet) {
    const approvals = await all('approvalsOf', op.id);
    const approved = approvals.filter(a => a.status === 'approved');
    const plan = JSON.parse(op.payload);
    const bound = bindPlan(wallet, plan);
    if (bound.digest !== plan.transactionHash || bound.digest !== JSON.parse(op.details).transaction_hash) {
      throw new HttpError(409, 'The stored transaction no longer matches the one that was approved.');
    }
    return {
      vaultId: wallet.address,
      accountId: 'bitcoin',
      transactionHash: bound.digest,
      statementDigest: op.digest,
      approvalMethod: 'veyns:palm',
      approvals: `${approved.length} of ${op.required}`,
      approvedBy: approved.map(a => a.user_id),
      decisionIds: approved.map(a => a.decision_id).filter(Boolean),
      keyEpoch: attestationOf(wallet).epoch ?? 0,
      // The record cannot predate the approvals it claims, nor be dated in the future.
      notBefore: Math.min(...approved.map(a => a.closed_at ?? a.created_at)) - 60,
      notAfter: now() + 60,
    };
  }

  /** The record and the key to check it with, for this request. */
  function authorizationOf(op) {
    if (!op.human_authorization) return null;
    try {
      return JSON.parse(op.human_authorization);
    } catch {
      return null;
    }
  }

  /** Runs the operation once the last needed approval has landed. */
  async function runOperation(op, decisionId) {
    const time = now();
    try {
      if (op.kind === 'withdraw') {
        const wallet = await one('walletOf', op.wallet_user_id);
        // With the key in the owner's browser, the quorum is complete but the signing is not:
        // the operation waits, and the owner's device signs and sends it.
        if (wallet?.custody === 'client') return;
      }
      const { txid } = op.kind === 'create' ? await createWallet(op, decisionId)
        : op.kind === 'policy' ? await applyPolicy(op)
        // Recovery and new accounts do nothing here: finishing them lets the owner's device
        // open the phrase, or derive the new network's address.
        : op.kind === 'upgrade' ? await prepareUpgrade(op)
        // Erasing happens when the owner's browser confirms it, so the key is cleared there too.
        : op.kind === 'reset' ? { txid: null }
        : op.kind === 'recovery' || op.kind === 'account' || op.kind === 'attestation' ? { txid: null }
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
      // Authorisation records are signed by the owner's vault; this server only verifies them.
      attestation: { algorithm: 'ML-DSA-65', signedBy: 'vault' },
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
      // Kept for the vault as a whole; each account carries its own in accounts[].
      policy: wallet ? policyOf(wallet) : null,
      members: members.map(memberView),
      networks: networkList(),
      accounts: wallet ? await accountsView(user.id, wallet, members) : [],
      labels,
      pending: await Promise.all(open.map(withApprovals)),
      history: await Promise.all(closed.map(withApprovals)),
    };

    // Spending is Bitcoin's today, so the vault-level rules shown are that account's.
    view.policy = view.accounts.find(account => account.network === 'bitcoin')?.policy ?? view.policy;

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

  /** Randomness the browser mixes into a new phrase, so it never relies on one generator. */
  function getRandom() {
    return { random: crypto.randomBytes(32).toString('base64') };
  }

  /**
   * Hands the browser the unlock secret for its encrypted key — only for an operation whose
   * palm approvals are complete, and only to the person whose device holds that key.
   */
  async function unlockFor({ user, params: [id] }) {
    const op = await ownOperation(id, user);
    if (op.wallet_user_id !== user.id) throw new HttpError(403, 'Only the account owner can unlock this wallet.');
    if (!['create', 'withdraw', 'recovery', 'account', 'upgrade', 'attestation'].includes(op.kind)) {
      throw new HttpError(409, 'Nothing to unlock for this request.');
    }
    if (!['running', 'done'].includes(op.status)) throw new HttpError(409, 'This request is still collecting palm approvals.');

    const wallet = await one('walletOf', user.id);
    if (op.kind === 'create') {
      if (wallet) throw new HttpError(409, 'This account already has a wallet.');
      const payload = JSON.parse(op.payload);
      return { unlock: openSealed(payload.unlockSealed, vault()).toString('base64'), salt: payload.salt, label: payload.label };
    }
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    if (op.kind === 'upgrade') {
      // The secret for the key this browser is about to make, not the one being retired.
      if (wallet.custody === 'client') throw new HttpError(409, 'This vault already lives in your browser.');
      const payload = JSON.parse(op.payload);
      return { unlock: openSealed(payload.unlockSealed, vault()).toString('base64'), salt: payload.salt };
    }
    if (wallet.custody !== 'client') throw new HttpError(409, 'This wallet signs on the server.');
    return {
      unlock: openSealed(wallet.unlock_sealed, vault()).toString('base64'),
      salt: wallet.salt,
      ...(op.kind === 'withdraw' ? await withdrawalUnlock(op, wallet) : {}),
    };
  }

  /** What the owner's device needs to sign the transaction and to attest to the approval. */
  async function withdrawalUnlock(op, wallet) {
    const expected = await expectedAuthorization(op, wallet);
    return {
      plan: JSON.parse(op.payload),
      address: wallet.address,
      transactionHash: expected.transactionHash,
      statementDigest: expected.statementDigest,
      approvals: expected.approvals,
      approvedBy: expected.approvedBy,
      decisionIds: expected.decisionIds,
      attestationEpoch: expected.keyEpoch,
    };
  }

  /** The browser reports the address it derived; the server stores only public details. */
  async function registerWallet({ user, body }) {
    const op = await ownOperation(String(body.operationId ?? ''), user);
    if (op.kind !== 'create' || op.status !== 'done' || op.wallet_user_id !== user.id) {
      throw new HttpError(409, 'That is not a finished wallet creation.');
    }
    if (await one('walletOf', user.id)) throw new HttpError(409, 'This account already has a wallet.');
    const address = String(body.address ?? '').trim();
    const publicKey = String(body.publicKey ?? '').trim();
    if (!isValidAddress(address)) throw new HttpError(400, `That is not a valid ${network} address.`);
    if (!/^[0-9a-f]{66}$/i.test(publicKey)) throw new HttpError(400, 'That public key does not look right.');
    if (addressOf(Buffer.from(publicKey, 'hex')) !== address) throw new HttpError(400, 'The address does not match the public key.');

    const payload = JSON.parse(op.payload);
    const time = now();
    const registration = readRegistration(body, { vaultId: address });
    await query('insertClientWallet', user.id, network, address, publicKey, payload.unlockSealed, payload.salt,
      user.sub, payload.decisionId, JSON.stringify(DEFAULT_POLICY), time, JSON.stringify(registration.chain),
      sealRoot(walletSeed, { vaultId: address, rootKeyId: registration.rootKeyId }));
    await query('insertMember', user.id, user.id, payload.label || 'Owner', true, time);
    // This vault exists because that palm approved it, so the owner's palm identity starts here.
    await query('bindPalm', palmId(user.sub), time, user.id, user.id);
    await query('insertAccountFull', user.id, 'bitcoin', address, publicKey,
      JSON.stringify(DEFAULT_POLICY), JSON.stringify([user.id]), time);
    return { wallet: walletView(await one('walletOf', user.id)) };
  }

  /** Takes the transaction the owner's browser signed, checks it against the approved plan, sends it. */
  async function broadcastSigned({ user, params: [id], body }) {
    const op = await ownOperation(id, user);
    if (op.wallet_user_id !== user.id) throw new HttpError(403, 'Only the account owner can send this.');
    if (op.kind !== 'withdraw') throw new HttpError(409, 'That request is not a withdrawal.');
    if (op.status === 'done' && op.txid) return { txid: op.txid };
    if (op.status !== 'running') throw new HttpError(409, 'This withdrawal is not ready to send.');

    const plan = JSON.parse(op.payload);
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');

    // 1. The plan on disk is still the transaction that was approved.
    const bound = bindPlan(wallet, plan);
    if (bound.digest !== plan.transactionHash || bound.digest !== JSON.parse(op.details).transaction_hash) {
      throw new HttpError(409, 'The stored transaction no longer matches the one that was approved.');
    }
    // 2. The owner's own key attested to that approval, for this exact transaction.
    //    This server cannot produce this record: it holds only the public half of that key.
    if (wallet.custody === 'client') {
      const expected = await expectedAuthorization(op, wallet);
      const authorization = body.authorization ?? authorizationOf(op);
      const lineage = attestationOf(wallet);
      if (!lineage.ok) throw new HttpError(409, `This vault has no valid attestation key: ${lineage.reason}.`);
      const checkedAuthorization = verifyAuthorization(authorization, lineage.publicKey, expected);
      if (!checkedAuthorization.ok) {
        throw new HttpError(409, `No valid human authorisation for this transaction: ${checkedAuthorization.reason}.`);
      }
      if (!op.human_authorization) await query('setAuthorization', JSON.stringify(authorization), op.id);
    }
    // 3. The signed bytes spend the approved coins, pay the approved outputs, at the approved fee.
    let checked;
    try {
      checked = verifyAgainstPlan(String(body.hex ?? ''), plan);
    } catch (error) {
      if (error instanceof WalletError) throw new HttpError(400, error.message);
      throw error;
    }
    try {
      const txid = await chain.broadcast(String(body.hex).trim());
      await query('finishOperation', 'done', txid, null, now(), op.id);
      return { txid };
    } catch (error) {
      if (!(error instanceof ChainError)) throw error;
      await query('finishOperation', 'failed', null, error.message, now(), op.id);
      throw new HttpError(502, error.message);
    }
  }

  /** Market price for the dashboard chart. Never touches wallet state. */
  async function getPrice() {
    try {
      return await prices.latest();
    } catch (error) {
      if (!(error instanceof ChainError)) throw error;
      return { usd: null, series: [], error: error.message };
    }
  }

  /** Every account this vault holds, with its balance read from that network. */
  async function accountsView(ownerId, wallet, members) {
    let rows = await all('accountsOf', ownerId);
    if (!rows.some(row => row.network === 'bitcoin')) {
      // A vault made before accounts existed still has the Bitcoin account it was created as.
      await query('insertAccountFull', ownerId, 'bitcoin', wallet.address, wallet.public_key,
        wallet.policy, JSON.stringify(members.map(m => m.member_id)), wallet.created_at);
      rows = await all('accountsOf', ownerId);
    }
    const byId = new Map(members.map(m => [m.member_id, m]));

    const accounts = await Promise.all(rows.map(async row => {
      const network = NETWORKS[row.network];
      const [amount, qr] = await Promise.all([
        row.network === 'bitcoin'
          ? chain.balance(row.address).then(b => b.confirmed + b.pending).catch(() => null)
          : balances.of(row.network, row.address),
        QRCode.toString(row.address, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' }).catch(() => null),
      ]);
      const policy = policyOfAccount(row, wallet);
      const signerIds = signersOf(row, members);
      const signers = signerIds.map(id => memberView(byId.get(id) ?? { member_id: id, label: 'Signer', is_owner: false }));
      return {
        network: row.network,
        label: network.label,
        symbol: network.symbol,
        chain: network.chain,
        canSend: network.canSend,
        address: row.address,
        explorer: network.explorer(row.address),
        amount,
        formatted: amount === null ? null : format(amount, row.network),
        qr,
        policy,
        signers,
        // What it takes to change this account's signers or thresholds, as they stand now.
        changeRequired: requiredToChange(policy, signers.length),
        rulesText: describePolicy(policy, signers),
        createdAt: row.created_at,
      };
    }));
    // The Bitcoin account made with the wallet comes first, then in the order they were added.
    return accounts.sort((a, b) => (a.network === 'bitcoin' ? -1 : b.network === 'bitcoin' ? 1 : a.createdAt - b.createdAt));
  }

  /** Adds an account on another network. The address comes from the same phrase, in the browser. */
  async function requestAccount({ user, body }) {
    requirePalmReady();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    if (wallet.custody !== 'client') {
      throw new HttpError(409, 'This vault was made before keys lived in the browser, so it has no recovery phrase for other networks to come from. Move it into this browser first.');
    }
    const networkId = String(body.network ?? '');
    const network = NETWORKS[networkId];
    if (!network) throw new HttpError(400, 'Choose one of the supported networks.');
    if (await one('accountOn', user.id, networkId)) throw new HttpError(409, `This vault already has a ${network.label} account.`);

    const roster = await all('membersOf', user.id);
    const owner = roster.find(m => m.member_id === user.id);
    const keep = new Map([[user.id, { id: user.id, label: owner?.label || 'Owner', owner: true }]]);
    const chosen = await collectSigners({ user, roster, keep, add: body.add, include: body.signers });
    const signers = [...chosen.values()];
    const policy = readRules(body.rules, DEFAULT_POLICY, signers.length);

    // Adding an account is as guarded as changing the main account: the same palms, in the same number.
    const { required } = await changeQuorum(user.id, 'bitcoin');
    const statement = `Add a ${network.label} account to my vault`;
    const details = {
      action: 'add account',
      network: `${network.label} ${network.chain}`,
      derived_from: 'the same recovery phrase',
      signers: signers.map(s => s.label).join(', '),
      rules: describePolicy(policy, signers),
    };
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'account', statement, details,
      payload: { network: networkId, rules: policy.rules, members: signers },
      required, networkId,
    });
    return { operation: operationView(op, [], user), signers, policy };
  }

  /** The browser reports the address it derived for the new network. */
  async function registerAccount({ user, body }) {
    const op = await ownOperation(String(body.operationId ?? ''), user);
    if (op.kind !== 'account' || op.status !== 'done' || op.wallet_user_id !== user.id) {
      throw new HttpError(409, 'That is not an approved account request.');
    }
    const payload = JSON.parse(op.payload);
    const networkId = payload.network;
    const network = NETWORKS[networkId];
    const address = String(body.address ?? '').trim();
    if (!network.valid(address)) throw new HttpError(400, `That does not look like a ${network.label} address.`);
    if (await one('accountOn', user.id, networkId)) throw new HttpError(409, `This vault already has a ${network.label} account.`);

    const time = now();
    const signers = payload.members ?? [{ id: user.id, label: 'Owner', owner: true }];
    await transaction(async q => {
      for (const member of signers) {
        await q('insertMember', user.id, member.id, member.label, member.owner, time);
      }
      await q('insertAccountFull', user.id, networkId, address, String(body.publicKey ?? '').slice(0, 130),
        JSON.stringify({ rules: payload.rules ?? DEFAULT_POLICY.rules }), JSON.stringify(signers.map(m => m.id)), time);
    });
    for (const member of signers) await assignPalmId(user.id, member.id);
    return { ok: true };
  }

  /**
   * Erasing the vault and starting over. The palm statement names the address, what it holds
   * and what is destroyed, so nobody approves this without having read it.
   */
  /** Everything an independent check of one authorisation needs, and nothing private. */
  async function getReceipt({ user, params: [id] }) {
    const op = await ownOperation(id, user);
    const authorization = authorizationOf(op);
    if (!authorization) throw new HttpError(404, 'There is no authorisation record for this request.');
    const wallet = await one('walletOf', op.wallet_user_id);
    const lineage = attestationOf(wallet);
    const publicKey = lineage.ok ? lineage.publicKey : null;
    return {
      authorization,
      publicKey,
      keyId: lineage.ok ? lineage.keyId : null,
      // The lineage, so a reader can check the key descends from the one the vault started with.
      attestationChain: wallet?.attestation_chain ? JSON.parse(wallet.attestation_chain) : null,
      rootKeyId: lineage.ok ? lineage.rootKeyId : null,
      signedBy: 'vault',
      algorithm: 'ML-DSA-65',
      statement: op.statement,
      details: JSON.parse(op.details),
      status: op.status,
      txid: op.txid,
      explorer: op.txid ? chain.explorerTx(op.txid) : null,
      // The server's own verdict; a client that verifies for itself need not believe it.
      verified: verifyAuthorization(authorization, publicKey, { transactionHash: authorization.record.transactionHash }),
    };
  }

  async function requestReset({ user }) {
    requirePalmReady();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'There is no vault to erase.');
    const [accounts, balance] = await Promise.all([
      all('accountsOf', user.id),
      chain.balance(wallet.address).catch(() => null),
    ]);
    const holding = balance ? balance.confirmed + balance.pending : null;
    const statement = 'Erase this vault and start over';
    const details = {
      action: 'erase vault',
      network,
      address: wallet.address,
      accounts: accounts.map(a => NETWORKS[a.network]?.label ?? a.network).join(', '),
      holds: holding === null ? 'unknown' : `${toBtc(holding)} tBTC`,
      warning: wallet.custody === 'client'
        ? 'the key in this browser goes with it; only the twelve words could bring it back'
        : 'the key held for this vault is destroyed and cannot be brought back',
    };
    const { required } = await changeQuorum(user.id, 'bitcoin');
    const op = await newOperation({ walletOwnerId: user.id, user, kind: 'reset', statement, details, required });
    return { operation: operationView(op, [], user), holding, custody: wallet.custody };
  }

  /** Sweeps the coins out if asked to, then removes the vault and everything hanging off it. */
  async function completeReset({ user, body }) {
    const op = await ownOperation(String(body.operationId ?? ''), user);
    if (op.kind !== 'reset' || op.status !== 'done' || op.wallet_user_id !== user.id) {
      throw new HttpError(409, 'That is not an approved erase.');
    }
    const wallet = await one('walletOf', user.id);
    if (!wallet) return { ok: true, txid: null, sweptSats: 0 };

    const balance = await chain.balance(wallet.address).catch(() => null);
    const holding = balance ? balance.confirmed + balance.pending : 0;
    const sweepTo = String(body.sweepTo ?? '').trim();
    if (holding > 0 && !sweepTo && body.acceptLoss !== true) {
      throw new HttpError(409, `This vault still holds ${toBtc(holding)} tBTC. Give an address to sweep it to, or say plainly that you are letting it go.`);
    }

    let txid = null;
    let sweptSats = 0;
    if (sweepTo) {
      if (!isValidAddress(sweepTo)) throw new HttpError(400, `That is not a valid ${network} address.`);
      if (wallet.custody !== 'server') {
        throw new HttpError(409, 'This vault signs in your browser: send the coins with Send funds first.');
      }
      if (balance?.pending > 0) throw new HttpError(409, 'A payment here is still waiting for its first confirmation.');
      try {
        const utxos = await chain.spendableUtxos(wallet.address);
        if (utxos.length) {
          const oldPublicKey = Buffer.from(wallet.public_key, 'hex');
          const plan = planSpend({ publicKey: oldPublicKey, utxos, toAddress: sweepTo, amountSats: 'max', feeRate: await chain.feeRate() });
          const privateKey = openSealed(wallet.sealed_key, vault());
          try {
            txid = await chain.broadcast(signPlan({ privateKey, publicKey: oldPublicKey, plan }).hex);
          } finally {
            privateKey.fill(0);
          }
          sweptSats = plan.sentSats;
        }
      } catch (error) {
        if (error instanceof ChainError || error instanceof WalletError) throw new HttpError(409, `The coins could not be moved: ${error.message}`);
        throw error;
      }
    }

    // Nothing of this vault is kept: not the key, not its accounts, signers or history.
    await transaction(async q => {
      await q('deleteApprovalsOfWallet', user.id);
      await q('deleteOperationsOfWallet', user.id);
      await q('deleteAccountsOfWallet', user.id);
      await q('deleteMembersOfWallet', user.id);
      await q('deleteWallet', user.id);
    });
    log.log(`vault erased for ${user.id}${txid ? `, coins swept in ${txid}` : ''}`);
    return { ok: true, txid, sweptSats };
  }

  /**
   * A registration the owner's device signed, checked as the chain it would become.
   *
   * For a new vault that is a chain of one, signed by the key it registers. For a rotation it
   * is the existing chain with one more link, which only the current key could have signed.
   * The server decides nothing here: it walks what it is given and refuses what does not walk.
   */
  function readRegistration(body, { vaultId, existing = [] }) {
    const link = body.attestationRegistration;
    if (!link?.record) throw new HttpError(400, 'This vault must register an attestation key.');
    const chain = [...existing, link];
    const walked = verifyChain(chain, { vaultId });
    if (!walked.ok) throw new HttpError(400, `That key registration does not hold up: ${walked.reason}.`);
    return { chain, ...walked };
  }

  /** Replacing the attestation key: palm-approved, like every other change to a vault. */
  async function requestAttestationRotation({ user }) {
    requirePalmReady();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    if (wallet.custody !== 'client') throw new HttpError(409, 'This vault signs on the server and has no attestation key of its own.');
    // A vault made before key lineages existed has no chain to continue, so it starts one.
    // A vault with a working chain continues it, and the key it has signs for the next.
    const current = attestationOf(wallet);
    const starting = !current.ok && !wallet.attestation_chain;
    if (!current.ok && !starting) {
      throw new HttpError(409, `This vault's key lineage cannot be continued: ${current.reason}.`);
    }
    const next = starting ? 1 : current.epoch + 1;
    const statement = starting
      ? 'Register the authorisation key of my vault'
      : 'Replace the authorisation key of my vault';
    const details = starting
      ? {
        action: 'register authorisation key',
        network,
        vault: wallet.address,
        to_epoch: '1',
        effect: 'this vault can sign authorisation records again',
      }
      : {
        action: 'replace authorisation key',
        network,
        vault: wallet.address,
        from_key: current.keyId,
        from_epoch: String(current.epoch),
        to_epoch: String(next),
        effect: 'records signed by the old key stop being accepted',
      };
    const { required } = await changeQuorum(user.id, 'bitcoin');
    const op = await newOperation({ walletOwnerId: user.id, user, kind: 'attestation', statement, details, required });
    return { operation: operationView(op, [], user), epoch: next, starting };
  }

  /** The browser reports the public half of the new key. The old one stops being accepted. */
  async function registerAttestationKey({ user, body }) {
    const op = await ownOperation(String(body.operationId ?? ''), user);
    if (op.kind !== 'attestation' || op.status !== 'done' || op.wallet_user_id !== user.id) {
      throw new HttpError(409, 'That is not an approved key replacement.');
    }
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    const current = attestationOf(wallet);
    if (!current.ok && wallet.attestation_chain) {
      throw new HttpError(409, `This vault's key lineage cannot be continued: ${current.reason}.`);
    }

    if (!current.ok) {
      // Starting a lineage: a root, self-signed, sealed so the database alone cannot move it.
      const registration = readRegistration(body, { vaultId: wallet.address });
      if (registration.epoch !== 1) throw new HttpError(409, 'A new lineage starts at epoch 1.');
      await query('setAttestationRoot', JSON.stringify(registration.chain),
        sealRoot(walletSeed, { vaultId: wallet.address, rootKeyId: registration.rootKeyId }), now(), user.id);
      return { attestation: attestationView(await one('walletOf', user.id)) };
    }

    const existing = JSON.parse(wallet.attestation_chain);
    const registration = readRegistration(body, { vaultId: wallet.address, existing });
    if (registration.epoch !== current.epoch + 1) throw new HttpError(409, 'A replacement key follows the one before it.');
    await query('setAttestationChain', JSON.stringify(registration.chain), now(), user.id);
    return { attestation: attestationView(await one('walletOf', user.id)) };
  }

  /** Asks for the palm approvals that move a server-held vault into the owner's browser. */
  async function requestUpgrade({ user }) {
    requirePalmReady();
    vault();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    if (wallet.custody === 'client') throw new HttpError(409, 'This vault already lives in your browser.');
    const statement = 'Move this vault into my browser and retire the key held on the server';
    const details = {
      action: 'move key to browser',
      network,
      from: wallet.address,
      coins: 'every confirmed coin is swept to the new address',
      spending_rule: 'the same signers and thresholds keep applying',
    };
    const { required } = await changeQuorum(user.id, 'bitcoin');
    const op = await newOperation({ walletOwnerId: user.id, user, kind: 'upgrade', statement, details, required });
    return { operation: operationView(op, [], user) };
  }

  /**
   * The browser has made its key and saved it; now the server sweeps the old address with the
   * key it still holds, and only then swaps the wallet over and forgets that key for good.
   */
  async function completeUpgrade({ user, body }) {
    const op = await ownOperation(String(body.operationId ?? ''), user);
    if (op.kind !== 'upgrade' || op.status !== 'done' || op.wallet_user_id !== user.id) {
      throw new HttpError(409, 'That is not an approved move.');
    }
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    if (wallet.custody === 'client') return { wallet: walletView(wallet), txid: op.txid, sweptSats: 0 };

    const address = String(body.address ?? '').trim();
    const publicKey = String(body.publicKey ?? '').trim();
    if (!isValidAddress(address)) throw new HttpError(400, `That is not a valid ${network} address.`);
    if (!/^[0-9a-f]{66}$/i.test(publicKey)) throw new HttpError(400, 'That public key does not look right.');
    if (addressOf(Buffer.from(publicKey, 'hex')) !== address) throw new HttpError(400, 'The address does not match the public key.');
    if (address === wallet.address) throw new HttpError(400, 'The new address has to be a different one.');
    // The moved vault is a new key lineage, rooted at the key the new phrase derives.
    const registration = readRegistration(body, { vaultId: address });

    let txid = null;
    let sweptSats = 0;
    try {
      const [balance, utxos, feeRate] = await Promise.all([
        chain.balance(wallet.address), chain.spendableUtxos(wallet.address), chain.feeRate(),
      ]);
      // An unconfirmed coin cannot be spent yet, and the old key is about to be destroyed.
      if (balance.pending > 0) {
        throw new HttpError(409, 'A payment here is still waiting for its first confirmation. Move the vault once it lands.');
      }
      if (utxos.length) {
        const oldPublicKey = Buffer.from(wallet.public_key, 'hex');
        const plan = planSpend({ publicKey: oldPublicKey, utxos, toAddress: address, amountSats: 'max', feeRate });
        const privateKey = openSealed(wallet.sealed_key, vault());
        try {
          txid = await chain.broadcast(signPlan({ privateKey, publicKey: oldPublicKey, plan }).hex);
        } finally {
          privateKey.fill(0);
        }
        sweptSats = plan.sentSats;
      }
    } catch (error) {
      if (error instanceof HttpError) throw error;
      if (error instanceof ChainError || error instanceof WalletError) throw new HttpError(409, `The coins could not be moved: ${error.message}`);
      throw error;
    }

    const payload = JSON.parse(op.payload);
    await transaction(async q => {
      const moved = await q('moveWalletToBrowser', address, publicKey, payload.unlockSealed, payload.salt, user.id);
      if (!moved.count) throw new HttpError(409, 'This vault has already been moved.');
      await q('setBitcoinAccount', address, publicKey, user.id);
      await q('insertAccountFull', user.id, 'bitcoin', address, publicKey,
        wallet.policy, JSON.stringify([user.id]), now());
      await q('setAttestationRoot', JSON.stringify(registration.chain),
        sealRoot(walletSeed, { vaultId: address, rootKeyId: registration.rootKeyId }), now(), user.id);
    });
    if (txid) await query('setOperationTxid', txid, op.id);
    return { wallet: walletView(await one('walletOf', user.id)), txid, sweptSats };
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
    const networkId = String(body.network ?? 'bitcoin');
    const network = NETWORKS[networkId];
    if (!network) throw new HttpError(400, 'That is not one of the networks here.');
    const account = await one('accountOn', user.id, networkId);
    if (!account) throw new HttpError(409, `This vault has no ${network.label} account.`);

    const roster = await all('membersOf', user.id);
    const current = signersOf(account, roster);
    const byId = new Map(roster.map(m => [m.member_id, m]));
    const keep = new Map(current.map(id => [id, {
      id,
      label: byId.get(id)?.label || 'Signer',
      owner: Boolean(byId.get(id)?.is_owner),
    }]));
    for (const id of body.remove ?? []) {
      const member = keep.get(String(id));
      if (!member) continue;
      if (member.owner) throw new HttpError(400, 'The owner cannot be removed.');
      keep.delete(String(id));
    }
    const chosen = await collectSigners({ user, roster, keep, add: body.add, include: body.include });
    const members = [...chosen.values()];
    if (!members.some(m => m.owner)) throw new HttpError(400, 'The owner must stay a signer.');
    const policy = readRules(body.rules, policyOfAccount(account, wallet), members.length);

    const removed = current.filter(id => !chosen.has(id));
    const statement = `Change who can approve for my ${network.label} account and how many palms it takes`;
    const details = {
      action: 'change signers and thresholds',
      network: `${network.label} ${network.chain}`,
      signers: members.map(m => m.label).join(', '),
      rules: describePolicy(policy, members),
      approvers: members.length,
    };
    // The palms that guard the account as it stands now are the ones that can change it.
    const { required } = await changeQuorum(user.id, networkId);
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'policy', statement, details,
      payload: { network: networkId, rules: policy.rules, members, removed },
      required, networkId,
    });
    return { operation: operationView(op, [], user), policy, members };
  }

  async function requestRecovery({ user }) {
    requirePalmReady();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    if (wallet.custody !== 'client') {
      throw new HttpError(409, 'This vault signs on the server and has no recovery phrase. Move it into this browser to get one.');
    }
    const statement = `Show the recovery phrase for my ${network} wallet`;
    const details = {
      action: 'reveal recovery phrase',
      network,
      scans: 'two palm scans, one per hand',
      warning: 'anyone who sees these words can spend the wallet',
    };
    const op = await newOperation({ walletOwnerId: user.id, user, kind: 'recovery', statement, details, required: 2 });
    return { operation: operationView(op, [], user) };
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
    const { signers, required, rule } = await quorumFor(user.id, 'bitcoin', leaving);
    // The digest of the exact transaction is part of what the palm approves, not a note beside it.
    const bound = bindPlan(wallet, plan);
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
      approvals_required: `${required} of ${signers.length} signer${signers.length === 1 ? '' : 's'}`,
      transaction_hash: bound.digest,
    };
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'withdraw', statement, details,
      payload: { ...plan, transactionHash: bound.digest }, required, networkId: 'bitcoin',
    });
    return { operation: operationView(op, [], user), plan, rule, transactionHash: bound.digest };
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
      if (op.network) {
        // Only the people who sign for that account, as it stands before this change.
        // A brand new account has no signers yet, so the main account's stand in.
        const [account, members] = await Promise.all([
          one('accountOn', op.wallet_user_id, op.kind === 'account' ? 'bitcoin' : op.network),
          all('membersOf', op.wallet_user_id),
        ]);
        if (!signersOf(account, members).includes(user.id)) {
          throw new HttpError(403, 'You are not a signer on that account.');
        }
      }
    } else if (op.wallet_user_id !== user.id) {
      throw new HttpError(403, 'Only the owner can create this wallet.');
    }

    // Recovery takes two scans from the same person, one per hand, so it has two slots.
    const slots = op.kind === 'recovery' ? 2 : 1;
    const mine = await all('myApprovals', op.id, user.id);
    const open = mine.find(a => a.status === 'open');
    if (open) return { approval: { id: open.id, status: 'open', slot: open.slot } };
    if (mine.filter(a => a.status === 'approved').length >= slots) throw new HttpError(409, 'You have already approved this.');

    const approvalId = randomId(16);
    const slot = mine.reduce((highest, a) => Math.max(highest, a.slot), 0) + 1;
    await query('insertApproval', approvalId, op.id, user.id, slot, now());
    return { approval: { id: approvalId, status: 'open', slot } };
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
    await query('bindPalm', palmId(claims.sub), now(), op.wallet_user_id, user.id);
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
    { method: 'GET', path: '/api/price', handler: getPrice, auth: true },
    { method: 'GET', path: '/api/random', handler: getRandom, auth: true },
    { method: 'GET', path: '/api/wallet', handler: getWallet, auth: true },
    { method: 'POST', path: '/api/wallet/approval', handler: requestWallet, auth: true },
    { method: 'POST', path: '/api/wallet/register', handler: registerWallet, auth: true },
    { method: 'POST', path: '/api/wallet/upgrade/approval', handler: requestUpgrade, auth: true },
    { method: 'POST', path: '/api/wallet/upgrade', handler: completeUpgrade, auth: true },
    { method: 'POST', path: '/api/attestation/approval', handler: requestAttestationRotation, auth: true },
    { method: 'POST', path: '/api/attestation/register', handler: registerAttestationKey, auth: true },
    { method: 'POST', path: '/api/wallet/reset/approval', handler: requestReset, auth: true },
    { method: 'POST', path: '/api/wallet/reset', handler: completeReset, auth: true },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/unlock$/, handler: unlockFor, auth: true },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/broadcast$/, handler: broadcastSigned, auth: true },
    { method: 'GET', path: /^\/api\/operations\/([\w-]{8,64})\/receipt$/, handler: getReceipt, auth: true },
    { method: 'POST', path: '/api/policy', handler: requestPolicy, auth: true },
    { method: 'POST', path: '/api/recovery', handler: requestRecovery, auth: true },
    { method: 'POST', path: '/api/accounts/approval', handler: requestAccount, auth: true },
    { method: 'POST', path: '/api/accounts/register', handler: registerAccount, auth: true },
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
    // For tests and maintenance scripts; nothing in a request path reaches for this.
    db: database,
    async close() {
      await new Promise(resolve => {
        server.close(resolve);
        server.closeAllConnections();
      });
      if (dbPromise) await (await dbPromise.catch(() => null))?.close();
    },
  };
}
