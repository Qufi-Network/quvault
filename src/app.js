import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import QRCode from 'qrcode';
import { openDb, describeDbError } from './db.js';
import { createVeyns, actionDigest, isFresh, randomId, HttpError, canonicalTransaction, transactionDigest, sha256Base64Url } from './veyns.js';
import { canonicalJson } from './canonical.js';
import { verifyAuthorization, verifyChain, keyIdOf, verifyCheckpoint } from './authorization.js';
import { serverKeys, seal, open as openSealed, sealRoot, rootSealMatches } from './vault.js';
import { createChain, createPrices, ChainError } from './chain.js';
import {
  createKey, publicKeyOf, addressOf, planSpend, signPlan, isValidAddress, toBtc, verifyAgainstPlan, WalletError,
  multisigAddressOf, multisigOf, psbtForPlan, signersOfPsbt, combinePsbts, finalizePsbt, signatureCount, NETWORK,
} from './bitcoin.js';
import {
  palmVaultOf, planPalmSpend, palmVaultPsbt, palmSignersOf, combinePalmPsbts, finalizePalmPsbt,
  palmVaultFromDescriptor, palmPathOf, recoveryClock, RECOVERY_CHOICES, delayForDays, daysOfDelay,
} from './palm-vault.js';
import { createPalmSigner, PalmRefused } from './palm-signer.js';
import {
  walletParams, walletSalt, walletAddressOf, deployCallOf, NONCE_CALL, transferCallOf, recoverAddress,
  evmAddressOfPublicKey, evmTransferDigest, eip712TransferDigest, normalTransfer, NATIVE, DEPLOYER, PalmWalletError,
} from './palm-wallet.js';
import { relayerKeyFrom, relayerAddressOf, signRelayed } from './palm-relayer.js';
import { DEFAULT_POLICY, PolicyError, describePolicy, requiredFor, requiredToChange, validatePolicy } from './policy.js';
import { NETWORKS, createBalances, format, networkList } from './networks.js';
import { canonicalTransfer, transferBytes, transferDigest, checkErc20Plan } from './canonical-transfer.js';
import { reconcileSignedTransfer, transactionHash as evmTransactionHash } from './evm.js';
import { createEvmChain, EvmChainError } from './evm-chain.js';
import { createSecurityLog, redact } from './events.js';
import {
  EVIDENCE, GENESIS, sealEntry, buildBundle, verifyBundle, summarisePayment, checkpointsAgree,
} from './evidence.js';
import { createScanner, SCANNER } from './scanner.js';
import { RATE, clientAddress, bucketFor, isOverLimit, refusalMessage } from './rate-limit.js';
import {
  ANCHOR, ANCHOR_POLICY, anchorWindow, createNullSink, assertSink, compareAgainstExternal,
} from './anchor.js';

const SESSION_COOKIE = 'palmsafe_sid';
const LOGIN_COOKIE = 'palmsafe_login';
const SESSION_SECONDS = 7 * 24 * 3600;
const LOGIN_SECONDS = 300;
const PALM_REQUEST_SECONDS = 300;
const OPERATION_SECONDS = 1800; // how long a quorum has to come together
const UNLOCK_SECONDS = 300; // how long the key stays open once a request has opened it

/*
 * The two custody modes, named rather than spelled out at each of the thirty places that ask.
 *
 * BROWSER is the only one that can spend. LEGACY is what the first version of QuVault made:
 * the server holds the whole private key, so a QuVault operator could sign with it and no
 * palm would be involved. That is not a property this product is allowed to have, so the
 * legacy key is now reachable from exactly one function — `sweepLegacyVault` — which can do
 * nothing but empty the vault to a single address under a completed palm approval.
 *
 * Legacy rows are not deleted and legacy coins are not stranded: the way out is
 * /api/wallet/upgrade, which sweeps to a browser-held key, or /api/wallet/reset, which sweeps
 * to an address the owner gives. Both end with `sealed_key = NULL` or the row gone.
 */
const CUSTODY = { BROWSER: 'client', LEGACY: 'server' };

const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webp': 'image/webp',
};

const SQL = {
  /*
   * One statement, atomic: insert the bucket or add one to it, and say what the count is now.
   * `expires_at` is never updated, because the window start is part of the key — a new window
   * is a different row, so there is no reset to get wrong under concurrency.
   */
  bumpRateLimit: `INSERT INTO rate_limits (bucket, hits, expires_at) VALUES ($1, 1, $2)
                  ON CONFLICT (bucket) DO UPDATE SET hits = rate_limits.hits + 1
                  RETURNING hits`,
  clearExpiredLimits: 'DELETE FROM rate_limits WHERE expires_at < $1',

  /* The evidence log. Append only; there is deliberately no UPDATE or DELETE here. */
  evidenceHead: 'SELECT hash FROM evidence ORDER BY seq DESC LIMIT 1',
  evidenceByKey: 'SELECT * FROM evidence WHERE idempotency_key = $1',
  appendEvidence: `INSERT INTO evidence
      (id, at, kind, actor, scope, subject_kind, subject_id, payload, prev_hash, hash, idempotency_key)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
  evidenceAll: 'SELECT * FROM evidence ORDER BY seq',
  evidenceForSubject: 'SELECT * FROM evidence WHERE subject_id = $1 ORDER BY seq',
  evidenceCount: 'SELECT count(*)::int AS n FROM evidence',
  insertCheckpoint: `INSERT INTO evidence_checkpoints
      (id, wallet_user_id, head, entry_count, at, key_id, checkpoint)
    VALUES ($1, $2, $3, $4, $5, $6, $7)`,
  checkpointsOf: 'SELECT * FROM evidence_checkpoints WHERE wallet_user_id = $1 ORDER BY at',
  checkpointById: 'SELECT * FROM evidence_checkpoints WHERE id = $1',
  checkpointByHead: 'SELECT * FROM evidence_checkpoints WHERE wallet_user_id = $1 AND head = $2',
  insertAnchor: `INSERT INTO evidence_anchors
      (id, checkpoint_id, wallet_user_id, sink, result, ref, detail, at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
  anchorsOf: 'SELECT * FROM evidence_anchors WHERE wallet_user_id = $1 ORDER BY at',
  /*
   * Checkpoints with no STORED attempt: the ones still to be forwarded. A sink outage leaves
   * work here rather than losing it, and this is what a retry run picks up.
   */
  checkpointsAwaitingAnchor: `SELECT c.* FROM evidence_checkpoints c
    WHERE c.wallet_user_id = $1
      AND NOT EXISTS (
        SELECT 1 FROM evidence_anchors a WHERE a.checkpoint_id = c.id AND a.result = 'STORED')
    ORDER BY c.at`,
  latestCheckpoint: 'SELECT * FROM evidence_checkpoints WHERE wallet_user_id = $1 ORDER BY at DESC LIMIT 1',

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
  freezeVault: 'UPDATE wallets SET frozen_at = $1, frozen_by = $2 WHERE user_id = $3 AND frozen_at IS NULL',
  unfreezeVault: 'UPDATE wallets SET frozen_at = NULL, frozen_by = NULL WHERE user_id = $1',
  stopOperationsOf: `UPDATE operations SET status = 'cancelled', error = $1, closed_at = $2
                     WHERE wallet_user_id = $3 AND status IN ('collecting', 'running') AND kind <> 'unfreeze' RETURNING id`,
  savedAddress: 'SELECT * FROM address_book WHERE wallet_user_id = $1 AND network = $2 AND address = $3',
  addressBookOf: 'SELECT network, address, name, added_at FROM address_book WHERE wallet_user_id = $1 ORDER BY lower(name)',
  saveAddress: `INSERT INTO address_book (wallet_user_id, network, address, name, added_at, added_by) VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (wallet_user_id, network, address)
                DO UPDATE SET name = EXCLUDED.name, added_at = EXCLUDED.added_at, added_by = EXCLUDED.added_by`,
  paidBefore: `SELECT count(*)::int AS n FROM operations WHERE wallet_user_id = $1 AND network = $2 AND kind = 'withdraw'
               AND status = 'done' AND lower(details::jsonb ->> 'to') = lower($3)`,
  pushSubscriptionsOf: 'SELECT * FROM push_subscriptions WHERE user_id = ANY($1)',
  pushCountOf: 'SELECT count(*)::int AS n FROM push_subscriptions WHERE user_id = $1',
  savePushSubscription: `INSERT INTO push_subscriptions (endpoint, user_id, p256dh, auth, created_at) VALUES ($1, $2, $3, $4, $5)
                         ON CONFLICT (endpoint)
                         DO UPDATE SET user_id = EXCLUDED.user_id, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth, created_at = EXCLUDED.created_at`,
  deletePushSubscription: 'DELETE FROM push_subscriptions WHERE endpoint = $1',
  deleteMyPushSubscription: 'DELETE FROM push_subscriptions WHERE endpoint = $1 AND user_id = $2',
  lockAccountToPalm: `UPDATE accounts SET address = $1, public_key = $2, required = $3, quorum_keys = $4, lock_kind = 'palm',
                        palm_vault_id = $5, palm_key = $6, recovery_delay = $7, descriptor = $8,
                        previous_address = COALESCE(previous_address, address)
                      WHERE wallet_user_id = $9 AND network = $10`,
  // A palm vault moving to new signers: guarded on the address it is moving from, so a move
  // can land once and only on the vault it was approved for.
  moveAccountToPalm: `UPDATE accounts SET address = $1, public_key = $2, required = $3, quorum_keys = $4, lock_kind = 'palm',
                        palm_vault_id = $5, palm_key = $6, recovery_delay = $7, descriptor = $8, previous_address = $9,
                        policy = $10, signers = $11, reminded = NULL
                      WHERE wallet_user_id = $12 AND network = 'bitcoin' AND address = $9`,
  palmAccounts: `SELECT * FROM accounts WHERE network = 'bitcoin' AND lock_kind = 'palm' AND required IS NOT NULL`,
  setReminded: `UPDATE accounts SET reminded = $1 WHERE wallet_user_id = $2 AND network = 'bitcoin'`,
  lockAccountToQuorum: `UPDATE accounts SET address = $1, public_key = $2, required = $3, quorum_keys = $4,
                          previous_address = COALESCE(previous_address, address)
                        WHERE wallet_user_id = $5 AND network = $6`,

  membersOf: 'SELECT * FROM members WHERE wallet_user_id = $1 ORDER BY is_owner DESC, added_at',
  memberIn: 'SELECT * FROM members WHERE wallet_user_id = $1 AND member_id = $2',
  keysOfMember: 'SELECT key_index FROM members WHERE member_id = $1 AND key_index IS NOT NULL ORDER BY key_index',
  setMemberKey: `UPDATE members SET public_key = $1, key_index = $2, key_at = $3
                 WHERE wallet_user_id = $4 AND member_id = $5`,
  walletsForMember: 'SELECT wallet_user_id FROM members WHERE member_id = $1',
  insertMember: `INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (wallet_user_id, member_id) DO UPDATE SET label = EXCLUDED.label`,
  // The first palm a signer puts to this vault is the identity everyone can point at afterwards.
  bindPalm: `UPDATE members SET palm_id = COALESCE(palm_id, $1), palm_at = COALESCE(palm_at, $2)
             WHERE wallet_user_id = $3 AND member_id = $4`,
  bindPalmId: 'UPDATE members SET palm_id = $1 WHERE wallet_user_id = $2 AND member_id = $3 AND palm_id IS NULL',
  deleteMember: 'DELETE FROM members WHERE wallet_user_id = $1 AND member_id = $2 AND is_owner = false',

  insertInvite: `INSERT INTO invites (code, wallet_user_id, network, label, created_by, created_at, expires_at, status)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'open')`,
  inviteByCode: `SELECT * FROM invites WHERE code = $1`,
  openInvitesOf: `SELECT * FROM invites WHERE wallet_user_id = $1 AND status = 'open' AND expires_at > $2 ORDER BY created_at DESC`,
  useInvite: `UPDATE invites SET status = 'used', used_by = $1, used_at = $2 WHERE code = $3 AND status = 'open'`,
  cancelInvite: `UPDATE invites SET status = 'cancelled' WHERE code = $1 AND wallet_user_id = $2 AND status = 'open'`,
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
  // Only the asker's own earlier request is replaced: one signer cannot cancel another's by asking.
  openOperationOfKind: `SELECT * FROM operations WHERE wallet_user_id = $1 AND kind = $2 AND started_by = $3 AND status = 'collecting'
                        ORDER BY seq DESC LIMIT 1`,
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
  markUnlocked: 'UPDATE operations SET unlocked_at = $2 WHERE id = $1 AND unlocked_at IS NULL',
  setAuthorization: 'UPDATE operations SET human_authorization = $1 WHERE id = $2',
  setPsbt: 'UPDATE operations SET psbt = $1 WHERE id = $2',

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
  setDecision: 'UPDATE approvals SET decision_id = $1, decision_token = $3 WHERE id = $2',
  markAcked: 'UPDATE approvals SET acked = true WHERE id = $1',
};

const sha256 = value => crypto.createHash('sha256').update(value).digest('base64url');
const fmtSats = n => Number(n).toLocaleString('en-US');
// A short, stable name for one person's palm inside this vault, from their pairwise subject.
const palmId = sub => `PALM-${sha256(`palm:${sub}`).replace(/[-_]/g, '').slice(0, 12).toUpperCase()}`;

/**
 * The opaque identity that goes into an authorisation record.
 *
 * A digest of the pairwise Veyns subject, not the subject itself: a receipt may be exported
 * and read by someone who should learn which vault and which rules, and not who. One function
 * so the record and the check against it cannot compute it differently.
 */
const subjectOf = sub => (sub ? sha256Base64Url(`subject:${sub}`).slice(0, 22) : null);

/*
 * What a caller is told when a fact that must be durable could not be written.
 *
 * Deliberately a 503 and not a 409: nothing is wrong with the request, the system cannot
 * currently record what it would be doing, and the right response is to try again later.
 */
const UNRECORDABLE = 'This cannot proceed right now: the evidence log is unavailable, and an '
  + 'authorisation that cannot be recorded will not be acted on. Nothing has changed. Try again.';

/**
 * A database row as the entry its hash was taken over.
 *
 * The column names and the hashed field names differ, and this is the one place that knows
 * both — so a row read back hashes to exactly what was stored, which is what the verifier
 * relies on.
 */
const toEvidenceEntry = row => ({
  id: row.id,
  seq: Number(row.seq),
  at: Number(row.at),
  kind: row.kind,
  actor: row.actor ?? null,
  scope: row.scope ?? null,
  subjectKind: row.subject_kind ?? null,
  subjectId: row.subject_id ?? null,
  payload: JSON.parse(row.payload),
  prev: row.prev_hash,
  hash: row.hash,
});

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
    // Absent by default, and absent in an ordinary deployment. See `legacyVault()`.
    legacySeed = '',
    // What Vercel's scheduler sends as a bearer token, when CRON_SECRET is set. Optional: without
    // it the reminder run is still harmless, because it runs at most once an hour whoever asks.
    cronSecret = '',
    network = 'testnet4',
    chainApi = 'https://mempool.space/testnet4/api',
    requirePalmSignin = false,
    /*
     * Whether `x-forwarded-for` can be believed. True is right behind Vercel, which overwrites
     * the header; set it false for a deployment with no proxy in front, where the header is
     * whatever the caller typed. It only affects address-keyed limits — see src/rate-limit.js.
     */
    trustProxy = true,
    now = () => Math.floor(Date.now() / 1000),
    fetchImpl = globalThis.fetch,
    log = console,
  } = options;

  const clientId = options.clientId || '';
  let closed = false;
  let dbPromise = null;
  const database = () => {
    if (!databaseUrl && options.requireDatabaseUrl) {
      const seen = options.databaseCandidates?.length
        ? ` The deployment has ${options.databaseCandidates.join(', ')}, but none holds a postgres:// URL.`
        : ' This deployment has no database variable at all. Connect Neon to Production, then redeploy.';
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

  /*
   * The evidence log.
   *
   * IDEMPOTENCY. The key is the kind, the subject and a digest of the payload. The same
   * logical fact written twice — a retried request, a serverless invocation that ran the same
   * path again — lands once. A genuinely different fact about the same subject differs in its
   * payload and so lands separately.
   *
   * ORDERING. `prev_hash` is unique, so two concurrent appends cannot both claim the same
   * predecessor. The loser retries against the new head. No lock, no ambiguity about order.
   *
   * FAILURE. An append is awaited, and a failure is logged and swallowed rather than failing
   * the request. That is a deliberate trade and it has a visible consequence: a missing entry
   * leaves a gap a reader can see, because the taxonomy never lets a later fact imply an
   * earlier one. A payment with `signature.produced` and no `broadcast.accepted` reads as
   * "signed, outcome unrecorded" — which is the truth. The alternative, refusing to broadcast
   * because the log is unavailable, would make the audit trail an availability dependency for
   * spending; and for `broadcast.accepted` it would be useless anyway, since the transaction
   * is already on the network by then and cannot be taken back.
   */
  async function appendEvidence(kind, {
    actor = null, scope = null, subjectKind = null, subjectId = null, idempotencyKey = null,
    required = false, ...fields
  } = {}, q = null) {
    const run = q ?? query;
    const payload = redact(fields);
    const key = idempotencyKey
      ?? `${kind}:${subjectId ?? '-'}:${sha256Base64Url(canonicalJson(payload)).slice(0, 22)}`;

    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        const already = (await run('evidenceByKey', key)).rows[0];
        if (already) return { appended: false, hash: already.hash };

        const prev = (await run('evidenceHead')).rows[0]?.hash ?? GENESIS;
        const sealed = sealEntry({
          id: randomId(12), at: now(), kind, actor, scope, subjectKind, subjectId, payload, prev,
        });
        await run('appendEvidence', sealed.id, sealed.at, sealed.kind, sealed.actor, sealed.scope,
          sealed.subjectKind, sealed.subjectId, canonicalJson(sealed.payload), sealed.prev,
          sealed.hash, key);
        return { appended: true, hash: sealed.hash };
      } catch (error) {
        // A uniqueness conflict means somebody else appended first: read the new head and
        // try again. Anything else is not retryable.
        const conflict = /duplicate key|unique/i.test(String(error?.message ?? ''));
        if (!conflict || attempt === 3) {
          log.error(error);
          if (required) throw new HttpError(503, UNRECORDABLE);
          return { appended: false, hash: null, error: 'the evidence log could not be written' };
        }
      }
    }
    if (required) throw new HttpError(503, UNRECORDABLE);
    return { appended: false, hash: null, error: 'the evidence log is contended' };
  }

  // Security events. Field names are filtered against an allowlist in src/events.js, so a
  // secret cannot be written into one by mistake and an event cannot fail a request.
  const security = createSecurityLog({ log, now, sink: options.securitySink });

  /*
   * The scanner, of which there is one and it is the null one.
   *
   * It is wired in so that the state is reportable and the events below have somewhere real
   * to come from. It cannot report a pass, so no code path here can act on one.
   */
  const scanner = createScanner({ provider: options.scannerProvider });

  /*
   * The external checkpoint sink, and how much unanchored evidence this deployment tolerates.
   *
   * No sink by default. That is the weaker posture and it is reported as such — see
   * `anchorStatus` and CHECKPOINTING.md — rather than quietly treated as fine.
   */
  const sink = assertSink(options.anchorSink ?? createNullSink());
  const anchorPolicy = { ...ANCHOR_POLICY, ...(options.anchorPolicy ?? {}) };

  /**
   * Turns whatever a provider said into the right security event.
   *
   * One function rather than three call sites, so that when a provider exists that can
   * actually fail a check, the failure is already being recorded. Returns the verdicts so a
   * caller can decide, and decides nothing itself.
   */
  function recordScannerEvidence(evidence, context = {}) {
    const at = { ...context, provider: evidence?.provider ?? scanner.name };
    const pad = evidence?.pad?.result;
    const biometric = evidence?.biometric?.result;
    if (pad === SCANNER.FAILED) security.padFailure({ ...at, reason: 'liveness check did not pass' });
    if (biometric === SCANNER.FAILED) security.biometricFailure({ ...at, reason: 'no match' });
    if (pad === undefined || pad === SCANNER.NOT_AVAILABLE || biometric === SCANNER.NOT_AVAILABLE) {
      security.scannerUnavailable({ ...at, reason: scanner.getCapabilities().reason });
    }
    return { pad: pad ?? SCANNER.NOT_AVAILABLE, biometric: biometric ?? SCANNER.NOT_AVAILABLE };
  }

  const veyns = createVeyns({ issuer, getClientId: () => clientId, backendSecret, now, fetchImpl });
  const chain = createChain({ apiUrl: chainApi, fetchImpl });
  // One EVM chain client per network, built lazily from the network's config. An EVM account's
  // whole send lifecycle goes through this instead of `chain`, which is Bitcoin's.
  const evmChains = new Map();
  const isEvm = networkId => NETWORKS[networkId]?.family === 'evm';
  function evmChainFor(networkId) {
    if (!evmChains.has(networkId)) {
      const net = NETWORKS[networkId];
      if (!net?.rpc || !net.chainId) throw new HttpError(409, `${networkId} is not a configured EVM network.`);
      const base = typeof net.explorer === 'function' ? net.explorer('X').replace(/\/address\/X$/, '') : null;
      evmChains.set(networkId, createEvmChain({ rpcUrl: net.rpc, chainId: net.chainId, explorer: base, fetchImpl }));
    }
    return evmChains.get(networkId);
  }
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

  /*
   * The palm signer: the holder of every palm vault's palm key, and so the reason Bitcoin
   * itself refuses a palm vault spend that no palm approved.
   *
   * HERE, in this step, it runs inside this server and its seed is derived from WALLET_SEED.
   * That closes the gap it was built for — a stolen recovery phrase is no longer enough to
   * move a palm vault's coins, because the thief has the signer keys and not the palm key — but
   * a compromise of this server still reaches the palm key. Moving the signer into an attested
   * enclave, with the vault policy recorded there, is the next step and is not this one.
   *
   * Each vault's palm key is recorded on its account when the vault is made, and checked
   * against the signer before every use: if the seed ever changed, the signer would derive a
   * different key, and a spend is refused rather than signed for a vault it does not hold.
   *
   * Veyns' keys are fetched once per process and pinned for its life, so a decision is checked
   * against the keys the signer started with rather than against whatever is served later.
   */
  let palmSignerPromise = null;
  const palmSigner = () => {
    if (!walletSeed) return Promise.reject(new HttpError(503, 'The palm signer needs WALLET_SEED.'));
    palmSignerPromise ??= (async () => {
      let body;
      try {
        const response = await fetchImpl(`${issuer}/jwks.json`, { signal: AbortSignal.timeout(10_000) });
        if (!response.ok) throw new Error(`status ${response.status}`);
        body = await response.json();
      } catch {
        throw new HttpError(502, 'Could not load the Veyns signing keys for the palm signer.');
      }
      const seed = crypto.createHmac('sha256', walletSeed).update('quvault palm signer seed v1').digest();
      return createPalmSigner({
        seed, issuer, audience: clientId, pinnedKeys: body.keys ?? [], networkName: network, network: NETWORK, now,
      });
    })().catch(error => {
      palmSignerPromise = null;
      throw error;
    });
    return palmSignerPromise;
  };

  /*
   * Alerts: a nudge to a signer's phone or browser when something in a vault needs them.
   *
   * The push carries no content at all, so payment details never pass through the browser
   * makers' push services and a forged push can say nothing false: the notification only says
   * to open Palm, and what is there is what is true. Pushes go only to the browser makers' own
   * push services, never to an address a caller chose, so this cannot be turned into a way of
   * making this server call somewhere else. The VAPID key that signs them is derived from
   * WALLET_SEED, so there is nothing new to configure.
   */
  const PUSH_HOSTS = [/(^|\.)fcm\.googleapis\.com$/, /(^|\.)push\.services\.mozilla\.com$/, /(^|\.)push\.apple\.com$/, /(^|\.)notify\.windows\.com$/];
  const isPushEndpoint = value => {
    try {
      const url = new URL(String(value));
      return url.protocol === 'https:' && PUSH_HOSTS.some(host => host.test(url.hostname));
    } catch {
      return false;
    }
  };
  let vapidKeys = null;
  const vapid = () => {
    if (vapidKeys || !walletSeed) return vapidKeys;
    const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    const scalar = (BigInt(`0x${crypto.createHmac('sha256', walletSeed).update('quvault vapid key v1').digest('hex')}`) % (order - 1n)) + 1n;
    const d = Buffer.from(scalar.toString(16).padStart(64, '0'), 'hex');
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(d);
    const pub = ecdh.getPublicKey();
    vapidKeys = {
      publicKey: pub.toString('base64url'),
      key: crypto.createPrivateKey({
        key: { kty: 'EC', crv: 'P-256', d: d.toString('base64url'), x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') },
        format: 'jwk',
      }),
    };
    return vapidKeys;
  };

  /** Pushes an empty alert to every device these people turned alerts on for. Never throws. */
  async function pushTo(userIds) {
    try {
      const keys = vapid();
      if (!keys || !userIds.length) return;
      const subscriptions = await all('pushSubscriptionsOf', userIds);
      await Promise.allSettled(subscriptions.map(async sub => {
        if (!isPushEndpoint(sub.endpoint)) return;
        const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
        const input = `${b64({ typ: 'JWT', alg: 'ES256' })}.${b64({ aud: new URL(sub.endpoint).origin, exp: now() + 12 * 3600, sub: publicOrigin })}`;
        const signature = crypto.sign('sha256', Buffer.from(input), { key: keys.key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
        const response = await fetchImpl(sub.endpoint, {
          method: 'POST',
          headers: { TTL: '3600', Urgency: 'high', authorization: `vapid t=${input}.${signature}, k=${keys.publicKey}`, 'content-length': '0' },
          signal: AbortSignal.timeout(4000),
        });
        // Gone for good: the browser unsubscribed or the person cleared it.
        if (response.status === 404 || response.status === 410) await query('deletePushSubscription', sub.endpoint);
      }));
    } catch (error) {
      log.warn(`Alerts not sent: ${error.message}`);
    }
  }

  /** Alerts everyone on a vault's roster except the person who just acted. */
  async function alertOthers(ownerId, exceptUserId) {
    try {
      const members = await all('membersOf', ownerId);
      await pushTo(members.map(m => m.member_id).filter(id => id !== exceptUserId));
    } catch (error) {
      log.warn(`Alerts not sent: ${error.message}`);
    }
  }

  /*
   * A frozen vault refuses every approval, signature and send. Freezing takes no palm, so that it
   * is quick in an emergency; the worst a stolen session can do with it is stop payments, and
   * unfreezing takes the palms of the vault's signers.
   */
  async function assertNotFrozen(ownerId) {
    const wallet = await one('walletOf', ownerId);
    if (wallet?.frozen_at) {
      throw new HttpError(423, 'This vault is frozen, so nothing can be approved, signed or sent. Unfreezing it needs its signers’ palms.');
    }
  }

  /*
   * The capability to open a legacy wallet's private key, which is a different thing from the
   * capability to open an unlock secret even though the same bytes derive both.
   *
   * `legacySeed` is supplied separately — QUVAULT_LEGACY_SEED, not WALLET_SEED — and is absent
   * from an ordinary deployment. Where it is absent, no request can reach a legacy private
   * key at all, because there is nothing to open it with. Where it is present, a migration is
   * possible and the honest description is below.
   *
   * WHAT THIS IS NOT: when the variable is set on the web process, the capability lives in the
   * same process as every ordinary request handler. That is configuration, not isolation, and
   * this comment exists so nobody later reads `legacyVault()` as a sandbox. Real isolation
   * means running the migration from `scripts/migrate-legacy.js` with the variable set only
   * for that process, and never setting it on the web deployment.
   */
  let legacyKeys = null;
  const legacyVault = () => {
    if (!legacySeed) {
      throw new HttpError(409, 'Legacy custody migration is not enabled on this deployment. '
        + 'A vault whose key is held on the server can only be migrated by an operator running the '
        + 'migration command; nothing served here can open that key.');
    }
    if (!legacyKeys) {
      try {
        legacyKeys = serverKeys(legacySeed);
      } catch (error) {
        throw new HttpError(503, error.message);
      }
    }
    return legacyKeys;
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
  /*
   * No code from anywhere else runs on this page. Not a widget, not a frame, and not the
   * identity provider's own script: Veyns is talked to over fetch and a redirect, never by
   * loading its JavaScript here. A script on this origin could read the encrypted key out of
   * IndexedDB and the unlock secret as it arrives, so the party that verifies a palm must not
   * also be a party that can execute. `connect-src` still names the issuer, because exchanging
   * data with it is the point; exchanging code with it is not.
   */
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    `connect-src 'self' ${issuer}`,
    "img-src 'self' data:",
    "style-src 'self' https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com',
    "object-src 'none'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    // The installable-app pieces. Both fall back to default-src 'self' anyway; stated so a
    // browser that does not fall back still loads the manifest and registers the worker.
    "manifest-src 'self'",
    "worker-src 'self'",
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

  /**
   * A short, stable name for the rules that were in force.
   *
   * It is a digest of the sentence the approval screen shows — the approvers and the amount
   * ladder — so a record made under one set of rules cannot be read as having been made under
   * another. Changing who can approve, or how many palms a size needs, changes this value.
   */
  const policyVersionOf = (policy, members) => sha256Base64Url(describePolicy(policy, members)).slice(0, 22);

  /**
   * What the server says it authorised.
   *
   * The signer checks its request against this rather than against whatever the page happens
   * to pass it, so a page that asked for the wrong thing is refused by the signer and not
   * only by the server afterwards.
   */
  async function authorizationDescriptor(op, wallet, { accountId = 'bitcoin', transactionHash = null } = {}) {
    const [members, account] = await Promise.all([
      all('membersOf', op.wallet_user_id),
      one('accountOn', op.wallet_user_id, accountId),
    ]);
    return {
      authorizationId: op.id,
      walletId: wallet.address,
      accountId,
      chain: 'bitcoin',
      network,
      policyVersion: policyVersionOf(policyOfAccount(account, wallet), members),
      // Version 1: the palm decision is the evidence, and the transaction digest is what binds
      // it. When a scanner exists, version 2's bindingNonce comes from the capture instead.
      authorizationVersion: 1,
      bindingNonce: transactionHash,
    };
  }

  /**
   * What an account's coins are locked to today: the owner's single key, or the quorum the
   * chain keeps. Everything that plans, signs or checks a spend asks this, so there is one
   * answer to the question rather than one per call site.
   */
  const lockOfAccount = (account, wallet) => {
    if (account?.required && account.lock_kind === 'palm') {
      const publicKeys = JSON.parse(account.quorum_keys);
      const vault = palmVaultOf({
        palmKey: account.palm_key, signerKeys: publicKeys, required: account.required,
        delay: account.recovery_delay, network: NETWORK,
      });
      // The stored address and the one these keys make must be the same vault, or nothing here
      // can be trusted to describe where the coins are.
      if (vault.address !== account.address) throw new HttpError(500, 'This palm vault does not match its own keys.');
      return { kind: 'palm', address: account.address, publicKeys, required: account.required, vault };
    }
    return account?.required
      ? { kind: 'multisig', address: account.address, publicKeys: JSON.parse(account.quorum_keys), required: account.required }
      : { kind: 'single', address: wallet.address, publicKey: Buffer.from(wallet.public_key, 'hex'), required: null };
  };

  // The four things a spend does that depend on what the coins are locked to.
  const planFor = (lock, { utxos, toAddress, amountSats, feeRate }) => (lock.kind === 'palm'
    ? planPalmSpend({ vault: lock.vault, utxos, toAddress, amountSats, feeRate })
    : planSpend({ ...lock, utxos, toAddress, amountSats, feeRate }));
  const unsignedFor = (lock, plan) => (lock.kind === 'palm' ? palmVaultPsbt(lock.vault, plan) : psbtForPlan(lock, plan));
  const signersOn = (lock, psbt) => (lock.kind === 'palm'
    ? palmSignersOf(lock.vault, psbt, lock.publicKeys)
    : signersOfPsbt(psbt));
  const combineFor = (lock, psbts) => (lock.kind === 'palm' ? combinePalmPsbts(psbts) : combinePsbts(psbts));

  const signersOf = (account, members) => {
    const roster = members.map(m => m.member_id);
    const stored = account?.signers ? JSON.parse(account.signers) : null;
    const kept = (stored ?? roster).filter(id => roster.includes(id));
    return kept.length ? kept : roster;
  };

  /**
   * The people whose keys an account is locked to on the chain. Somebody can be on the roster
   * and not here: invited after the lock, they can approve changes but their key cannot sign
   * for these coins, so their palm must not count towards moving them either.
   */
  const keyHoldersOf = (account, members) => {
    const keys = account?.required ? JSON.parse(account.quorum_keys) : [];
    return members.filter(m => m.public_key && keys.includes(m.public_key));
  };

  /**
   * The vault a request is about. Your own by default. Someone else's only when its Bitcoin is
   * locked to the chain and your key is one of the ones it is locked to: then the chain needs
   * the same signatures and palms whoever asks, and asking is how the others carry on when the
   * owner can no longer.
   */
  async function signerVault(user, ownerId) {
    const id = String(ownerId || user.id);
    const [wallet, account, members] = await Promise.all([
      one('walletOf', id), one('accountOn', id, 'bitcoin'), all('membersOf', id),
    ]);
    if (!wallet) throw new HttpError(id === user.id ? 409 : 404, id === user.id ? 'Create the wallet first.' : 'Vault not found.');
    if (id !== user.id) {
      if (!members.some(m => m.member_id === user.id)) throw new HttpError(404, 'Vault not found.');
      if (!keyHoldersOf(account, members).some(m => m.member_id === user.id)) {
        throw new HttpError(403, 'Only someone whose key this vault is locked to can ask for that.');
      }
    }
    return { ownerId: id, wallet, account, members };
  }

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
    frozen: w.frozen_at ? { at: w.frozen_at, by: w.frozen_by } : null,
    // The public half of the owner's attestation key, and the lineage it descends from.
    // The server has never had the other half, and cannot extend the lineage itself.
    attestation: attestationView(w),
    // A legacy vault is described by what is true of it, not by the strength of the envelope
    // its key sits in. The server can open that envelope; that is the fact that matters.
    protection: w.custody === CUSTODY.BROWSER
      ? 'Key in the owner’s browser; its unlock secret sealed with ML-KEM-768 + X25519'
      : 'Legacy: the key is held on the server and can no longer spend. Move this vault into your browser.',
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
    // The Bitcoin key they sign with. Until this exists they can approve but not sign.
    signingKey: m.public_key || null,
    signingKeyAt: m.key_at || null,
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
    // Waiting for the palm of whoever is reading this: the one thing a dashboard must shout about.
    needsYou: op.status === 'collecting' && approvals.find(a => a.user_id === me?.id)?.status !== 'approved',
    txid: op.txid,
    error: op.error,
    // Whether a signed record of the human authorisation exists for this request.
    humanVerified: Boolean(op.human_authorization),
    // Present on an approved invitation: the code to pass to the person invited.
    inviteCode: op.kind === 'invite' && op.payload ? (JSON.parse(op.payload).code ?? null) : null,
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
    throw new HttpError(400, `Veyns refused the palm request both ways. ${refusals.join('; ')} `
      + 'Check that this account has its palm scanner connected and is admitted to the palm pilot.');
  }

  /** Ends operations whose quorum never arrived, or that were approved but never signed. */
  /*
   * Counting a request against its policy.
   *
   * FAILS OPEN, deliberately. If the count cannot be read, the request is allowed. A rate
   * limiter is there to protect availability, and one that refuses every request when its own
   * table is unreachable would be a new and worse outage than the one it prevents. It is not
   * an authorisation control — nothing here decides whether a caller may do something, only how
   * often — so failing open does not let anyone past a gate that was keeping them out.
   *
   * Throws HttpError 429 when the caller is over, carrying `retryAfter` so the response can say
   * when to come back.
   */
  let sweptLimitsAt = 0;
  async function enforceLimit(route, req, user) {
    const policy = route.limit;
    if (!policy) return;
    const key = policy.by === 'user' ? user?.id : clientAddress(req, { trustProxy });
    // A user-keyed policy on a route with no user must not silently count everyone together.
    if (!key) return;

    const time = now();
    const { bucket, expiresAt, retryAfter } = bucketFor({ policy, key, now: time });
    let hits;
    try {
      ({ hits } = (await query('bumpRateLimit', bucket, expiresAt)).rows[0]);
      // Housekeeping, at most once a window: expired rows are dead weight rather than a
      // correctness problem, so this is cheap and occasional instead of part of the hot path.
      if (time - sweptLimitsAt > policy.seconds) {
        sweptLimitsAt = time;
        await query('clearExpiredLimits', time);
      }
    } catch (error) {
      log.error(error);
      return;
    }
    if (!isOverLimit(Number(hits), policy)) return;

    // Recorded without the caller's address: an IP is personal data, and the policy name plus
    // the user, where there is one, is enough to act on.
    security.emit('request.rate_limited', {
      kind: policy.name,
      ...(policy.by === 'user' ? { userId: user.id } : {}),
      reason: `over ${policy.limit} requests in ${policy.seconds}s`,
    });
    throw Object.assign(new HttpError(429, refusalMessage(retryAfter)), { retryAfter });
  }

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

  /**
   * A shared vault must never move on a single palm. Once anyone else signs for an account, no
   * one approver can spend it or change it alone — whatever the amount rules or the on-chain
   * threshold say. This floor is a hard invariant, applied everywhere `required` is derived, so
   * it cannot be lowered by a policy, an amount, or a choice made at lock time.
   */
  const quorumFloor = signerCount => (signerCount > 1 ? 2 : 1);

  /** Who may approve for one account, and what a movement of `sats` from it needs. */
  async function quorumFor(walletOwnerId, networkId, sats) {
    const [wallet, members, account] = await Promise.all([
      one('walletOf', walletOwnerId), all('membersOf', walletOwnerId), one('accountOn', walletOwnerId, networkId),
    ]);
    const policy = policyOfAccount(account, wallet);
    const signers = signersOf(account, members);
    const { approvals, rule } = requiredFor(policy, sats);
    const required = Math.min(Math.max(1, signers.length), Math.max(approvals, quorumFloor(signers.length)));
    return { wallet, account, members, signers, policy, required, rule };
  }

  /** What it takes to change an account's signers or thresholds: its own quorum, as it stands now. */
  async function changeQuorum(walletOwnerId, networkId) {
    const { policy, signers, members, account, wallet } = await quorumFor(walletOwnerId, networkId, 0);
    let required = Math.min(Math.max(1, signers.length), Math.max(requiredToChange(policy, signers.length), quorumFloor(signers.length)));
    // Once the chain keeps the threshold, the people who could move every coin are the most any
    // change can ask for. Asking for more would let one signer who has died block the others
    // from replacing them, and protects nothing those same people could not take anyway.
    if (account?.required) required = Math.min(required, Math.max(account.required, quorumFloor(signers.length)));
    return { required, policy, signers, members, account, wallet };
  }

  async function newOperation({ walletOwnerId, user, kind, statement, details, payload = null, required = 1, networkId = null }) {
    // Nothing new starts in a frozen vault, except the request to unfreeze it.
    if (!['create', 'unfreeze'].includes(kind)) await assertNotFrozen(walletOwnerId);
    const id = randomId(16);
    const time = now();
    const replaced = await transaction(async q => {
      const previous = (await q('openOperationOfKind', walletOwnerId, kind, user.id)).rows[0];
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
    // Everyone else on the vault hears that something was asked for, whoever asked.
    if (!['create', 'signing'].includes(kind)) await alertOthers(walletOwnerId, user.id);
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
      if (!person) throw new HttpError(400, `No one has the approver code "${code}". They must sign in to Veyns once first.`);
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

  /**
   * The only function in this codebase that opens a legacy private key, and the only thing
   * that key is still permitted to do.
   *
   * It cannot send an amount, because there is no amount to choose: it sweeps everything to
   * one address and leaves nothing behind. It cannot pick outputs, set a change address or
   * be handed a plan from anywhere else — the plan is built here, from the chain's own view
   * of the vault, immediately before signing. So the worst a compromised caller can do is
   * empty a legacy vault to an address that a completed palm approval already named, which
   * is what both of its callers are for.
   *
   * There is deliberately no path from a withdrawal to this function. A legacy vault that
   * wants to spend an amount has to move into a browser first.
   */
  /**
   * Proves that a legacy sweep was really authorised, before anything opens a key.
   *
   * A row in the operations table is not evidence. Somebody who can write to this database can
   * write `status = 'done'`, invent approvals and choose the statement — so none of those
   * things is trusted here on its own:
   *
   *   1. The operation's digest is recomputed from its own statement and details. A row whose
   *      statement was edited no longer hashes to its digest.
   *   2. The quorum is recomputed from the policy, rather than read from `op.required`, so a
   *      row claiming it needed one approval cannot lower the bar.
   *   3. Every approval is re-checked against Veyns itself: the decision must exist there, be
   *      approved, and name this exact action digest. Forging this means forging Veyns, not
   *      forging a row.
   *
   * Together these mean a database writer cannot cause a legacy key to be opened. They would
   * also need the palm decisions to exist upstream, for an action digest that covers the
   * statement the owner actually read.
   */
  async function assertSweepAuthorization(op, wallet) {
    if (!op || op.wallet_user_id !== wallet.user_id) throw new HttpError(409, 'That approval is for another vault.');
    if (op.kind !== 'upgrade' && op.kind !== 'reset') throw new HttpError(409, 'That kind of request cannot move a legacy vault.');
    if (op.status !== 'done') throw new HttpError(409, 'That request has not been approved.');

    // 1. The row still hashes to what the palm was asked about.
    let details;
    try {
      details = JSON.parse(op.details);
    } catch {
      throw new HttpError(409, 'That request is not readable.');
    }
    if (actionDigest(op.statement, details) !== op.digest) {
      throw new HttpError(409, 'That request has been altered since it was approved.');
    }

    // 2. How many palms this actually needed, computed now from the rules.
    const { required } = await changeQuorum(wallet.user_id, 'bitcoin');
    const approvals = (await all('approvalsOf', op.id)).filter(a => a.status === 'approved');
    if (approvals.length < required) {
      throw new HttpError(409, `This needs ${required} palm approval${required === 1 ? '' : 's'} and has ${approvals.length}.`);
    }

    // 3. Veyns has to agree that each of those decisions happened, for this action.
    for (const approval of approvals) {
      if (!approval.request_id || !approval.decision_id) {
        throw new HttpError(409, 'An approval on this request names no palm decision.');
      }
      let remote;
      try {
        remote = await veyns.backend(`/v1/approvals/${encodeURIComponent(approval.request_id)}`);
      } catch (error) {
        // Unreachable is not the same as refused: do not open a key on an unverified approval.
        throw new HttpError(502, `The palm decisions could not be re-checked with Veyns (${error.message}).`);
      }
      if (remote?.status !== 'approved') throw new HttpError(409, 'Veyns does not record that approval as granted.');
      if (remote?.action?.digest !== op.digest) throw new HttpError(409, 'That palm decision was for a different action.');
    }
    return { details, approvals: approvals.length, required };
  }

  async function sweepLegacyVault(wallet, { toAddress, reason, pendingMessage, operation }) {
    if (wallet?.custody !== CUSTODY.LEGACY || !wallet.sealed_key) {
      throw new HttpError(409, 'This vault signs in the owner’s browser. The server holds no key for it.');
    }
    if (!isValidAddress(toAddress)) throw new HttpError(400, `That is not a valid ${network} address.`);
    // Nothing below this line runs on an unproven authorisation.
    await assertSweepAuthorization(operation, wallet);
    try {
      const [balance, utxos, feeRate] = await Promise.all([
        chain.balance(wallet.address), chain.spendableUtxos(wallet.address), chain.feeRate(),
      ]);
      // An unconfirmed coin cannot be spent yet, and this key is about to stop existing.
      if (balance.pending > 0) throw new HttpError(409, pendingMessage);
      if (!utxos.length) return { txid: null, sweptSats: 0 };

      const publicKey = Buffer.from(wallet.public_key, 'hex');
      const plan = planSpend({ publicKey, utxos, toAddress, amountSats: 'max', feeRate });
      const privateKey = openSealed(wallet.sealed_key, legacyVault());
      let hex;
      try {
        hex = signPlan({ privateKey, publicKey, plan }).hex;
      } finally {
        privateKey.fill(0);
      }
      const txid = await chain.broadcast(hex);
      security.migration({
        vaultId: wallet.address, address: toAddress, txid, sats: plan.sentSats,
        custody: CUSTODY.LEGACY, reason, outcome: 'swept',
      });
      await appendEvidence(EVIDENCE.CUSTODY_MIGRATION, {
        subjectKind: 'wallet', subjectId: wallet.address,
        vaultId: wallet.address, address: toAddress, txid, sats: plan.sentSats,
        custody: CUSTODY.LEGACY, reason, outcome: 'swept', network, chain: 'bitcoin',
      });
      log.log(`legacy vault ${wallet.address} swept to ${toAddress} (${reason}) in ${txid}`);
      return { txid, sweptSats: plan.sentSats };
    } catch (error) {
      if (error instanceof HttpError) throw error;
      if (error instanceof ChainError || error instanceof WalletError) {
        throw new HttpError(409, `The coins could not be moved: ${error.message}`);
      }
      throw error;
    }
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
      /*
       * Checked only when the record carries them, so a version 1 receipt still verifies
       * exactly as it did. A version 2 record that names a different proposal, policy, chain
       * or network — or claims a threshold the rules did not ask for — is refused here rather
       * than merely read back later.
       *
       * These come from `authorizationDescriptor`, the same function that tells the browser
       * what it is signing, so the statement and the check cannot drift apart.
       */
      ...(({ walletId, authorizationVersion, bindingNonce, authorizationId, ...rest }) => rest)(
        await authorizationDescriptor(op, wallet, { transactionHash: bound.digest })),
      proposalId: op.id,
      threshold: op.required,
      subject: subjectOf((await one('userById', op.wallet_user_id))?.sub),
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
      if (op.kind === 'withdraw' || op.kind === 'lock') {
        const wallet = await one('walletOf', op.wallet_user_id);
        // With the key in the owner's browser, the quorum is complete but the signing is not:
        // the operation waits, and the owner's device signs and sends it. A lock with nothing
        // to move has no transaction to wait for, so it simply happens.
        //
        // "Moving" means there is a transaction for the browser to sign — a Bitcoin plan has
        // `inputs`, and an EVM withdrawal is an account-chain transfer (`chain === 'evm'`).
        // Without the EVM arm an EVM withdrawal would be marked done here, before it was ever
        // signed, and the broadcast would then be refused as "not running".
        const stored = op.payload ? JSON.parse(op.payload) : null;
        const moving = Boolean(stored && (stored.inputs || stored.chain === 'evm' || stored.chain === 'evm-palm'));
        if (wallet?.custody === CUSTODY.BROWSER && moving) return;
        // Nothing else may move coins here. A legacy vault used to be signed for at this
        // point, by the server, with the key it was holding; that path is gone, and both of
        // the ways a legacy vault can still move its money are palm-approved sweeps.
        if (moving) {
          throw new HttpError(409, 'This vault was made before keys lived in the browser and can no longer '
            + 'spend from the server. Move it into your browser first; every coin comes with it.');
        }
        if (op.kind === 'lock' && !moving) {
          await lockAccount(op);
          await query('finishOperation', 'done', null, null, time, op.id);
          return;
        }
        if (op.kind === 'withdraw' && stored?.move) {
          await applyMove(op);
          await query('finishOperation', 'done', null, null, time, op.id);
          return;
        }
      }
      const { txid } = op.kind === 'create' ? await createWallet(op, decisionId)
        : op.kind === 'policy' ? await applyPolicy(op)
        // Recovery and new accounts do nothing here: finishing them lets the owner's device
        // open the phrase, or derive the new network's address.
        : op.kind === 'invite' ? await issueInvite(op)
        : op.kind === 'join' ? await acceptInvite(op)
        : op.kind === 'address' ? await saveAddressName(op)
        : op.kind === 'unfreeze' ? await unfreeze(op)
        : op.kind === 'upgrade' ? await prepareUpgrade(op)
        // Erasing happens when the owner's browser confirms it, so the key is cleared there too.
        : op.kind === 'reset' ? { txid: null }
        : ['recovery', 'account', 'attestation', 'signing'].includes(op.kind) ? { txid: null }
        // Withdrawals and locks are signed in the owner's browser and returned above. There is
        // no remaining kind of operation that this server can sign for.
        : { txid: null };
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
      // Bitcoin palm vaults: the palm signer runs here, so it needs the seed and the Veyns backend.
      palmVault: Boolean(walletSeed && backendSecret),
      recoveryChoices: RECOVERY_CHOICES,
      // The account that pays the network fee for Palm Wallets on Ethereum and BSC. Its address only.
      gasAccount: gasAccount()?.address ?? null,
      // The key browsers check alerts against. Public by design; the private half derives from WALLET_SEED.
      vapidPublicKey: vapid()?.publicKey ?? null,
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

    /*
     * A spend from an account the chain guards is not finished when the palms are in: it
     * still needs this person's signature. The view says how many have been collected and
     * whether one of them should be theirs, so nobody is left looking at a request that is
     * waiting for them without being told.
     */
    const withApprovals = async op => {
      const approvals = await all('approvalsOf', op.id);
      const view = operationView(op, approvals, user);
      if (op.kind === 'withdraw' && op.status === 'running' && isEvm(op.network)) {
        const evmAccount = await one('accountOn', op.wallet_user_id, op.network);
        if (evmAccount?.lock_kind !== 'palm' || !evmAccount.required) return view;
        const signed = Object.keys(collectedOf(op));
        const member = await one('memberIn', op.wallet_user_id, user.id);
        const approved = approvals.some(a => a.user_id === user.id && a.status === 'approved');
        view.signatures = { done: signed.length, required: evmAccount.required };
        view.needsSignature = Boolean(approved && member?.public_key
          && JSON.parse(evmAccount.quorum_keys).includes(member.public_key)
          && !signed.includes(evmAddressOfPublicKey(member.public_key)));
        view.needsYou = view.needsYou || view.needsSignature;
        return view;
      }
      if (op.kind !== 'withdraw' || op.status !== 'running') return view;
      const account = await one('accountOn', op.wallet_user_id, 'bitcoin');
      if (!account?.required) return view;

      const plan = JSON.parse(op.payload);
      const lock = lockOfAccount(account);
      const signed = signersOn(lock, op.psbt || unsignedFor(lock, plan));
      const member = await one('memberIn', op.wallet_user_id, user.id);
      const approved = approvals.some(a => a.user_id === user.id && a.status === 'approved');
      view.signatures = { done: signed.length, required: account.required };
      view.needsSignature = Boolean(
        approved && member?.public_key
        && JSON.parse(account.quorum_keys).includes(member.public_key)
        && !signed.includes(member.public_key),
      );
      view.needsYou = view.needsYou || view.needsSignature;
      return view;
    };
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
      addressBook: (await all('addressBookOf', user.id)).map(a => ({ network: a.network, address: a.address, name: a.name, addedAt: a.added_at })),
      signsFor: (await Promise.all(visible.filter(id => id !== user.id).map(id => signedVaultView(id, user)))).filter(Boolean),
      alerts: (await one('pushCountOf', user.id)).n,
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
   *
   * One approval opens the key once. The window starts when the key is first opened and
   * cannot be restarted, so trying again a moment later is the same opening — a retry after
   * a broadcast that did not land — while the request never becomes a standing permission.
   * A request that has sent its transaction is finished with the key for good.
   */
  async function unlockFor({ user, params: [id] }) {
    const op = await ownOperation(id, user);
    await assertNotFrozen(op.wallet_user_id);
    // Spending from an account the chain guards is signed by each signer in turn, with their
    // own key. Owner or not, what comes back is that person's key and the transaction the
    // quorum is collecting — never the owner's key standing in for everybody's.
    if (op.kind === 'withdraw' && isEvm(op.network)) {
      const evmAccount = await one('accountOn', op.wallet_user_id, op.network);
      if (evmAccount?.lock_kind === 'palm' && evmAccount.required) return palmWalletUnlock(op, evmAccount, user);
    } else if (op.kind === 'withdraw') {
      const account = await one('accountOn', op.wallet_user_id, 'bitcoin');
      if (account?.required) return quorumUnlock(op, account, user);
    }
    if (op.wallet_user_id !== user.id) throw new HttpError(403, 'Only the account owner can unlock this wallet.');
    if (!['create', 'withdraw', 'recovery', 'account', 'upgrade', 'attestation', 'signing', 'lock'].includes(op.kind)) {
      throw new HttpError(409, 'Nothing to unlock for this request.');
    }
    if (!['running', 'done'].includes(op.status)) throw new HttpError(409, 'This request is still collecting palm approvals.');

    const time = now();
    const spent = 'That approval has been used. Ask for a new palm scan.';
    if (op.txid) throw new HttpError(409, spent);
    if (time > op.expires_at + UNLOCK_SECONDS) throw new HttpError(409, spent);
    if (op.unlocked_at && time > op.unlocked_at + UNLOCK_SECONDS) throw new HttpError(409, spent);
    await query('markUnlocked', op.id, time);

    const wallet = await one('walletOf', user.id);
    if (op.kind === 'create') {
      if (wallet) throw new HttpError(409, 'This account already has a wallet.');
      const payload = JSON.parse(op.payload);
      return { unlock: openSealed(payload.unlockSealed, vault()).toString('base64'), salt: payload.salt, label: payload.label };
    }
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    if (op.kind === 'upgrade') {
      // The secret for the key this browser is about to make, not the one being retired.
      if (wallet.custody === CUSTODY.BROWSER) throw new HttpError(409, 'This vault already lives in your browser.');
      const payload = JSON.parse(op.payload);
      return { unlock: openSealed(payload.unlockSealed, vault()).toString('base64'), salt: payload.salt };
    }
    if (wallet.custody !== CUSTODY.BROWSER) throw new HttpError(409, 'This wallet signs on the server.');
    // An EVM withdrawal unlocks to a transfer and a derivation path, not a UTXO plan.
    if ((op.kind === 'withdraw' || (op.kind === 'lock' && op.payload && JSON.parse(op.payload).chain === 'evm')) && isEvm(op.network)) {
      return evmWithdrawalUnlock(op, wallet);
    }
    return {
      unlock: openSealed(wallet.unlock_sealed, vault()).toString('base64'),
      salt: wallet.salt,
      ...(['withdraw', 'lock'].includes(op.kind) && op.payload && JSON.parse(op.payload).inputs
        ? await withdrawalUnlock(op, wallet) : {}),
    };
  }

  /** When the last palm a request needed landed, which is when there was anything to sign. */
  const signableAt = (op, approvals) => {
    const times = approvals
      .filter(a => a.status === 'approved')
      .map(a => a.closed_at ?? a.created_at)
      .sort((a, b) => a - b);
    return times[op.required - 1] ?? times.at(-1) ?? 0;
  };

  /**
   * What one signer's browser needs to add its signature: their own key, which only their own
   * palm opens, and the transaction the quorum is collecting.
   *
   * The window here runs from the moment the request became signable — when the last palm it
   * needed landed — and not from the first opening of the key. A quorum's approvals arrive
   * hours apart, and whoever approved first would otherwise find their window long gone by
   * the time there was anything to sign.
   */
  async function quorumUnlock(op, account, user) {
    if (!['running', 'done'].includes(op.status)) {
      throw new HttpError(409, 'This request is still collecting palm approvals.');
    }
    if (op.txid) throw new HttpError(409, 'That transaction has already been sent.');

    const member = await one('memberIn', op.wallet_user_id, user.id);
    const keys = JSON.parse(account.quorum_keys);
    if (!member?.public_key || !keys.includes(member.public_key)) {
      throw new HttpError(403, 'Your key is not one of the ones this account is locked to.');
    }
    const approvals = await all('approvalsOf', op.id);
    const approval = approvals.find(a => a.user_id === user.id && a.status === 'approved');
    if (!approval) throw new HttpError(409, 'Put your palm to this request first.');
    if (now() > signableAt(op, approvals) + UNLOCK_SECONDS) {
      throw new HttpError(409, 'That approval has been used. Ask for a new palm scan.');
    }

    const mine = await one('walletOf', user.id);
    if (mine?.custody !== CUSTODY.BROWSER) throw new HttpError(409, 'Move your own vault into this browser first.');
    const plan = JSON.parse(op.payload);
    return {
      // The signer for a quorum share checks against the same descriptor, but the wallet it
      // names is the signer's own — this person signs with their key, not the owner's.
      ...await authorizationDescriptor(op, mine, { transactionHash: plan.transactionHash }),
      unlock: openSealed(mine.unlock_sealed, vault()).toString('base64'),
      salt: mine.salt,
      keyIndex: member.key_index,
      signingKey: member.public_key,
      psbt: op.psbt || unsignedFor(lockOfAccount(account), plan),
      plan,
      address: account.address,
      transactionHash: plan.transactionHash,
      required: account.required,
      signatures: signersOn(lockOfAccount(account), op.psbt || unsignedFor(lockOfAccount(account), plan)).length,
      // A palm vault spend is signed through a Taproot script, which the browser reads differently.
      lockKind: lockOfAccount(account).kind,
    };
  }

  /** What the owner's device needs to sign the transaction and to attest to the approval. */
  async function withdrawalUnlock(op, wallet) {
    const expected = await expectedAuthorization(op, wallet);
    const owner = await one('userById', op.wallet_user_id);
    return {
      ...await authorizationDescriptor(op, wallet, { transactionHash: expected.transactionHash }),
      plan: JSON.parse(op.payload),
      address: wallet.address,
      transactionHash: expected.transactionHash,
      statementDigest: expected.statementDigest,
      approvals: expected.approvals,
      approvedBy: expected.approvedBy,
      decisionIds: expected.decisionIds,
      attestationEpoch: expected.keyEpoch,
      /*
       * The institutional fields a version 2 receipt needs. Sent so the browser signs a record
       * that can establish its own policy and threshold; a version 1 record cannot, which is
       * finding F1 of the Phase A report.
       *
       * `threshold` is what the rules asked for, as an integer. `subject` is the opaque
       * per-application identity of the vault owner — never a name or an email.
       */
      proposalId: op.id,
      threshold: op.required,
      subject: subjectOf(owner?.sub),
      expiresAt: op.expires_at,
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
    await assertNotFrozen(op.wallet_user_id);
    if (op.wallet_user_id !== user.id) throw new HttpError(403, 'Only the account owner can send this.');
    if (op.kind !== 'withdraw' && op.kind !== 'lock') throw new HttpError(409, 'That request does not send a transaction.');
    if (op.status === 'done' && op.txid) return { txid: op.txid };
    if (op.status !== 'running') throw new HttpError(409, 'This withdrawal is not ready to send.');

    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    // An EVM withdrawal runs the same three gates on the account-chain path.
    if (isEvm(op.network)) return evmBroadcast({ op, user, wallet, body });

    // A shared vault must be locked to the chain to spend. A withdrawal planned while the vault
    // was still solo cannot be finished once a co-signer has joined — the door check at request
    // time cannot catch that one, so it is refused here too. Locking (op.kind 'lock') is exempt,
    // because locking is how a shared vault stops being spendable by one key.
    if (op.kind === 'withdraw') {
      const acct = await one('accountOn', user.id, 'bitcoin');
      if (!acct?.required && signersOf(acct, await all('membersOf', user.id)).length > 1) {
        throw new HttpError(409, 'This vault now has more than one signer. Lock it to the chain before sending.');
      }
    }

    const plan = JSON.parse(op.payload);

    const event = { operationId: op.id, userId: user.id, vaultId: wallet.address, kind: op.kind, network, chain: 'bitcoin', custody: wallet.custody };
    security.signingAttempt(event);
    const asEvidence = { actor: user.id, subjectKind: 'operation', subjectId: op.id };
    await appendEvidence(EVIDENCE.AUTHORIZATION_ATTEMPTED, { ...asEvidence, ...event });

    // 1. The plan on disk is still the transaction that was approved.
    const bound = bindPlan(wallet, plan);
    if (bound.digest !== plan.transactionHash || bound.digest !== JSON.parse(op.details).transaction_hash) {
      security.digestMismatch({ ...event, digestExpected: JSON.parse(op.details).transaction_hash, digestOffered: bound.digest });
      security.signingRejected({ ...event, reason: 'stored transaction no longer matches the approval' });
      await appendEvidence(EVIDENCE.DIGEST_MISMATCH, {
        ...asEvidence, ...event,
        digestExpected: JSON.parse(op.details).transaction_hash, digestOffered: bound.digest,
      });
      await appendEvidence(EVIDENCE.AUTHORIZATION_REJECTED, {
        ...asEvidence, ...event, reason: 'stored transaction no longer matches the approval',
      });
      throw new HttpError(409, 'The stored transaction no longer matches the one that was approved.');
    }
    // 2. The owner's own key attested to that approval, for this exact transaction.
    //    This server cannot produce this record: it holds only the public half of that key.
    if (wallet.custody === CUSTODY.BROWSER) {
      const expected = await expectedAuthorization(op, wallet);
      const authorization = body.authorization ?? authorizationOf(op);
      const lineage = attestationOf(wallet);
      if (!lineage.ok) {
        security.authorizationFailure({ ...event, reason: lineage.reason });
        security.signingRejected({ ...event, reason: 'no valid attestation key' });
        await appendEvidence(EVIDENCE.AUTHORIZATION_REJECTED, {
          ...asEvidence, ...event, reason: 'no valid attestation key',
        });
        throw new HttpError(409, `This vault has no valid attestation key: ${lineage.reason}.`);
      }
      const checkedAuthorization = verifyAuthorization(authorization, lineage.publicKey, expected);
      if (!checkedAuthorization.ok) {
        // The reason is written by verifyAuthorization, not by the caller, so it is safe text.
        security.authorizationFailure({ ...event, reason: checkedAuthorization.reason, keyEpoch: lineage.epoch });
        security.signingRejected({ ...event, reason: 'authorisation did not verify' });
        await appendEvidence(EVIDENCE.AUTHORIZATION_REJECTED, {
          ...asEvidence, ...event, reason: checkedAuthorization.reason, keyEpoch: lineage.epoch,
        });
        throw new HttpError(409, `No valid human authorisation for this transaction: ${checkedAuthorization.reason}.`);
      }
      if (!op.human_authorization) await query('setAuthorization', JSON.stringify(authorization), op.id);
      /*
       * Granted is its own fact, recorded before anything is sent. What the record claims
       * about a sensor is carried verbatim — 'none' in this build — so a reader is never left
       * to assume a palm was measured. See requirement 5 of the evidence phase.
       */
      /*
       * REQUIRED. Nothing irreversible has happened yet, so if this cannot be recorded the
       * right answer is to refuse and let the caller retry. A high-value transaction must
       * never be broadcast without durable evidence of the authorisation and the policy that
       * permitted it, and this is the first of the three gates that guarantees it.
       */
      await appendEvidence(EVIDENCE.AUTHORIZATION_GRANTED, {
        ...asEvidence, ...event, required: true,
        transactionHash: bound.digest,
        receiptVersion: authorization?.record?.v ?? null,
        policyVersion: authorization?.record?.policyVersion ?? null,
        threshold: authorization?.record?.threshold ?? null,
        approvalCount: authorization?.record?.approvalCount ?? null,
        keyEpoch: lineage.epoch,
        // Who approved, and which palm decisions settled it — opaque identifiers, so the log
        // records that a quorum happened AND who was in it, which is what makes it auditable.
        approvedBy: expected.approvedBy,
        decisionIds: expected.decisionIds,
        sensorEvidence: authorization?.record?.verification?.sensorEvidence ?? 'none',
        verification: 'verified',
      });
    }
    // 3. The signed bytes spend the approved coins, pay the approved outputs, at the approved fee.
    let checked;
    try {
      checked = verifyAgainstPlan(String(body.hex ?? ''), plan);
    } catch (error) {
      if (error instanceof WalletError) {
        security.signingRejected({ ...event, reason: 'signed bytes do not match the approved plan' });
        await appendEvidence(EVIDENCE.AUTHORIZATION_REJECTED, {
          ...asEvidence, ...event, reason: 'signed bytes do not match the approved plan',
        });
        throw new HttpError(400, error.message);
      }
      throw error;
    }
    try {
      /*
       * REQUIRED. A signature that has not been sent is inert, so refusing here loses nothing
       * — the caller retries and signs again. Once the network has it, that stops being true,
       * which is why both of these are written before the broadcast and not after.
       */
      await appendEvidence(EVIDENCE.SIGNATURE_PRODUCED, {
        ...asEvidence, ...event, required: true,
        transactionHash: bound.digest, isolation: 'none:browser-javascript',
      });
      /*
       * REQUIRED, and the last durable fact before the irreversible step. It carries the txid,
       * which is known here because verifying the signed bytes against the plan yields it —
       * that is what makes an uncertain outcome reconcilable rather than merely unknown.
       */
      await appendEvidence(EVIDENCE.BROADCAST_ATTEMPTED, {
        ...asEvidence, ...event, required: true,
        txid: checked.txid, transactionHash: bound.digest,
      });
      const txid = await chain.broadcast(String(body.hex).trim());
      // The account only becomes a quorum once its coins are actually on their way to one,
      // so a lock that could not be sent leaves everything exactly as it was.
      if (op.kind === 'lock') await lockAccount(op);
      await query('finishOperation', 'done', txid, null, now(), op.id);
      security.signingSuccess({ ...event, txid, transactionHash: bound.digest, isolation: 'none:browser-javascript' });
      /*
       * NOT required, and it cannot be: by the time this runs the transaction is on the
       * network and no refusal here can recall it. If the write fails the log shows an attempt
       * with no outcome, which `reconcileBroadcast` resolves by asking the chain — see
       * EVIDENCE.md. That is the honest handling of an irreversible step.
       */
      await appendEvidence(EVIDENCE.BROADCAST_ACCEPTED, {
        ...asEvidence, ...event, txid, transactionHash: bound.digest,
      });
      return { txid };
    } catch (error) {
      if (!(error instanceof ChainError)) throw error;
      await query('finishOperation', 'failed', null, error.message, now(), op.id);
      security.signingRejected({ ...event, reason: 'the network would not take the transaction' });
      await appendEvidence(EVIDENCE.BROADCAST_REFUSED, {
        ...asEvidence, ...event, reason: 'the network would not take the transaction',
      });
      throw new HttpError(502, error.message);
    }
  }

  /*
   * One signer's signature, added to what the quorum has collected so far.
   *
   * The transaction the signatures gather on is rebuilt here from the stored plan every time,
   * so a signature can only ever be collected for the transaction the palms approved. What a
   * browser sends is compared against what was already there, and the only thing it is allowed
   * to have added is a signature from its own key: nobody can put words in another signer's
   * mouth, and nobody can reach the threshold on their own.
   *
   * This server can put signatures together. It cannot make one, because no signer's key is
   * here — which is the whole point of moving the threshold onto the chain.
   */
  /**
   * The palm key's signature on a palm vault spend that has all its signers.
   *
   * The palm signer is handed Veyns' own signed decisions and the transaction itself. It reads
   * what is being spent out of the transaction, recomputes the digest the palms approved, and
   * checks each decision with Veyns' key; this server's record that the palms happened is not
   * part of what it relies on. If it refuses, nothing is signed and nothing is sent.
   */
  async function palmFinish(op, account, lock, psbt, approvals) {
    const signer = await palmSigner();
    if (signer.publicKeyFor(account.palm_vault_id) !== account.palm_key) {
      throw new HttpError(409, 'The palm signer no longer holds this vault\'s palm key. Nothing was signed.');
    }
    const decisions = approvals
      .filter(a => a.status === 'approved' && !a.invalidated_at && a.decision_token)
      .map(a => a.decision_token);
    // The Veyns subjects of the people whose keys this vault is locked to, in both forms Veyns
    // uses. Nobody else's palm counts towards moving these coins.
    const subjects = [];
    for (const { member_id: memberId } of keyHoldersOf(account, await all('membersOf', op.wallet_user_id))) {
      const person = await one('userById', memberId);
      // One person, in both forms Veyns may name them by: they count once, however named.
      if (person?.sub) subjects.push([person.sub, approvalSubject(person.sub)]);
    }
    let signed;
    try {
      signed = signer.sign({
        vaultId: account.palm_vault_id,
        policy: { signerKeys: lock.publicKeys, required: lock.required, delay: account.recovery_delay, signerSubs: subjects },
        psbt,
        action: { statement: op.statement, details: JSON.parse(op.details) },
        decisions,
      });
    } catch (error) {
      if (error instanceof PalmRefused) throw new HttpError(409, `The palm key refused to sign: ${error.message}.`);
      throw error;
    }
    await query('setPsbt', signed.psbt, op.id);
    return finalizePalmPsbt(lock.vault, signed.psbt);
  }

  async function addSignature({ user, params: [id], body }) {
    const op = await ownOperation(id, user);
    await assertNotFrozen(op.wallet_user_id);
    if (op.kind !== 'withdraw') throw new HttpError(409, 'That request is not a withdrawal.');
    if (op.status === 'done' && op.txid) return { txid: op.txid, signatures: op.required, required: op.required };
    if (op.status !== 'running') throw new HttpError(409, 'This withdrawal is not ready to sign.');
    if (isEvm(op.network)) return palmWalletSignature(op, user, body);

    const account = await one('accountOn', op.wallet_user_id, 'bitcoin');
    if (!account?.required) throw new HttpError(409, 'That account is not spent by signatures.');
    const member = await one('memberIn', op.wallet_user_id, user.id);
    const keys = JSON.parse(account.quorum_keys);
    if (!member?.public_key || !keys.includes(member.public_key)) {
      throw new HttpError(403, 'Your key is not one of the ones this account is locked to.');
    }
    const approvals = await all('approvalsOf', op.id);
    if (!approvals.some(a => a.user_id === user.id && a.status === 'approved')) {
      throw new HttpError(409, 'Put your palm to this request first.');
    }

    const plan = JSON.parse(op.payload);
    const lock = lockOfAccount(account);
    const bound = bindPlan(lock, plan);
    if (bound.digest !== plan.transactionHash || bound.digest !== JSON.parse(op.details).transaction_hash) {
      throw new HttpError(409, 'The stored transaction no longer matches the one that was approved.');
    }

    const base = unsignedFor(lock, plan);
    const before = signersOn(lock, op.psbt || base);
    // A palm vault spend whose signers are all in, asked again after the palm signer said no
    // (Veyns unreachable, say): nothing more to add, so go straight back to the palm signer.
    const retry = lock.kind === 'palm' && before.length >= account.required;
    let merged = op.psbt || base;
    if (!retry) {
      try {
        merged = combineFor(lock, [base, op.psbt, String(body.psbt ?? '')].filter(Boolean));
      } catch (error) {
        throw new HttpError(400, error instanceof WalletError ? error.message : 'That signature is not for this transaction.');
      }
      const added = signersOn(lock, merged).filter(key => !before.includes(key));
      if (added.length !== 1 || added[0] !== member.public_key) {
        throw new HttpError(400, added.length ? 'A browser may only add a signature from its own key.' : 'That added no signature.');
      }
      await query('setPsbt', merged, op.id);
    }

    const signatures = retry ? before.length : before.length + 1;
    if (signatures < account.required) return { signatures, required: account.required, txid: null };

    // Enough of them. The finished transaction is checked against the approved plan exactly as
    // a single-key one is, because being signed by the right people is not the same as paying
    // the right people.
    let finished;
    try {
      // A palm vault has one more signature to come, and Bitcoin will not take the spend without it.
      finished = lock.kind === 'palm' ? await palmFinish(op, account, lock, merged, approvals) : finalizePsbt(merged);
      verifyAgainstPlan(finished.hex, plan);
    } catch (error) {
      if (error instanceof WalletError) throw new HttpError(400, error.message);
      throw error;
    }
    try {
      const txid = await chain.broadcast(finished.hex);
      // A move to new signers: the account follows its coins to the new vault.
      if (plan.move) {
        try {
          await applyMove(op);
        } catch (error) {
          log.error(error);
        }
      }
      await query('finishOperation', 'done', txid, null, now(), op.id);
      return { signatures, required: account.required, txid };
    } catch (error) {
      if (!(error instanceof ChainError)) throw error;
      await query('finishOperation', 'failed', null, error.message, now(), op.id);
      throw new HttpError(502, error.message);
    }
  }

  /** Market price for the dashboard chart. Never touches wallet state. */
  /**
   * What this deployment's palm-vein scanner can do.
   *
   * The honest answer is nothing: there is no scanner integrated with QuVault. The route
   * exists so the answer is reportable rather than assumed, and so a page can say so plainly
   * instead of implying hardware that is not there.
   */
  async function getScanner({ user }) {
    const capabilities = scanner.getCapabilities();
    recordScannerEvidence(null, { userId: user.id });
    return {
      provider: scanner.name,
      available: capabilities.available,
      presentationAttackDetection: capabilities.presentationAttackDetection,
      biometricMatch: capabilities.biometricMatch,
      deviceAttestation: capabilities.deviceAttestation,
      scannerClass: capabilities.scannerClass,
      reason: capabilities.reason,
      // Authorisation records stay at version 1 until a provider can fill a version 2 in.
      authorizationVersion: 1,
    };
  }

  /**
   * The evidence for one payment, as a bundle an outsider can check.
   *
   * Everything a verifier needs travels in the bundle: the format, the genesis constant, the
   * entries and the head. `scripts/verify-evidence.js` checks one with no database and no
   * application, which is the whole point — evidence that only the system that produced it can
   * validate is not evidence.
   *
   * A slice of the chain cannot be checked back to the genesis, so the bundle says
   * `complete: false` and the verifier adjusts rather than reporting a false break.
   */
  async function exportEvidence({ user, params: [id] }) {
    const op = await ownOperation(id, user);
    const rows = await all('evidenceForSubject', op.id);
    const entries = rows.map(toEvidenceEntry);
    const bundle = buildBundle({ entries, exportedAt: now(), subjectId: op.id, complete: false });
    return {
      bundle,
      // The server's own reading. A verifier who does not trust it runs the script instead.
      verified: verifyBundle(bundle),
      // Each fact present or absent, never inferred from another.
      summary: summarisePayment(entries, op.id),
    };
  }

  /**
   * Resolves a broadcast whose outcome was never recorded, by asking the chain.
   *
   * The one state the evidence log can be left in by a crash at the wrong moment:
   * `broadcast.attempted` with neither an acceptance nor a refusal after it. The attempt
   * carries the txid, so the question "did this reach the network?" has an authority that is
   * not this application — Bitcoin itself.
   *
   * Three answers, and only two of them licence writing anything:
   *
   *   the chain has it          → `broadcast.accepted`, marked reconciled
   *   the chain has never seen it → `broadcast.refused`, marked reconciled
   *   we could not ask          → nothing. The outcome stays open, which is the truth.
   *
   * Idempotent: the appended fact uses the ordinary key, so running this twice over the same
   * payment writes once. Safe to run on a schedule.
   */
  async function reconcileBroadcast(op, { actor = null } = {}) {
    const entries = (await all('evidenceForSubject', op.id)).map(toEvidenceEntry);
    const state = summarisePayment(entries, op.id);
    if (!state.outcomeUnknown) return { reconciled: false, reason: 'the outcome is already recorded' };

    const attempt = entries.find(e => e.kind === EVIDENCE.BROADCAST_ATTEMPTED);
    const txid = attempt?.payload?.txid;
    if (!txid) return { reconciled: false, reason: 'the attempt names no transaction to ask about' };

    const status = await chain.transactionStatus(txid);
    if (status.known === null) {
      // Could not ask. Writing either outcome here would be a guess, so nothing is written.
      return { reconciled: false, reason: 'the Bitcoin service could not be reached', txid };
    }

    const fact = { actor, subjectKind: 'operation', subjectId: op.id, txid, outcome: 'reconciled' };
    if (status.known) {
      await appendEvidence(EVIDENCE.BROADCAST_ACCEPTED, {
        ...fact, network, chain: 'bitcoin', reason: 'reconciled against the chain',
      });
      // The operation itself may also have been left mid-flight by the same crash.
      if (op.status !== 'done') await query('finishOperation', 'done', txid, null, now(), op.id);
      return { reconciled: true, outcome: 'accepted', txid, confirmed: status.confirmed };
    }
    await appendEvidence(EVIDENCE.BROADCAST_REFUSED, {
      ...fact, network, chain: 'bitcoin', reason: 'the chain has never seen this transaction',
    });
    return { reconciled: true, outcome: 'refused', txid };
  }

  /**
   * Forwards a checkpoint to the external sink, and records what happened either way.
   *
   * Every attempt is a row, so an outage followed by a success reads as two facts in order
   * rather than a status field that forgets the outage. A failure is never fatal: the
   * checkpoint is already stored and still useful locally, and `retryAnchors` picks it up.
   */
  async function anchorCheckpoint(checkpointRow, { actor = null } = {}) {
    let outcome;
    try {
      outcome = await sink.store(JSON.parse(checkpointRow.checkpoint));
    } catch (error) {
      log.error(error);
      outcome = { result: ANCHOR.UNREACHABLE, ref: null, detail: 'the sink threw' };
    }
    await query('insertAnchor', randomId(12), checkpointRow.id, checkpointRow.wallet_user_id,
      sink.name, outcome.result, outcome.ref ?? null, outcome.detail ?? null, now());

    await appendEvidence(EVIDENCE.CHECKPOINT_ANCHORED, {
      actor,
      subjectKind: 'wallet',
      subjectId: checkpointRow.wallet_user_id === actor ? undefined : checkpointRow.wallet_user_id,
      provider: sink.name,
      outcome: outcome.result,
      reason: outcome.detail ?? null,
    });
    return outcome;
  }

  /**
   * Forwards every checkpoint that has no successful anchor yet.
   *
   * This is the recovery path after a sink outage, and the only part of checkpointing a server
   * schedule can actually perform — the signing needs the owner's key, which is in their
   * browser. Idempotent: a checkpoint already STORED is not in the set.
   */
  async function retryAnchors({ user }) {
    const waiting = await all('checkpointsAwaitingAnchor', user.id);
    const results = [];
    for (const row of waiting) {
      const outcome = await anchorCheckpoint(row, { actor: user.id });
      results.push({ checkpoint: row.head, count: row.entry_count, result: outcome.result });
      // A sink that is down will be down for the next one too; do not hammer it.
      if (outcome.result === ANCHOR.UNREACHABLE) break;
    }
    return { attempted: results.length, waiting: waiting.length, results, sink: sink.describe() };
  }

  /**
   * Where this log stands: how much of it is unanchored, and by what.
   *
   * The honest summary, with the three tiers kept apart. A deployment with no sink is told
   * that it has no durable external anchor, in those words, rather than being shown a green
   * light because a hash chain verifies.
   */
  async function anchorStatus({ user }) {
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    const latest = await one('latestCheckpoint', user.id);
    const count = Number((await one('evidenceCount')).n);
    const window = anchorWindow({
      lastCheckpointAt: latest ? Number(latest.at) : null,
      lastCheckpointCount: latest ? latest.entry_count : 0,
      entryCount: count,
      now: now(),
      policy: anchorPolicy,
    });
    const anchors = await all('anchorsOf', user.id);
    const stored = anchors.filter(a => a.result === ANCHOR.STORED);
    const awaiting = await all('checkpointsAwaitingAnchor', user.id);

    return {
      entries: count,
      window,
      policy: anchorPolicy,
      // Tier 1: the chain. Tier 2: the browser, which is local only. Tier 3: the sink.
      externalAnchor: {
        ...sink.describe(),
        lastStoredAt: stored.length ? Number(stored.at(-1).at) : null,
        lastStoredCount: stored.length
          ? (await one('checkpointById', stored.at(-1).checkpoint_id))?.entry_count ?? null
          : null,
        awaitingForwarding: awaiting.length,
      },
      lastCheckpoint: latest
        ? { head: latest.head, count: latest.entry_count, at: Number(latest.at) }
        : null,
      /*
       * Said explicitly because the brief it answers was explicit: a browser's stored head is
       * a local tripwire, not a durable external record. A verifier cannot fetch it, and
       * clearing site data erases it.
       */
      browserCopyIsNotAnAnchor: true,
    };
  }

  /**
   * What the browser needs in order to sign a checkpoint: the head, and how many entries it
   * covers. Read-only, and it commits to nothing — the signature is the commitment.
   */
  async function checkpointTarget({ user }) {
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    const head = (await one('evidenceHead'))?.hash ?? GENESIS;
    const count = (await one('evidenceCount')).n;
    const latest = await one('latestCheckpoint', user.id);
    /*
     * Every point this server claims its log passed through, so a browser holding its own
     * record of an earlier commitment can compare and notice a disagreement. The heads are
     * recomputed from the live log rather than read from the checkpoint rows — otherwise an
     * operator who rewrote the log and kept the rows would be reporting the old heads back.
     */
    const entries = (await all('evidenceAll')).map(toEvidenceEntry);
    const claimed = (await all('checkpointsOf', user.id)).map(row => ({
      count: row.entry_count,
      head: entries[row.entry_count - 1]?.hash ?? (row.entry_count === 0 ? GENESIS : null),
    }));
    return {
      vaultId: wallet.address,
      head,
      count: Number(count),
      nonce: randomId(12),
      at: now(),
      // So a page can say whether anything has happened since the last commitment.
      lastCheckpoint: latest ? { head: latest.head, count: latest.entry_count, at: Number(latest.at) } : null,
      // What this server says its history was at each committed point. A browser compares.
      claimedHeads: claimed,
    };
  }

  /**
   * Records a checkpoint the browser signed.
   *
   * Verified before it is stored, against the vault's registered attestation key and against
   * the head the server actually has — a checkpoint for a head this log does not hold is
   * refused, because storing it would create a commitment to a log nobody has.
   */
  async function registerCheckpoint({ user, body }) {
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    const lineage = attestationOf(wallet);
    if (!lineage.ok) throw new HttpError(409, `This vault has no valid attestation key: ${lineage.reason}.`);

    const head = (await one('evidenceHead'))?.hash ?? GENESIS;
    const count = Number((await one('evidenceCount')).n);
    const checked = verifyCheckpoint(body.checkpoint, lineage.publicKey, {
      vaultId: wallet.address, head, count,
    });
    if (!checked.ok) throw new HttpError(409, `That checkpoint cannot be accepted: ${checked.reason}.`);

    try {
      await query('insertCheckpoint', randomId(12), user.id, head, count,
        checked.record.at, lineage.keyId, JSON.stringify(body.checkpoint));
    } catch (error) {
      // One checkpoint per head: a repeat is not an error, it is the same commitment.
      if (!/duplicate key|unique/i.test(String(error?.message ?? ''))) throw error;
      return { checkpoint: { head, count }, appended: false };
    }
    /*
     * Recorded as a fact too, so the log says when it was committed to. This entry is covered
     * by the NEXT checkpoint, never by the one just made — which is what keeps the two
     * structures acyclic.
     */
    await appendEvidence(EVIDENCE.CHECKPOINT_SIGNED, {
      actor: user.id, subjectKind: 'wallet', subjectId: wallet.address,
      vaultId: wallet.address, keyEpoch: lineage.epoch, outcome: 'committed',
    });

    /*
     * Forwarded immediately, because a checkpoint sitting only in this database is not an
     * external anchor. If the sink is down the attempt is recorded and the checkpoint waits
     * for `POST /api/evidence/anchor/retry` — losing it here would be the one unrecoverable
     * outcome, so it is the one thing that cannot happen.
     */
    const row = await one('checkpointByHead', user.id, head);
    const anchored = row ? await anchorCheckpoint(row, { actor: user.id }) : { result: ANCHOR.NOT_CONFIGURED };
    return {
      checkpoint: { head, count, at: checked.record.at },
      appended: true,
      external: { result: anchored.result, sink: sink.name, ...sink.describe() },
    };
  }

  /** Reconciles one payment on request. Read-mostly: it writes only a settled outcome. */
  async function reconcileOne({ user, params: [id] }) {
    const op = await ownOperation(id, user);
    if (op.wallet_user_id !== user.id) throw new HttpError(403, 'Only the account owner can reconcile this.');
    return reconcileBroadcast(op, { actor: user.id });
  }

  /** The whole log, for an investigation. Chain-complete, so it checks back to the genesis. */
  async function exportAllEvidence({ user }) {
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'This account has no wallet.');
    const entries = (await all('evidenceAll')).map(toEvidenceEntry);
    const checkpoints = (await all('checkpointsOf', user.id)).map(row => JSON.parse(row.checkpoint));
    const bundle = buildBundle({ entries, exportedAt: now(), complete: true, checkpoints });
    const lineage = attestationOf(wallet);

    /*
     * The public attestation key travels with the bundle so a verifier can check the
     * checkpoint signatures without asking this server for anything. A bundle that needed the
     * server to validate it would not be independent evidence.
     */
    const publicKey = lineage.ok ? lineage.publicKey : null;
    return {
      bundle,
      vaultPublicKey: publicKey,
      vaultKeyId: lineage.ok ? lineage.keyId : null,
      verified: verifyBundle(bundle),
      checkpoints: checkpointsAgree(bundle, publicKey
        ? checkpoint => verifyCheckpoint(checkpoint, publicKey, { vaultId: wallet.address })
        : null),
    };
  }

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
        // The page needs these to shape the send form: how many base units a whole coin is,
        // and whether the account is account-based (EVM) or UTXO (Bitcoin).
        decimals: network.decimals,
        family: network.family ?? row.network,
        address: row.address,
        explorer: network.explorer(row.address),
        // When the chain keeps this account's threshold, what it keeps.
        quorum: row.required ? {
          required: row.required,
          keys: JSON.parse(row.quorum_keys),
          script: row.public_key,
          previousAddress: row.previous_address,
          // A palm vault: Bitcoin itself needs the palm key too, and the signers alone only after
          // the delay. The descriptor is everything another wallet needs to find these coins.
          palm: row.lock_kind === 'palm' && !isEvm(row.network) ? await palmView(row) : null,
          // An Ethereum or BSC account locked to the palm: its wallet contract, and who pays the gas.
          palmWallet: row.lock_kind === 'palm' && isEvm(row.network) ? await palmWalletView(row) : null,
        } : null,
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
    if (wallet.custody !== CUSTODY.BROWSER) {
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

  /*
   * A signer's own key for one vault.
   *
   * The request is made against the signer's own wallet, because it is their phrase that has
   * to be opened, and it is their palm that opens it. The vault they are signing for is only
   * told the public half afterwards. Somebody who has no wallet of their own has no phrase to
   * derive from, and is told so rather than being handed a second set of words to keep.
   */
  async function requestSigningKey({ user, body }) {
    requirePalmReady();
    const ownerId = String(body.vaultOwnerId ?? '').trim();
    const member = await one('memberIn', ownerId, user.id);
    if (!member) throw new HttpError(404, 'You do not sign for that vault.');
    const mine = await one('walletOf', user.id);
    if (!mine) {
      throw new HttpError(409, 'Create your own vault first: the key you sign with comes from your own phrase.');
    }
    if (mine.custody !== CUSTODY.BROWSER) throw new HttpError(409, 'Move your vault into this browser first.');
    if (member.public_key) throw new HttpError(409, 'You already have a signing key for that vault.');

    // One branch per vault this person signs for, never reused between them.
    const used = (await all('keysOfMember', user.id)).map(row => row.key_index);
    const index = used.length ? Math.max(...used) + 1 : 0;
    const label = ownerId === user.id ? 'my own vault' : 'a vault you sign for';
    const statement = `Create the key I sign ${ownerId === user.id ? 'my' : 'their'} Bitcoin with`;
    const details = {
      action: 'create a signing key',
      vault: label,
      derived_from: `your own phrase, branch ${index}`,
      branch: index,
      effect: 'the vault is told the public half; the key itself stays in this browser',
    };
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'signing', statement, details,
      payload: { vaultOwnerId: ownerId, index }, required: 1, networkId: 'bitcoin',
    });
    return { operation: operationView(op, [], user), index, vaultOwnerId: ownerId };
  }

  /** The browser reports the public half of the key it derived, and nothing else. */
  async function registerSigningKey({ user, body }) {
    const op = await ownOperation(String(body.operationId ?? ''), user);
    if (op.kind !== 'signing' || op.status !== 'done' || op.wallet_user_id !== user.id) {
      throw new HttpError(409, 'That request cannot register a signing key.');
    }
    const publicKey = String(body.publicKey ?? '').trim().toLowerCase();
    if (!/^0[23][0-9a-f]{64}$/.test(publicKey)) throw new HttpError(400, 'That public key does not look right.');

    const { vaultOwnerId, index } = JSON.parse(op.payload);
    const member = await one('memberIn', vaultOwnerId, user.id);
    if (!member) throw new HttpError(404, 'You do not sign for that vault.');
    if (member.public_key) throw new HttpError(409, 'You already have a signing key for that vault.');
    await query('setMemberKey', publicKey, index, now(), vaultOwnerId, user.id);
    return { signingKey: publicKey, index };
  }

  /*
   * Locking an account to the people who sign for it.
   *
   * Until this happens a threshold is a rule this server remembers: the coins sit behind the
   * owner's single key, and whoever holds that key can spend alone. Locking moves them into a
   * script that names every signer's key and how many signatures it takes, so the rule is
   * kept by Bitcoin and survives this server entirely.
   *
   * Two things follow from that and cannot be arranged away. The script cannot read the
   * amount being sent, so an account the chain guards has one threshold rather than a ladder
   * of them. And the threshold is part of the address, so changing it later means a new
   * address and moving the coins again.
   */
  /* --------------------------------------------- saved names, and the payee on the phone */

  // bech32 and EVM addresses mean the same in any case, so they are kept in one; base58 is not.
  const normalAddress = (networkId, address) => (isEvm(networkId) || /^(bc1|tb1|bcrt1)/i.test(address)
    ? address.toLowerCase() : address);

  /**
   * How a payee is put to the person approving, on their phone: by the name a palm saved for it
   * if there is one, plainly marked when this vault has never paid it, and with the address in
   * short groups so its start and end are easy to compare against what they expect.
   */
  async function describeDestination(ownerId, networkId, to) {
    const saved = await one('savedAddress', ownerId, networkId, normalAddress(networkId, to));
    const paid = (await one('paidBefore', ownerId, networkId, to))?.n ?? 0;
    const groups = to.match(/.{1,4}/g) ?? [to];
    const check = groups.length > 6 ? [...groups.slice(0, 3), '…', ...groups.slice(-2)].join(' ') : groups.join(' ');
    return {
      phrase: saved ? `${saved.name} (${to})` : paid ? to : `a new address ${to}`,
      details: {
        check_address: check,
        ...(saved ? { saved_as: saved.name } : {}),
        first_payment: paid ? `no, paid ${paid} time${paid === 1 ? '' : 's'} before` : 'yes, this vault has never paid it',
      },
    };
  }

  /** Saving a name for an address. It takes a palm, so a name on a phone was put there by a palm. */
  async function requestAddressName({ user, body }) {
    requirePalmReady();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    const networkId = String(body.network ?? 'bitcoin');
    if (!NETWORKS[networkId] || !(networkId === 'bitcoin' || isEvm(networkId))) {
      throw new HttpError(400, 'Names can be saved for Bitcoin, Ethereum and BNB Smart Chain addresses.');
    }
    const address = String(body.address ?? '').trim();
    const valid = networkId === 'bitcoin' ? isValidAddress(address) : /^0x[0-9a-fA-F]{40}$/.test(address);
    if (!valid) throw new HttpError(400, 'That is not a valid address for that network.');
    const name = String(body.name ?? '').trim().replace(/\s+/g, ' ');
    if (!/^[\p{L}\p{N} .,'&()]{1,40}$/u.test(name)) {
      throw new HttpError(400, 'Use a name of up to 40 letters, numbers and spaces.');
    }
    const { required, signers } = await changeQuorum(user.id, 'bitcoin');
    const statement = `Save ${address} as “${name}”`;
    const details = {
      action: 'save an address name',
      network: NETWORKS[networkId].label ?? networkId,
      address,
      name,
      approvals_required: `${required} of ${signers.length}`,
      effect: 'payments to this address will show this name when they are approved',
    };
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'address', statement, details,
      payload: { network: networkId, address: normalAddress(networkId, address), name }, required, networkId: 'bitcoin',
    });
    return { operation: operationView(op, [], user) };
  }

  async function saveAddressName(op) {
    const { network: networkId, address, name } = JSON.parse(op.payload);
    await query('saveAddress', op.wallet_user_id, networkId, address, name, now(), op.started_by);
    return { txid: null };
  }

  /* ------------------------------------------------------------------ freeze */

  /** Anyone on a vault's roster can freeze it, at once, without a palm. */
  async function freezeVault({ user, body }) {
    const ownerId = String(body.vaultOwnerId ?? user.id);
    const wallet = await one('walletOf', ownerId);
    const allowed = wallet && (ownerId === user.id || await one('memberIn', ownerId, user.id));
    if (!allowed) throw new HttpError(404, 'Vault not found.');
    const time = now();
    const stopped = await transaction(async q => {
      const froze = (await q('freezeVault', time, user.id, ownerId)).count === 1;
      // Everything in flight stops with it: nothing approved before the freeze can be signed after.
      const ops = (await q('stopOperationsOf', 'The vault was frozen.', time, ownerId)).rows;
      const approvals = [];
      for (const op of ops) approvals.push(...(await q('cancelApprovalsOf', time, op.id)).rows);
      return { froze, approvals };
    });
    cancelRemote(stopped.approvals);
    if (stopped.froze) await alertOthers(ownerId, user.id);
    const after = await one('walletOf', ownerId);
    return { frozen: { at: after.frozen_at, by: after.frozen_by } };
  }

  /** Unfreezing takes the palms of the vault's signers: the same quorum any other change needs. */
  async function requestUnfreeze({ user, body }) {
    requirePalmReady();
    const ownerId = String(body.vaultOwnerId ?? user.id);
    const wallet = await one('walletOf', ownerId);
    const allowed = wallet && (ownerId === user.id || await one('memberIn', ownerId, user.id));
    if (!allowed) throw new HttpError(404, 'Vault not found.');
    if (!wallet.frozen_at) throw new HttpError(409, 'This vault is not frozen.');
    const { required, signers } = await changeQuorum(ownerId, 'bitcoin');
    const statement = ownerId === user.id ? 'Unfreeze my vault' : 'Unfreeze the vault';
    const details = {
      action: 'unfreeze the vault',
      frozen_since: new Date(wallet.frozen_at * 1000).toUTCString(),
      approvals_required: `${required} of ${signers.length}`,
      effect: 'payments and changes can be asked for and approved again',
    };
    const op = await newOperation({ walletOwnerId: ownerId, user, kind: 'unfreeze', statement, details, required, networkId: 'bitcoin' });
    return { operation: operationView(op, [], user) };
  }

  async function unfreeze(op) {
    await query('unfreezeVault', op.wallet_user_id);
    return { txid: null };
  }

  /* ------------------------------------------------------------------ alerts */

  async function subscribePush({ user, body }) {
    const endpoint = String(body.endpoint ?? '');
    const p256dh = String(body.keys?.p256dh ?? '');
    const auth = String(body.keys?.auth ?? '');
    if (!isPushEndpoint(endpoint) || endpoint.length > 1000) throw new HttpError(400, 'That is not a browser push address.');
    if (!/^[\w-]{20,200}$/.test(p256dh) || !/^[\w-]{8,100}$/.test(auth)) throw new HttpError(400, 'That subscription is incomplete.');
    await query('savePushSubscription', endpoint, user.id, p256dh, auth, now());
    return { alerts: (await one('pushCountOf', user.id)).n };
  }

  async function unsubscribePush({ user, body }) {
    await query('deleteMyPushSubscription', String(body.endpoint ?? ''), user.id);
    return { alerts: (await one('pushCountOf', user.id)).n };
  }

  async function requestLock({ user, body }) {
    requirePalmReady();
    const lockNetwork = String(body.network ?? 'bitcoin');
    if (isEvm(lockNetwork)) return requestEvmLock({ user, body, networkId: lockNetwork });
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    if (wallet.custody !== CUSTODY.BROWSER) throw new HttpError(409, 'Move this vault into your browser first.');

    const members = await all('membersOf', user.id);
    const account = await one('accountOn', user.id, 'bitcoin');
    if (!account) throw new HttpError(409, 'This vault has no Bitcoin account.');
    if (account.required) throw new HttpError(409, 'This account is already locked to a quorum on the chain.');

    const signerIds = signersOf(account, members);
    const signers = signerIds.map(id => members.find(m => m.member_id === id)).filter(Boolean);
    const without = signers.filter(m => !m.public_key);
    if (without.length) {
      const names = without.map(m => m.label).join(', ');
      throw new HttpError(409, `Everyone has to make a signing key first. Still waiting for: ${names}.`);
    }
    // A palm vault may be one person's: Bitcoin then needs their key and the palm key, so even a
    // vault of one is never spent by one signature.
    const palm = body.palm === true;
    if (signers.length < 2 && !palm) throw new HttpError(409, 'A quorum needs at least two signers.');

    const required = Number(body.required);
    // A quorum on the chain must never be spendable by one signature: the floor is two.
    const floor = quorumFloor(signers.length);
    if (!Number.isInteger(required) || required < floor || required > signers.length) {
      throw new HttpError(400, `Choose between ${floor} and ${signers.length} signatures.`);
    }

    const days = body.recoveryDays === undefined || body.recoveryDays === null ? 365 : Number(body.recoveryDays);
    if (palm && !RECOVERY_CHOICES.includes(days)) {
      throw new HttpError(400, `Choose a recovery delay of ${RECOVERY_CHOICES.join(', ')} days.`);
    }

    const keys = signers.map(m => m.public_key);
    let quorumAddress;
    let palmVault = null;
    try {
      if (palm) {
        // A palm key for this vault alone, made by the palm signer and kept by it.
        const signer = await palmSigner();
        const palmVaultId = randomId(16);
        const palmKey = signer.publicKeyFor(palmVaultId);
        const made = palmVaultOf({ palmKey, signerKeys: keys, required, delay: delayForDays(days), network: NETWORK });
        palmVault = { kind: 'palm', palmVaultId, palmKey, delay: made.delay, descriptor: made.descriptor };
        quorumAddress = made.address;
      } else {
        quorumAddress = multisigAddressOf(keys, required);
      }
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(400, error instanceof WalletError ? error.message : 'Those keys do not make a quorum.');
    }

    // The coins have to move, because the script they are locked to is the address itself.
    let plan = null;
    try {
      const [utxos, suggested] = await Promise.all([chain.spendableUtxos(wallet.address), chain.feeRate()]);
      const feeRate = Number(body.feeRate) > 0 ? Number(body.feeRate) : suggested;
      if (utxos.length) {
        plan = planSpend({
          publicKey: Buffer.from(wallet.public_key, 'hex'),
          utxos, toAddress: quorumAddress, amountSats: 'max', feeRate,
        });
      }
    } catch (error) {
      if (error instanceof WalletError || error instanceof ChainError) throw new HttpError(400, error.message);
      throw error;
    }

    const policy = policyOfAccount(account, wallet);
    const palms = Math.min(signers.length, Math.max(requiredToChange(policy, signers.length), quorumFloor(signers.length)));
    const bound = plan ? bindPlan(wallet, plan) : null;
    const what = palm
      ? (signers.length === 1 ? 'my palm' : `${required} of ${signers.length} and the palm`)
      : `${required} of ${signers.length}`;
    const statement = plan
      ? `Lock my Bitcoin to ${what} on the chain and move ${toBtc(plan.sentSats)} tBTC to it`
      : `Lock my Bitcoin to ${what} on the chain`;
    const details = {
      action: palm ? 'lock to the palm on the chain' : 'lock to a quorum on the chain',
      network,
      approvals_required: `${required} of ${signers.length} signature${signers.length === 1 ? '' : 's'}`,
      signers: signers.map(m => m.label).join(', '),
      to: quorumAddress,
      effect: palm
        ? 'from now on Bitcoin itself refuses any spend from this account without a palm approval'
        : 'from now on this account is spent by signatures, not by one key',
      ...(palm ? {
        recovery: `if the palm signer is ever gone, the signers alone can move the coins after about ${days} days`,
        ...lockWarning(required, signers.length, days),
      } : {}),
      ...(plan ? {
        amount_sats: plan.sentSats,
        fee_sats: plan.feeSats,
        spends: plan.inputs.map(i => `${i.txid}:${i.index}`).join(' '),
        transaction_hash: bound.digest,
      } : { amount_sats: 0 }),
    };
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'lock', statement, details,
      payload: { ...(plan ?? {}), transactionHash: bound?.digest ?? null, quorum: { keys, required, address: quorumAddress, ...(palmVault ?? {}) } },
      required: palms, networkId: 'bitcoin',
    });
    return { operation: operationView(op, [], user), quorum: { address: quorumAddress, required, signers: signers.length, palm }, plan };
  }

  /** Writes the quorum onto the account, once the coins are on their way to it. */
  async function lockAccount(op) {
    const { quorum } = JSON.parse(op.payload);
    if (quorum.kind === 'palm-evm') return lockEvmAccount(op);
    if (quorum.kind === 'palm') {
      const made = palmVaultOf({
        palmKey: quorum.palmKey, signerKeys: quorum.keys, required: quorum.required, delay: quorum.delay, network: NETWORK,
      });
      if (made.address !== quorum.address) throw new HttpError(500, 'The palm vault no longer matches the one that was approved.');
      await query('lockAccountToPalm', quorum.address, Buffer.from(made.leaves.normal.script).toString('hex'),
        quorum.required, JSON.stringify(quorum.keys), quorum.palmVaultId, quorum.palmKey, quorum.delay, quorum.descriptor,
        op.wallet_user_id, 'bitcoin');
      return;
    }
    const script = multisigOf(quorum.keys, quorum.required).witnessScript;
    await query('lockAccountToQuorum', quorum.address, Buffer.from(script).toString('hex'),
      quorum.required, JSON.stringify(quorum.keys), op.wallet_user_id, 'bitcoin');
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
  /*
   * A read-only relay of one transaction from the chain API, so the page can reconcile a receipt
   * against what was broadcast without talking to an explorer itself (the CSP forbids that). It
   * returns public chain data only — nothing of this vault the chain does not already show.
   */
  async function chainTransaction({ params: [txid] }) {
    try {
      return await chain.transaction(txid);
    } catch (error) {
      const missing = error?.status === 404;
      throw new HttpError(missing ? 404 : 502,
        missing ? 'The network has not seen that transaction yet.' : 'Could not read that transaction from the network.');
    }
  }

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
      /*
       * The server's own verdict; a client that verifies for itself need not believe it.
       *
       * The expected digest comes from the OPERATION, never from the record being verified.
       * It used to read `authorization.record.transactionHash`, which made the check circular:
       * it proved the signature was valid over the record, not that the record was about this
       * payment, so any internally consistent record was reported as verified. That was
       * finding F2 of the Phase A report.
       */
      verified: verifyAuthorization(authorization, publicKey, {
        transactionHash: JSON.parse(op.details).transaction_hash,
        statementDigest: op.digest,
        vaultId: wallet?.address,
        proposalId: op.id,
        threshold: op.required,
      }),
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
      warning: wallet.custody === CUSTODY.BROWSER
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
      if (wallet.custody !== CUSTODY.LEGACY) {
        throw new HttpError(409, 'This vault signs in your browser: send the coins with Send funds first.');
      }
      ({ txid, sweptSats } = await sweepLegacyVault(wallet, {
        toAddress: sweepTo,
        reason: 'vault erased',
        pendingMessage: 'A payment here is still waiting for its first confirmation.',
        operation: op,
      }));
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
    if (wallet.custody !== CUSTODY.BROWSER) throw new HttpError(409, 'This vault signs on the server and has no attestation key of its own.');
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

  const INVITE_SECONDS = 7 * 24 * 3600;

  /**
   * An invitation to sign for one account. The quorum that could change the signers is the
   * quorum that authorises this; afterwards the code itself is what the invited person needs,
   * together with their own palm. The code is generated when the approvals land, not before.
   */
  async function requestInvite({ user, body }) {
    requirePalmReady();
    // Usually the owner. Anyone whose key a locked vault is locked to may also invite, so that
    // when the owner can no longer, the others can still bring someone in to replace them.
    const ownerId = body.vaultOwnerId && String(body.vaultOwnerId) !== user.id
      ? (await signerVault(user, body.vaultOwnerId)).ownerId : user.id;
    const wallet = await one('walletOf', ownerId);
    if (!wallet) throw new HttpError(409, 'Create the vault first.');
    const networkId = String(body.network ?? 'bitcoin');
    const network = NETWORKS[networkId];
    if (!network) throw new HttpError(400, 'That is not one of the networks here.');
    const account = await one('accountOn', ownerId, networkId);
    if (!account) throw new HttpError(409, `This vault has no ${network.label} account.`);
    const label = String(body.label ?? '').replace(/\s+/g, ' ').trim().slice(0, 40);
    if (!label) throw new HttpError(400, 'Give the person a name so the others know who they are.');

    const { required, signers } = await changeQuorum(ownerId, networkId);
    const statement = `Invite ${label} to approve for ${ownerId === user.id ? 'my' : 'the'} ${network.label} account`;
    const details = {
      action: 'invite a signer',
      network: `${network.label} ${network.chain}`,
      invitee: label,
      effect: 'whoever redeems the code with their own palm becomes a signer',
      signers_after: String(signers.length + 1),
      expires: '7 days',
    };
    const op = await newOperation({
      walletOwnerId: ownerId, user, kind: 'invite', statement, details,
      payload: { network: networkId, label }, required, networkId,
    });
    return { operation: operationView(op, [], user) };
  }

  /** Once approved, the code exists. It is written into the operation so the owner can read it. */
  async function issueInvite(op) {
    const payload = JSON.parse(op.payload);
    const code = `QV-${randomId(6).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6)}-${randomId(6).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6)}`;
    const time = now();
    await query('insertInvite', code, op.wallet_user_id, payload.network, payload.label, op.started_by, time, time + INVITE_SECONDS);
    await query('setPayload', JSON.stringify({ ...payload, code, expiresAt: time + INVITE_SECONDS }), op.id);
    return { txid: null };
  }

  /** The invited person redeems a code with their own palm, and joins on approval. */
  async function requestJoin({ user, body }) {
    requirePalmReady();
    const code = String(body.code ?? '').trim().toUpperCase();
    const invite = await one('inviteByCode', code);
    if (!invite || invite.status !== 'open') throw new HttpError(404, 'That invitation code is not open. Ask for a new one.');
    if (invite.expires_at <= now()) throw new HttpError(409, 'That invitation has expired. Ask for a new one.');
    if (invite.wallet_user_id === user.id) throw new HttpError(409, 'That is an invitation to your own vault.');
    if (await one('memberIn', invite.wallet_user_id, user.id)) throw new HttpError(409, 'You already sign for that vault.');

    const wallet = await one('walletOf', invite.wallet_user_id);
    const network = NETWORKS[invite.network];
    const statement = `Join ${wallet ? wallet.address.slice(0, 10) : 'a'}… as a signer for its ${network?.label ?? invite.network} account`;
    const details = {
      action: 'join as a signer',
      network: `${network?.label ?? invite.network} ${network?.chain ?? ''}`.trim(),
      invited_as: invite.label,
      effect: 'your palm can approve transactions for that account from now on',
    };
    // Only the invited person's own palm: the vault already authorised the invitation itself.
    const op = await newOperation({
      walletOwnerId: invite.wallet_user_id, user, kind: 'join', statement, details,
      payload: { code, network: invite.network, label: invite.label }, required: 1, networkId: invite.network,
    });
    return { operation: operationView(op, [], user) };
  }

  /** Joining, once that palm lands: onto the roster, onto the account, and the code is spent. */
  async function acceptInvite(op) {
    const payload = JSON.parse(op.payload);
    const invite = await one('inviteByCode', payload.code);
    if (!invite || invite.status !== 'open') throw new HttpError(409, 'That invitation is no longer open.');
    const joiner = await one('userById', op.started_by);
    const time = now();
    const [account, members] = await Promise.all([
      one('accountOn', op.wallet_user_id, payload.network), all('membersOf', op.wallet_user_id),
    ]);
    if (!account) throw new HttpError(409, 'That account no longer exists.');
    const signers = [...new Set([...signersOf(account, members), joiner.id])];

    // A vault that was a personal one (its rules untouched) becomes a shared one the moment a
    // second signer joins, and its default is that everyone signs: no spend without all of them.
    // The owner can loosen this later to any m-of-n, but never below the two-signer floor.
    const current = account.policy ? JSON.parse(account.policy) : DEFAULT_POLICY;
    const untouched = current.rules?.length === 1 && current.rules[0].upToSats === null && Number(current.rules[0].approvals) <= 1;
    const nextPolicy = untouched ? { rules: [{ upToSats: null, approvals: signers.length }] } : current;

    await transaction(async q => {
      const used = await q('useInvite', joiner.id, time, payload.code);
      if (!used.count) throw new HttpError(409, 'That invitation was already used.');
      await q('insertMember', op.wallet_user_id, joiner.id, payload.label, false, time);
      await q('setAccountPolicy', JSON.stringify(nextPolicy), JSON.stringify(signers), op.wallet_user_id, payload.network);
    });
    await assignPalmId(op.wallet_user_id, joiner.id);
    return { txid: null };
  }

  /** The invitations this vault has out, so the owner can pass the code on again or cancel it. */
  async function listInvites({ user }) {
    const rows = await all('openInvitesOf', user.id, now());
    return {
      invites: rows.map(row => ({
        code: row.code,
        network: row.network,
        label: row.label,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
      })),
    };
  }

  async function cancelInvite({ user, body }) {
    const cancelled = await query('cancelInvite', String(body.code ?? '').trim().toUpperCase(), user.id);
    if (!cancelled.count) throw new HttpError(404, 'That invitation is not open.');
    return { ok: true };
  }

  /** Asks for the palm approvals that move a server-held vault into the owner's browser. */
  async function requestUpgrade({ user }) {
    requirePalmReady();
    vault();
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    if (wallet.custody === CUSTODY.BROWSER) throw new HttpError(409, 'This vault already lives in your browser.');
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
    if (wallet.custody === CUSTODY.BROWSER) return { wallet: walletView(wallet), txid: op.txid, sweptSats: 0 };

    const address = String(body.address ?? '').trim();
    const publicKey = String(body.publicKey ?? '').trim();
    if (!isValidAddress(address)) throw new HttpError(400, `That is not a valid ${network} address.`);
    if (!/^[0-9a-f]{66}$/i.test(publicKey)) throw new HttpError(400, 'That public key does not look right.');
    if (addressOf(Buffer.from(publicKey, 'hex')) !== address) throw new HttpError(400, 'The address does not match the public key.');
    if (address === wallet.address) throw new HttpError(400, 'The new address has to be a different one.');
    // The moved vault is a new key lineage, rooted at the key the new phrase derives.
    const registration = readRegistration(body, { vaultId: address });

    // This is the migration out of legacy custody: the coins go to the key the browser just
    // made, and the row below stops holding a key at all.
    const { txid, sweptSats } = await sweepLegacyVault(wallet, {
      toAddress: address,
      reason: 'moved into the owner’s browser',
      pendingMessage: 'A payment here is still waiting for its first confirmation. Move the vault once it lands.',
      operation: op,
    });

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
    if (wallet.custody !== CUSTODY.BROWSER) {
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
  /* ============================================================ EVM: Ethereum and BSC spends
   *
   * The account-chain path, kept apart from the Bitcoin one so the Bitcoin code is untouched.
   * It builds the exact transaction the palm approves (`canonicalTransfer`), runs the same
   * three broadcast gates the Bitcoin path does — the stored transfer still hashes to the
   * approval, the owner's key attested to it, and the signed bytes are that transfer — with
   * `reconcileSignedTransfer` as the third, and posts through the network's own JSON-RPC.
   */

  /** The expectation the owner's V2 record is checked against, for an EVM transfer. */
  async function evmExpectedAuthorization(op, wallet) {
    const approvals = (await all('approvalsOf', op.id)).filter(a => a.status === 'approved');
    const stored = JSON.parse(op.payload);
    const digest = transferDigest(canonicalTransfer({
      chain: stored.chain, network: stored.network, from: stored.from, asset: stored.asset,
      plan: stored,
    }));
    if (digest !== stored.transactionHash || digest !== JSON.parse(op.details).transaction_hash) {
      throw new HttpError(409, 'The stored transaction no longer matches the one that was approved.');
    }
    const members = await all('membersOf', op.wallet_user_id);
    const account = await one('accountOn', op.wallet_user_id, op.network);
    return {
      vaultId: wallet.address,
      accountId: op.network,
      transactionHash: digest,
      statementDigest: op.digest,
      approvalMethod: 'veyns:palm',
      approvals: `${approvals.length} of ${op.required}`,
      approvedBy: approvals.map(a => a.user_id),
      decisionIds: approvals.map(a => a.decision_id).filter(Boolean),
      keyEpoch: attestationOf(wallet).epoch ?? 0,
      chain: 'evm',
      network: op.network,
      policyVersion: policyVersionOf(policyOfAccount(account, wallet), members),
      proposalId: op.id,
      threshold: op.required,
      subject: subjectOf((await one('userById', op.wallet_user_id))?.sub),
      notBefore: Math.min(...approvals.map(a => a.closed_at ?? a.created_at)) - 60,
      notAfter: now() + 60,
    };
  }

  /** What the owner's browser needs to sign an EVM transfer: the transfer, its path, the V2 fields. */
  async function evmWithdrawalUnlock(op, wallet) {
    const expected = await evmExpectedAuthorization(op, wallet);
    const owner = await one('userById', op.wallet_user_id);
    return {
      unlock: openSealed(wallet.unlock_sealed, vault()).toString('base64'),
      salt: wallet.salt,
      transfer: JSON.parse(op.payload),
      path: NETWORKS[op.network]?.path ?? "m/44'/60'/0'/0/0",
      address: wallet.address,
      walletId: wallet.address,
      accountId: op.network,
      transactionHash: expected.transactionHash,
      statementDigest: expected.statementDigest,
      chain: 'evm',
      network: op.network,
      // The browser signer checks the request against these before it signs. An EVM transfer
      // is authorised with a version-2 record, and the binding nonce is the transfer digest.
      authorizationVersion: 2,
      bindingNonce: expected.transactionHash,
      policyVersion: expected.policyVersion,
      approvals: expected.approvals,
      approvedBy: expected.approvedBy,
      decisionIds: expected.decisionIds,
      attestationEpoch: expected.keyEpoch,
      proposalId: op.id,
      threshold: op.required,
      subject: subjectOf(owner?.sub),
      authorizationId: op.id,
      expiresAt: op.expires_at,
    };
  }

  /** Build, propose, and record an EVM withdrawal. Native-coin send; ERC-20 is a later step. */
  async function evmWithdrawal({ user, wallet, account, networkId, body }) {
    if (account.lock_kind === 'palm' && account.required) {
      return palmWalletWithdrawal({ user, ownerId: user.id, account, networkId, body });
    }
    const net = NETWORKS[networkId];
    const evm = evmChainFor(networkId);
    const from = account.address;
    const to = String(body.to ?? '').trim();
    if (!net.valid(to)) throw new HttpError(400, `That is not a valid ${net.label} address.`);
    const value = String(body.amount ?? '').trim();
    if (!/^[1-9][0-9]*$/.test(value)) throw new HttpError(400, `Enter an amount in the smallest unit (wei) of ${net.symbol}.`);

    let plan;
    try {
      const [nonce, fees] = await Promise.all([evm.nonce(from), evm.fees()]);
      // A native transfer is a fixed 21000 gas; no contract call, nothing to estimate.
      plan = {
        chainId: String(net.chainId), nonce, to, value, data: '0x', gasLimit: '21000',
        maxFeePerGas: fees.maxFeePerGas, maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
      };
    } catch (error) {
      if (error instanceof EvmChainError) throw new HttpError(502, error.message);
      throw error;
    }
    const transfer = canonicalTransfer({ chain: 'evm', network: networkId, from, plan });
    const digest = transferDigest(transfer);

    // The quorum ladder, by amount, exactly as Bitcoin — the account carries its own policy.
    // The ladder compares a number; a wei value past Number range collapses to its top rule,
    // which is the safe direction (more approvals, never fewer).
    const ladder = await quorumFor(user.id, networkId, Number(value));
    const required = ladder.required;
    const destination = await describeDestination(user.id, networkId, to);
    const statement = `Send ${format(value, networkId)} ${net.symbol} to ${destination.phrase}`;
    const details = {
      action: 'withdraw', network: networkId, to, ...destination.details,
      amount_wei: value, chain_id: net.chainId,
      max_fee_per_gas: plan.maxFeePerGas, gas_limit: plan.gasLimit,
      approvals_required: `${required} of ${ladder.signers.length} signer${ladder.signers.length === 1 ? '' : 's'}`,
      transaction_hash: digest,
    };
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'withdraw', statement, details,
      payload: { ...transfer, transactionHash: digest }, required, networkId,
    });
    await appendEvidence(EVIDENCE.PROPOSAL_CREATED, {
      actor: user.id, subjectKind: 'operation', subjectId: op.id,
      userId: user.id, vaultId: from, kind: 'withdraw', network: networkId, chain: 'evm',
      transactionHash: digest, threshold: required, address: to,
    });
    return { operation: operationView(op, [], user), transfer, transactionHash: digest, rule: ladder.rule };
  }

  /** Verify the three gates and broadcast an EVM transfer. Mirrors the Bitcoin broadcast tail. */
  async function evmBroadcast({ op, user, wallet, body }) {
    const networkId = op.network;
    const event = { operationId: op.id, userId: user.id, vaultId: wallet.address, kind: op.kind, network: networkId, chain: 'evm', custody: wallet.custody };
    const asEvidence = { actor: user.id, subjectKind: 'operation', subjectId: op.id };
    security.signingAttempt(event);
    await appendEvidence(EVIDENCE.AUTHORIZATION_ATTEMPTED, { ...asEvidence, ...event });

    const stored = JSON.parse(op.payload);
    // Gate 1 + the authorisation check share this expectation; it throws on a stored-plan mismatch.
    const expected = await evmExpectedAuthorization(op, wallet);

    // Gate 2 — the owner's key attested to this exact transfer.
    const authorization = body.authorization ?? authorizationOf(op);
    const lineage = attestationOf(wallet);
    if (!lineage.ok) {
      await appendEvidence(EVIDENCE.AUTHORIZATION_REJECTED, { ...asEvidence, ...event, reason: 'no valid attestation key' });
      throw new HttpError(409, `This vault has no valid attestation key: ${lineage.reason}.`);
    }
    const checkedAuth = verifyAuthorization(authorization, lineage.publicKey, expected);
    if (!checkedAuth.ok) {
      security.signingRejected({ ...event, reason: 'authorisation did not verify' });
      await appendEvidence(EVIDENCE.AUTHORIZATION_REJECTED, { ...asEvidence, ...event, reason: checkedAuth.reason });
      throw new HttpError(409, `No valid human authorisation for this transaction: ${checkedAuth.reason}.`);
    }
    if (!op.human_authorization) await query('setAuthorization', JSON.stringify(authorization), op.id);
    await appendEvidence(EVIDENCE.AUTHORIZATION_GRANTED, {
      ...asEvidence, ...event, required: true,
      transactionHash: expected.transactionHash,
      receiptVersion: authorization?.record?.v ?? null,
      policyVersion: authorization?.record?.policyVersion ?? null,
      threshold: authorization?.record?.threshold ?? null,
      approvalCount: authorization?.record?.approvalCount ?? null,
      keyEpoch: lineage.epoch,
      approvedBy: expected.approvedBy, decisionIds: expected.decisionIds,
      sensorEvidence: authorization?.record?.verification?.sensorEvidence ?? 'none',
      verification: 'verified',
    });

    // Gate 3 — the signed bytes are exactly the approved transfer, signed by the approved account.
    const raw = String(body.hex ?? '').trim();
    const reconciled = reconcileSignedTransfer(stored, raw);
    if (!reconciled.ok) {
      security.signingRejected({ ...event, reason: reconciled.reason });
      await appendEvidence(EVIDENCE.AUTHORIZATION_REJECTED, { ...asEvidence, ...event, reason: reconciled.reason });
      throw new HttpError(400, `The signed transaction does not match the approval: ${reconciled.reason}.`);
    }
    const txid = evmTransactionHash(raw);

    try {
      await appendEvidence(EVIDENCE.SIGNATURE_PRODUCED, {
        ...asEvidence, ...event, required: true,
        transactionHash: expected.transactionHash, isolation: 'none:browser-javascript',
      });
      await appendEvidence(EVIDENCE.BROADCAST_ATTEMPTED, {
        ...asEvidence, ...event, required: true, txid, transactionHash: expected.transactionHash,
      });
      const sent = await evmChainFor(networkId).broadcast(raw);
      if (op.kind === 'lock') await lockAccount(op);
      await query('finishOperation', 'done', sent, null, now(), op.id);
      security.signingSuccess({ ...event, txid: sent, transactionHash: expected.transactionHash, isolation: 'none:browser-javascript' });
      await appendEvidence(EVIDENCE.BROADCAST_ACCEPTED, { ...asEvidence, ...event, txid: sent, transactionHash: expected.transactionHash });
      return { txid: sent };
    } catch (error) {
      if (!(error instanceof EvmChainError)) throw error;
      await query('finishOperation', 'failed', null, error.message, now(), op.id);
      security.signingRejected({ ...event, reason: 'the network would not take the transaction' });
      await appendEvidence(EVIDENCE.BROADCAST_REFUSED, { ...asEvidence, ...event, reason: 'the network would not take the transaction' });
      throw new HttpError(502, error.message);
    }
  }

  async function requestWithdrawal({ user, body }) {
    requirePalmReady();
    // Any signer may propose a payment from a vault the chain guards: the chain still needs the
    // same signatures, and the palms behind them, whoever asked.
    if (body.vaultOwnerId && String(body.vaultOwnerId) !== user.id && isEvm(String(body.network ?? ''))) {
      const ownerId = String(body.vaultOwnerId);
      const [evmAccount, members] = await Promise.all([one('accountOn', ownerId, String(body.network)), all('membersOf', ownerId)]);
      if (!members.some(m => m.member_id === user.id)) throw new HttpError(404, 'Vault not found.');
      if (evmAccount?.lock_kind !== 'palm' || !keyHoldersOf(evmAccount, members).some(m => m.member_id === user.id)) {
        throw new HttpError(403, 'Only someone whose key this wallet is locked to can ask for that.');
      }
      return palmWalletWithdrawal({ user, ownerId, account: evmAccount, networkId: String(body.network), body });
    }
    if (body.vaultOwnerId && String(body.vaultOwnerId) !== user.id) {
      if (body.network && body.network !== 'bitcoin') throw new HttpError(409, 'Only the owner can send from that account.');
      const { ownerId, account } = await signerVault(user, body.vaultOwnerId);
      return bitcoinWithdrawal({ user, ownerId, account, body });
    }
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    // A legacy vault's key is on the server, so a spend from one would be a spend this server
    // could make by itself. It is refused at the door rather than at the broadcast, so nobody
    // collects palm approvals for a transaction that was never going to be signed.
    if (wallet.custody !== CUSTODY.BROWSER) {
      security.signingRejected({
        userId: user.id, vaultId: wallet.address, custody: wallet.custody, kind: 'withdraw',
        reason: 'legacy server custody cannot spend',
      });
      throw new HttpError(409, 'This vault was made before keys lived in the browser, so the server still '
        + 'holds its key and spending from it is no longer allowed. Move the vault into your browser '
        + 'first. It takes one palm scan and brings every coin with it.');
    }

    // Which account is spending. Defaults to Bitcoin for back-compatibility; an EVM network
    // routes to its own send path, which is UTXO-free and account-based.
    const networkId = String(body.network ?? 'bitcoin');
    if (isEvm(networkId)) {
      const evmAccount = await one('accountOn', user.id, networkId);
      if (!evmAccount) throw new HttpError(409, `Add a ${NETWORKS[networkId].label} account first.`);
      return evmWithdrawal({ user, wallet, account: evmAccount, networkId, body });
    }

    const account = await one('accountOn', user.id, 'bitcoin');
    return bitcoinWithdrawal({ user, ownerId: user.id, account, body });
  }

  /** A payment from a vault's Bitcoin account, asked for by its owner or, once it is locked, by any signer. */
  async function bitcoinWithdrawal({ user, ownerId, account, body }) {
    // A shared vault must be locked to the chain before it can send. Until it is, its coins sit
    // behind the owner's single key and the quorum is only a rule this server keeps — so a lost
    // phrase, or this server, could move them alone. Inviting and receiving work unlocked;
    // sending does not. Locking sweeps the coins into the m-of-n script and is a different op.
    if (!account?.required) {
      const signers = signersOf(account, await all('membersOf', ownerId));
      if (signers.length > 1) {
        throw new HttpError(409,
          'This vault has more than one signer, so it must be locked to the chain before it can send. '
          + 'Lock it to a quorum first: until then its coins are guarded only by a rule here, not by Bitcoin.');
      }
    }
    const lock = lockOfAccount(account, await one('walletOf', ownerId));

    const to = String(body.to ?? '').trim();
    if (!isValidAddress(to)) throw new HttpError(400, `That is not a valid ${network} address.`);
    const max = body.amount === 'max';
    const amountSats = max ? 'max' : Number(body.amount);
    if (!max && (!Number.isInteger(amountSats) || amountSats <= 0)) throw new HttpError(400, 'Enter an amount in satoshis.');

    let plan;
    try {
      const [utxos, suggested] = await Promise.all([chain.spendableUtxos(lock.address), chain.feeRate()]);
      const feeRate = Number(body.feeRate) > 0 ? Number(body.feeRate) : suggested;
      plan = planFor(lock, { utxos, toAddress: to, amountSats, feeRate });
    } catch (error) {
      if (error instanceof WalletError || error instanceof ChainError) throw new HttpError(400, error.message);
      throw error;
    }

    const leaving = plan.sentSats + plan.feeSats;
    const ladder = await quorumFor(ownerId, 'bitcoin', leaving);
    // An account the chain guards has one threshold, because a script cannot read the amount
    // being sent. That threshold is the number of signatures, and every signature costs a palm.
    const { signers, rule } = ladder;
    const required = lock.required ?? ladder.required;
    // The digest of the exact transaction is part of what the palm approves, not a note beside it.
    const bound = bindPlan(lock, plan);
    const destination = await describeDestination(ownerId, 'bitcoin', to);
    const statement = `Send ${toBtc(plan.sentSats)} tBTC to ${destination.phrase}`;
    const details = {
      action: 'withdraw',
      network,
      to,
      ...destination.details,
      amount_sats: plan.sentSats,
      fee_sats: plan.feeSats,
      fee_rate: `${plan.feeRate} sat/vB`,
      spends: plan.inputs.map(i => `${i.txid}:${i.index}`).join(' '),
      change_sats: plan.changeSats,
      approvals_required: lock.required
        ? `${required} of ${lock.publicKeys.length} signer${lock.publicKeys.length === 1 ? '' : 's'}${lock.kind === 'palm' ? ' and the palm' : ''}`
        : `${required} of ${signers.length} signer${signers.length === 1 ? '' : 's'}`,
      transaction_hash: bound.digest,
    };
    const op = await newOperation({
      walletOwnerId: ownerId, user, kind: 'withdraw', statement, details,
      payload: { ...plan, transactionHash: bound.digest }, required, networkId: 'bitcoin',
    });
    await appendEvidence(EVIDENCE.PROPOSAL_CREATED, {
      actor: user.id, subjectKind: 'operation', subjectId: op.id,
      userId: user.id, vaultId: lock.address, kind: 'withdraw', network, chain: 'bitcoin',
      transactionHash: bound.digest, threshold: required, sats: plan.sentSats, address: to,
    });
    // A quorum starts collecting signatures from the unsigned transaction itself.
    if (lock.required) await query('setPsbt', unsignedFor(lock, plan), op.id);
    return { operation: operationView(op, [], user), plan, rule, transactionHash: bound.digest };
  }

  /* ------------------------------------------ refresh, replacing a signer, inheritance */

  /** Shown before anyone locks or moves a vault where every signer is needed. */
  const lockWarning = (required, count, days) => (required < count ? {} : {
    warning: count === 1
      ? `if you die, these coins can only be moved after about ${days} days, and only with your twelve words`
      : `every signer is needed, so if any one of you dies normal spending stops; after about ${days} days the coins can move again, but only with that person's twelve words`,
  });

  /**
   * Every coin in a palm vault, moved to a palm vault: back into itself (a refresh, which
   * restarts every recovery clock) or into a new one (new signers, threshold or delay). Either
   * way it is an ordinary palm vault spend, so the vault's own signers sign, their palms approve,
   * and the palm key signs last, all through the path every payment takes.
   */
  async function palmMoveRequest({ user, ownerId, account, toAddress, statementOf, details, move = null, feeRate }) {
    const lock = lockOfAccount(account);
    let plan = null;
    try {
      const [utxos, suggested] = await Promise.all([chain.spendableUtxos(lock.address), chain.feeRate()]);
      const rate = Number(feeRate) > 0 ? Number(feeRate) : suggested;
      if (utxos.length) plan = planPalmSpend({ vault: lock.vault, utxos, toAddress, amountSats: 'max', feeRate: rate });
    } catch (error) {
      if (error instanceof WalletError || error instanceof ChainError) throw new HttpError(400, error.message);
      throw error;
    }
    if (!plan && !move) throw new HttpError(409, 'There are no confirmed coins in this vault to refresh.');
    const moved = plan ? plan.outputs.reduce((sum, output) => sum + output.sats, 0) : 0;
    const bound = plan ? bindPlan(lock, plan) : null;
    const keys = lock.publicKeys.length;
    const fullDetails = {
      ...details,
      approvals_required: `${lock.required} of ${keys} signer${keys === 1 ? '' : 's'} and the palm`,
      ...(plan ? {
        amount_sats: moved,
        fee_sats: plan.feeSats,
        fee_rate: `${plan.feeRate} sat/vB`,
        spends: plan.inputs.map(i => `${i.txid}:${i.index}`).join(' '),
        transaction_hash: bound.digest,
      } : { amount_sats: 0 }),
    };
    const op = await newOperation({
      walletOwnerId: ownerId, user, kind: 'withdraw', statement: statementOf(plan ? toBtc(moved) : null), details: fullDetails,
      payload: { ...(plan ?? {}), transactionHash: bound?.digest ?? null, ...(move ? { move } : {}) },
      required: lock.required, networkId: 'bitcoin',
    });
    if (plan) {
      await appendEvidence(EVIDENCE.PROPOSAL_CREATED, {
        actor: user.id, subjectKind: 'operation', subjectId: op.id,
        userId: user.id, vaultId: lock.address, kind: 'withdraw', network, chain: 'bitcoin',
        transactionHash: bound.digest, threshold: lock.required, sats: moved, address: toAddress,
      });
      await query('setPsbt', unsignedFor(lock, plan), op.id);
    }
    return { operation: operationView(op, [], user), plan };
  }

  /** Sends a palm vault's coins straight back into it, so every recovery clock starts again. */
  async function requestRefresh({ user, body }) {
    requirePalmReady();
    const { ownerId, account } = await signerVault(user, body.vaultOwnerId);
    if (account?.lock_kind !== 'palm' || !account.required) {
      throw new HttpError(409, 'Only a vault locked to the palm has a recovery clock to restart.');
    }
    const days = daysOfDelay(account.recovery_delay);
    const mine = ownerId === user.id;
    return palmMoveRequest({
      user, ownerId, account, toAddress: account.address, feeRate: body.feeRate,
      statementOf: amount => `Refresh ${mine ? 'my' : 'the'} vault: move ${amount} tBTC back into it, so its recovery clock starts again`,
      details: {
        action: 'refresh the vault',
        network,
        to: account.address,
        to_is: 'this same vault',
        effect: `the coins come straight back here, and the recovery path stays closed for about ${days} more days`,
      },
    });
  }

  /**
   * A palm vault with different signers, a different threshold or a different delay. The
   * signers are part of the address, so this is a new vault and every coin moves to it, approved
   * and signed by the vault as it stands. Anyone whose key it is locked to can ask, so the
   * others can carry on when one of them, the owner included, never can again.
   */
  async function requestMove({ user, body }) {
    requirePalmReady();
    const { ownerId, account, members } = await signerVault(user, body.vaultOwnerId);
    if (account?.lock_kind !== 'palm' || !account.required) {
      throw new HttpError(409, 'Replacing a signer moves a palm vault. Lock this account to the palm first.');
    }
    const lock = lockOfAccount(account);
    const ids = [...new Set((Array.isArray(body.signers) ? body.signers : []).map(String))];
    const chosen = ids.map(id => members.find(m => m.member_id === id));
    if (!ids.length || chosen.some(m => !m)) throw new HttpError(400, 'Choose the new signers from the people on this vault.');
    const without = chosen.filter(m => !m.public_key);
    if (without.length) {
      throw new HttpError(409, `Everyone in the new vault needs a signing key first. Still waiting for: ${without.map(m => m.label).join(', ')}.`);
    }
    const required = Number(body.required);
    const floor = quorumFloor(chosen.length);
    if (!Number.isInteger(required) || required < floor || required > chosen.length) {
      throw new HttpError(400, `Choose between ${floor} and ${chosen.length} signatures.`);
    }
    const days = body.recoveryDays === undefined || body.recoveryDays === null
      ? daysOfDelay(account.recovery_delay) : Number(body.recoveryDays);
    if (!RECOVERY_CHOICES.includes(days)) throw new HttpError(400, `Choose a recovery delay of ${RECOVERY_CHOICES.join(', ')} days.`);
    const delay = delayForDays(days);
    const keys = chosen.map(m => m.public_key);
    const same = keys.length === lock.publicKeys.length && keys.every(key => lock.publicKeys.includes(key));
    if (same && required === lock.required && delay === account.recovery_delay) {
      throw new HttpError(409, 'That is the vault as it already is. Change a signer, the number of signatures or the delay.');
    }

    let made;
    let palmVaultId;
    let palmKey;
    try {
      const signer = await palmSigner();
      palmVaultId = randomId(16);
      palmKey = signer.publicKeyFor(palmVaultId);
      made = palmVaultOf({ palmKey, signerKeys: keys, required, delay, network: NETWORK });
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(400, error instanceof WalletError ? error.message : 'Those keys do not make a vault.');
    }
    const names = list => (list.length ? list.join(', ') : 'nobody');
    const leaving = keyHoldersOf(account, members).filter(m => !keys.includes(m.public_key)).map(m => m.label);
    const joining = chosen.filter(m => !lock.publicKeys.includes(m.public_key)).map(m => m.label);
    const who = names(chosen.map(m => m.label));
    const rule = chosen.length === 1 ? 'and the palm' : `${required} of ${chosen.length} and the palm`;
    const move = {
      kind: 'palm', palmVaultId, palmKey, keys, required, delay,
      address: made.address, descriptor: made.descriptor, signers: chosen.map(m => m.member_id), from: account.address,
    };
    return palmMoveRequest({
      user, ownerId, account, toAddress: made.address, feeRate: body.feeRate, move,
      statementOf: amount => (amount === null
        ? `Change who signs for the vault to ${who}, ${rule}`
        : `Move the vault to ${who}, ${rule}, and send ${amount} tBTC to it`),
      details: {
        action: 'replace signers',
        network,
        signers: chosen.map(m => m.label).join(', '),
        leaving: names(leaving),
        joining: names(joining),
        new_rule: `${required} of ${chosen.length} signature${chosen.length === 1 ? '' : 's'} and the palm`,
        recovery: `the signers alone, after about ${days} days`,
        ...lockWarning(required, chosen.length, days),
        to: made.address,
        effect: 'the vault becomes a new palm vault with these signers; every coin moves there and the old address is retired',
      },
    });
  }

  /** Points the account at the vault a move was approved for, once its coins are on their way. */
  async function applyMove(op) {
    const { move } = JSON.parse(op.payload);
    const made = palmVaultOf({
      palmKey: move.palmKey, signerKeys: move.keys, required: move.required, delay: move.delay, network: NETWORK,
    });
    if (made.address !== move.address) throw new HttpError(500, 'The new palm vault no longer matches the one that was approved.');
    const policy = { rules: [{ upToSats: null, approvals: move.required }] };
    const moved = await query('moveAccountToPalm', move.address, Buffer.from(made.leaves.normal.script).toString('hex'),
      move.required, JSON.stringify(move.keys), move.palmVaultId, move.palmKey, move.delay, move.descriptor,
      move.from, JSON.stringify(policy), JSON.stringify(move.signers), op.wallet_user_id);
    if (moved.count !== 1) throw new HttpError(409, 'This vault has already moved.');
    await pruneRoster(op.wallet_user_id);
  }

  /** What one palm vault shows about its recovery path: the delay, the description, the clock. */
  async function palmView(row) {
    const view = {
      recoveryDelayBlocks: row.recovery_delay,
      recoveryDelayDays: daysOfDelay(row.recovery_delay),
      descriptor: row.descriptor,
      clock: null,
    };
    try {
      const lock = lockOfAccount(row);
      const [utxos, tip] = await Promise.all([chain.spendableUtxos(row.address), tipHeight()]);
      const { coins, ...clock } = recoveryClock(lock.vault, utxos, tip);
      view.clock = { ...clock, coinCount: coins.length, refreshDue: clock.daysLeft !== null && clock.daysLeft <= 60 };
    } catch (error) {
      if (!(error instanceof ChainError)) throw error;
    }
    return view;
  }

  // The chain's height moves every ten minutes or so; one look a minute is plenty for a clock.
  let tipCache = { at: 0, height: null };
  async function tipHeight() {
    if (tipCache.height !== null && now() - tipCache.at < 60) return tipCache.height;
    const height = await chain.tipHeight();
    tipCache = { at: now(), height };
    return height;
  }

  /** A vault this person signs for but does not own, as much as they need to act on it. */
  async function signedVaultView(ownerId, user) {
    const [members, account] = await Promise.all([all('membersOf', ownerId), one('accountOn', ownerId, 'bitcoin')]);
    const me = members.find(m => m.member_id === user.id);
    if (!me || !account) return null;
    const holders = keyHoldersOf(account, members);
    return {
      ownerId,
      ownerLabel: members.find(m => m.is_owner)?.label || 'the owner',
      address: account.address,
      explorer: chain.explorerAddress(account.address),
      locked: Boolean(account.required),
      required: account.required ?? null,
      keyCount: account.required ? JSON.parse(account.quorum_keys).length : null,
      holdsKey: holders.some(m => m.member_id === user.id),
      keyHolders: holders.map(m => m.member_id),
      members: members.map(memberView),
      amount: await chain.balance(account.address).then(b => b.confirmed + b.pending).catch(() => null),
      palm: account.lock_kind === 'palm' && account.required ? await palmView(account) : null,
    };
  }

  /** Everything an inheritance sheet prints. Only for someone on the vault. */
  async function inheritanceSheet({ user, body }) {
    const ownerId = String(body.vaultOwnerId || user.id);
    const [members, account] = await Promise.all([all('membersOf', ownerId), one('accountOn', ownerId, 'bitcoin')]);
    if (ownerId !== user.id && !members.some(m => m.member_id === user.id)) throw new HttpError(404, 'Vault not found.');
    if (account?.lock_kind !== 'palm' || !account.required) {
      throw new HttpError(409, 'An inheritance sheet is for a vault locked to the palm.');
    }
    const holders = keyHoldersOf(account, members);
    return {
      address: account.address,
      network,
      required: account.required,
      signers: holders.map(m => ({ label: m.label, owner: m.is_owner })),
      recoveryDelayBlocks: account.recovery_delay,
      recoveryDelayDays: daysOfDelay(account.recovery_delay),
      descriptor: account.descriptor,
      descriptorQr: await QRCode.toString(account.descriptor, { type: 'svg', margin: 1, errorCorrectionLevel: 'L' }).catch(() => null),
      palmAt: publicOrigin,
      printedAt: now(),
    };
  }

  /* ----------------------------------------------- the recovery door, for heirs
   *
   * Inside the signed in app only. An heir signs in to Palm with their own palm, and needs no
   * vault of their own to use it. Nothing secret reaches this server: the page sends the public
   * vault description and gets back an unsigned transaction, signs it on the device with the
   * twelve words, and sends back signatures. Bitcoin checks the delay itself, so this cannot
   * open the recovery path a block early for anyone.
   */
  const readVault = descriptor => {
    try {
      return palmVaultFromDescriptor(descriptor, NETWORK);
    } catch (error) {
      if (error instanceof WalletError) throw new HttpError(400, error.message);
      throw error;
    }
  };

  async function recoveryDoorPlan({ body }) {
    const vault = readVault(body.descriptor);
    let utxos;
    let tip;
    let suggested;
    try {
      [utxos, tip, suggested] = await Promise.all([chain.spendableUtxos(vault.address), tipHeight(), chain.feeRate()]);
    } catch (error) {
      if (error instanceof ChainError) throw new HttpError(502, error.message);
      throw error;
    }
    const clock = recoveryClock(vault, utxos, tip);
    const view = {
      address: vault.address,
      explorer: chain.explorerAddress(vault.address),
      required: vault.required,
      keys: vault.keys.map(key => Buffer.from(key).toString('hex')),
      recoveryDelayBlocks: vault.delay,
      recoveryDelayDays: daysOfDelay(vault.delay),
      clock,
      feeRate: suggested,
      plan: null,
      psbt: null,
    };
    const to = String(body.to ?? '').trim();
    if (!to) return view;
    if (!isValidAddress(to)) throw new HttpError(400, `That is not a valid ${network} address.`);
    const ready = utxos.filter(u => clock.coins.some(c => c.ready && c.txid === u.txid && c.vout === u.vout));
    if (!ready.length) {
      throw new HttpError(409, clock.coins.length
        ? `No coins can use the recovery path yet. The first opens in about ${clock.daysLeft} days.`
        : 'This vault has no confirmed coins.');
    }
    try {
      const feeRate = Number(body.feeRate) > 0 ? Number(body.feeRate) : suggested;
      view.plan = planPalmSpend({ vault, utxos: ready, toAddress: to, amountSats: 'max', feeRate, path: 'recovery' });
      view.psbt = palmVaultPsbt(vault, view.plan, { path: 'recovery' });
    } catch (error) {
      if (error instanceof WalletError) throw new HttpError(400, error.message);
      throw error;
    }
    return view;
  }

  async function recoveryDoorSend({ body }) {
    const vault = readVault(body.descriptor);
    const psbt = String(body.psbt ?? '');
    let finished;
    try {
      if (palmPathOf(vault, psbt) !== 'recovery') throw new WalletError('That transaction does not use this vault’s recovery path.');
      finished = finalizePalmPsbt(vault, psbt);
    } catch (error) {
      if (error instanceof WalletError) throw new HttpError(400, error.message);
      throw error;
    }
    try {
      const txid = await chain.broadcast(finished.hex);
      return { txid, explorer: chain.explorerTx(txid) };
    } catch (error) {
      if (!(error instanceof ChainError)) throw error;
      const early = /BIP68|non-final/i.test(error.message);
      throw new HttpError(early ? 409 : 502, early ? 'Bitcoin says these coins are not old enough to use the recovery path yet.' : error.message);
    }
  }

  /* ---------------------------------------------------------- refresh reminders
   *
   * Once a day the scheduler asks, and every palm vault whose recovery path opens within 60, 30
   * or 7 days, or has opened, gets one alert to each signer per step. The alert carries nothing;
   * the app shows the clock. At most one run an hour, whoever calls, so calling it more often
   * than the scheduler does cannot make this server ask the chain service for more.
   */
  const reminderStage = days => (days <= 0 ? 4 : days <= 7 ? 3 : days <= 30 ? 2 : days <= 60 ? 1 : 0);

  async function sendReminders({ headers }) {
    if (cronSecret && headers?.authorization !== `Bearer ${cronSecret}`) throw new HttpError(401, 'Not allowed.');
    const hour = Math.floor(now() / 3600);
    let hits = 1;
    try {
      ({ hits } = (await query('bumpRateLimit', `reminders:${hour}`, (hour + 2) * 3600)).rows[0]);
    } catch (error) {
      log.error(error);
    }
    if (Number(hits) > 1) return { ran: false, reason: 'already ran this hour' };
    const rows = await all('palmAccounts');
    let reminded = 0;
    for (const row of rows) {
      try {
        const lock = lockOfAccount(row);
        const clock = recoveryClock(lock.vault, await chain.spendableUtxos(row.address), await tipHeight());
        if (clock.nextOpensAt === null) continue;
        const stage = reminderStage(clock.daysLeft);
        const [at, last] = String(row.reminded ?? '').split(':').map(Number);
        if (stage <= (at === clock.nextOpensAt ? last : 0)) continue;
        await pushTo(keyHoldersOf(row, await all('membersOf', row.wallet_user_id)).map(m => m.member_id));
        await query('setReminded', `${clock.nextOpensAt}:${stage}`, row.wallet_user_id);
        reminded++;
      } catch (error) {
        log.warn(`Reminder skipped: ${error.message}`);
      }
    }
    return { ran: true, vaults: rows.length, reminded };
  }

  /* ============================================== Palm Wallets: Ethereum and BSC need the palm
   *
   * An EVM account locked to the palm lives in a PalmWallet contract (contracts/), at an address
   * worked out before the contract exists. A transfer needs the threshold of signers' signatures
   * and the palm key's, checked by the contract; the signers' keys are the ones they already
   * hold for this vault, and the palm key belongs to the palm signer. The gas account builds the
   * wallet on its first payment and submits every transfer, and can move nothing by itself.
   */
  let gasKey = null;
  const gasAccount = () => {
    if (!walletSeed) return null;
    gasKey ??= relayerKeyFrom(walletSeed);
    return { key: gasKey, address: relayerAddressOf(gasKey) };
  };

  /** A palm wallet's settings, from what the account stores, checked against its address. */
  function palmWalletOf(account) {
    const description = JSON.parse(account.descriptor);
    const keys = JSON.parse(account.quorum_keys);
    const params = walletParams({
      signers: keys.map(evmAddressOfPublicKey), threshold: account.required,
      palmSigner: account.palm_key, recoveryDays: Math.round(account.recovery_delay / 86400),
    });
    const salt = walletSalt(account.palm_vault_id);
    if (walletAddressOf(params, salt) !== String(account.address).toLowerCase()) {
      throw new HttpError(500, 'This Palm Wallet does not match its own settings.');
    }
    return { ...params, salt, keys, address: String(account.address).toLowerCase(), chainId: Number(description.chainId) };
  }

  /** What the account view says about a palm wallet. */
  async function palmWalletView(row) {
    const net = NETWORKS[row.network];
    const view = {
      signers: JSON.parse(row.quorum_keys).map(evmAddressOfPublicKey),
      palmSigner: row.palm_key,
      recoveryDelayDays: Math.round(row.recovery_delay / 86400),
      built: null,
      gasAccount: gasAccount()?.address ?? null,
      gasBalance: null,
      gasSymbol: net.symbol,
    };
    try {
      const evm = evmChainFor(row.network);
      const [code, gas] = await Promise.all([evm.code(row.address), view.gasAccount ? evm.balance(view.gasAccount) : null]);
      view.built = code !== '0x';
      view.gasBalance = gas === null ? null : format(gas, row.network);
    } catch (error) {
      if (!(error instanceof EvmChainError)) throw error;
    }
    return view;
  }

  /**
   * Locking an Ethereum or BSC account to the palm. The wallet's address is known now; the coins
   * move there in one transfer the owner's device signs, and the contract itself is built by the
   * gas account on the wallet's first payment.
   */
  async function requestEvmLock({ user, body, networkId }) {
    const net = NETWORKS[networkId];
    const wallet = await one('walletOf', user.id);
    if (!wallet) throw new HttpError(409, 'Create the wallet first.');
    if (wallet.custody !== CUSTODY.BROWSER) throw new HttpError(409, 'Move this vault into your browser first.');
    if (body.palm !== true) throw new HttpError(400, `${net.label} is locked to the palm, or not at all.`);
    const members = await all('membersOf', user.id);
    const account = await one('accountOn', user.id, networkId);
    if (!account) throw new HttpError(409, `This vault has no ${net.label} account.`);
    if (account.required) throw new HttpError(409, 'This account is already locked to the palm.');

    const signers = signersOf(account, members).map(id => members.find(m => m.member_id === id)).filter(Boolean);
    const without = signers.filter(m => !m.public_key);
    if (without.length) {
      throw new HttpError(409, `Everyone has to make a signing key first. Still waiting for: ${without.map(m => m.label).join(', ')}.`);
    }
    const required = Number(body.required);
    const floor = quorumFloor(signers.length);
    if (!Number.isInteger(required) || required < floor || required > signers.length) {
      throw new HttpError(400, `Choose between ${floor} and ${signers.length} signatures.`);
    }
    const days = body.recoveryDays === undefined || body.recoveryDays === null ? 365 : Number(body.recoveryDays);
    if (!RECOVERY_CHOICES.includes(days)) throw new HttpError(400, `Choose a recovery delay of ${RECOVERY_CHOICES.join(', ')} days.`);

    const keys = signers.map(m => m.public_key);
    const palmVaultId = randomId(16);
    let params;
    let palmAddress;
    try {
      palmAddress = (await palmSigner()).palmAddressFor(palmVaultId);
      params = walletParams({ signers: keys.map(evmAddressOfPublicKey), threshold: required, palmSigner: palmAddress, recoveryDays: days });
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(400, error instanceof PalmWalletError ? error.message : 'Those keys do not make a Palm Wallet.');
    }
    const address = walletAddressOf(params, walletSalt(palmVaultId));

    // Every coin of the account's own currency moves in one transfer; the gas for it comes out of it.
    const evm = evmChainFor(networkId);
    let transfer = null;
    try {
      const [balance, nonce, fees] = await Promise.all([evm.balance(account.address), evm.nonce(account.address), evm.fees()]);
      const value = BigInt(balance) - 21000n * BigInt(fees.maxFeePerGas);
      if (value > 0n) {
        transfer = canonicalTransfer({
          chain: 'evm', network: networkId, from: account.address,
          plan: {
            chainId: String(net.chainId), nonce, to: address, value: value.toString(10), data: '0x', gasLimit: '21000',
            maxFeePerGas: fees.maxFeePerGas, maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
          },
        });
      }
    } catch (error) {
      if (error instanceof EvmChainError) throw new HttpError(502, error.message);
      throw error;
    }
    const digest = transfer ? transferDigest(transfer) : null;
    const { required: palms } = await changeQuorum(user.id, networkId);
    const what = signers.length === 1 ? 'my palm' : `${required} of ${signers.length} and the palm`;
    const statement = transfer
      ? `Lock my ${net.label} to ${what} on the chain and move ${format(transfer.value, networkId)} ${net.symbol} to it`
      : `Lock my ${net.label} to ${what} on the chain`;
    const details = {
      action: 'lock to the palm on the chain',
      network: networkId,
      approvals_required: `${required} of ${signers.length} signature${signers.length === 1 ? '' : 's'} and the palm`,
      signers: signers.map(m => m.label).join(', '),
      to: address,
      effect: `from now on the ${net.label} network itself refuses any transfer from this account without a palm approval`,
      recovery: `if the palm signer is ever gone, the signers alone can schedule a transfer that runs after about ${days} days, and a palm approval can still cancel it`,
      ...lockWarning(required, signers.length, days),
      ...(transfer ? {
        amount_wei: transfer.value, chain_id: net.chainId, max_fee_per_gas: transfer.maxFeePerGas, transaction_hash: digest,
      } : { amount_wei: '0' }),
    };
    const op = await newOperation({
      walletOwnerId: user.id, user, kind: 'lock', statement, details,
      payload: {
        ...(transfer ?? {}), transactionHash: digest,
        quorum: { kind: 'palm-evm', palmVaultId, palmKey: palmAddress, keys, required, recoveryDays: days, address, chainId: net.chainId },
      },
      required: Math.max(palms, 1), networkId,
    });
    return { operation: operationView(op, [], user), quorum: { address, required, signers: signers.length, palm: true } };
  }

  /** Writes a palm wallet onto an EVM account, once its coins are on their way to it. */
  async function lockEvmAccount(op) {
    const { quorum } = JSON.parse(op.payload);
    const params = walletParams({
      signers: quorum.keys.map(evmAddressOfPublicKey), threshold: quorum.required, palmSigner: quorum.palmKey, recoveryDays: quorum.recoveryDays,
    });
    if (walletAddressOf(params, walletSalt(quorum.palmVaultId)) !== quorum.address) {
      throw new HttpError(500, 'The Palm Wallet no longer matches the one that was approved.');
    }
    const description = { kind: 'palm-wallet', chainId: quorum.chainId, deployer: DEPLOYER, ...params };
    await query('lockAccountToPalm', quorum.address, quorum.palmKey, quorum.required, JSON.stringify(quorum.keys),
      quorum.palmVaultId, quorum.palmKey, params.recoveryDelay, JSON.stringify(description), op.wallet_user_id, op.network);
  }

  /** A transfer out of a palm wallet: native coin, any amount up to everything in it. */
  async function palmWalletWithdrawal({ user, ownerId, account, networkId, body }) {
    const net = NETWORKS[networkId];
    const pw = palmWalletOf(account);
    const to = String(body.to ?? '').trim();
    if (!net.valid(to)) throw new HttpError(400, `That is not a valid ${net.label} address.`);
    const evm = evmChainFor(networkId);
    let balance;
    let nonce;
    try {
      const code = await evm.code(pw.address);
      [balance, nonce] = await Promise.all([
        evm.balance(pw.address),
        code === '0x' ? '0' : evm.call({ to: pw.address, data: NONCE_CALL }).then(raw => BigInt(raw).toString(10)),
      ]);
    } catch (error) {
      if (error instanceof EvmChainError) throw new HttpError(502, error.message);
      throw error;
    }
    const amount = body.amount === 'max' ? balance : String(body.amount ?? '').trim();
    if (!/^[1-9][0-9]*$/.test(amount)) throw new HttpError(400, `Enter an amount in the smallest unit (wei) of ${net.symbol}.`);
    if (BigInt(amount) > BigInt(balance)) throw new HttpError(400, `This wallet holds ${format(balance, networkId)} ${net.symbol}.`);

    const transfer = normalTransfer({ token: NATIVE, to, amount, nonce });
    const digest = evmTransferDigest({ chainId: pw.chainId, wallet: pw.address, transfer });
    const destination = await describeDestination(ownerId, networkId, to);
    const statement = `Send ${format(amount, networkId)} ${net.symbol} to ${destination.phrase}`;
    const details = {
      action: 'withdraw', network: networkId, to, ...destination.details,
      token: 'native', amount_units: amount, wallet: pw.address, chain_id: String(pw.chainId),
      approvals_required: `${pw.threshold} of ${pw.signers.length} signer${pw.signers.length === 1 ? '' : 's'} and the palm`,
      transaction_hash: digest,
    };
    const op = await newOperation({
      walletOwnerId: ownerId, user, kind: 'withdraw', statement, details,
      payload: { chain: 'evm-palm', network: networkId, chainId: pw.chainId, wallet: pw.address, transfer, transactionHash: digest },
      required: pw.threshold, networkId,
    });
    await appendEvidence(EVIDENCE.PROPOSAL_CREATED, {
      actor: user.id, subjectKind: 'operation', subjectId: op.id,
      userId: user.id, vaultId: pw.address, kind: 'withdraw', network: networkId, chain: 'evm',
      transactionHash: digest, threshold: pw.threshold, address: to,
    });
    return { operation: operationView(op, [], user), transfer, transactionHash: digest };
  }

  /** The signatures a palm wallet transfer has collected so far, by signer address. */
  const collectedOf = op => (op.psbt ? JSON.parse(op.psbt) : {});

  /** What one signer's browser needs to sign a palm wallet transfer with their own key. */
  async function palmWalletUnlock(op, account, user) {
    if (!['running', 'done'].includes(op.status)) throw new HttpError(409, 'This request is still collecting palm approvals.');
    if (op.txid) throw new HttpError(409, 'That transfer has already been sent.');
    const member = await one('memberIn', op.wallet_user_id, user.id);
    if (!member?.public_key || !JSON.parse(account.quorum_keys).includes(member.public_key)) {
      throw new HttpError(403, 'Your key is not one of the ones this wallet is locked to.');
    }
    const approvals = await all('approvalsOf', op.id);
    if (!approvals.some(a => a.user_id === user.id && a.status === 'approved')) throw new HttpError(409, 'Put your palm to this request first.');
    if (now() > signableAt(op, approvals) + UNLOCK_SECONDS) throw new HttpError(409, 'That approval has been used. Ask for a new palm scan.');
    const mine = await one('walletOf', user.id);
    if (mine?.custody !== CUSTODY.BROWSER) throw new HttpError(409, 'Move your own vault into this browser first.');
    const stored = JSON.parse(op.payload);
    const [members, wallet] = await Promise.all([all('membersOf', op.wallet_user_id), one('walletOf', op.wallet_user_id)]);
    return {
      authorizationId: op.id,
      walletId: mine.address,
      accountId: op.network,
      chain: 'evm',
      network: op.network,
      policyVersion: policyVersionOf(policyOfAccount(account, wallet), members),
      authorizationVersion: 1,
      bindingNonce: stored.transactionHash,
      unlock: openSealed(mine.unlock_sealed, vault()).toString('base64'),
      salt: mine.salt,
      keyIndex: member.key_index,
      signingKey: member.public_key,
      palmWallet: { chainId: stored.chainId, wallet: stored.wallet, transfer: stored.transfer },
      transactionHash: stored.transactionHash,
      required: account.required,
      signatures: Object.keys(collectedOf(op)).length,
    };
  }

  /**
   * One signer's signature on a palm wallet transfer. It must be over exactly the transfer the
   * palms approved and come from this signer's own key. Once there are enough, the palm signer is
   * handed Veyns' own decisions and adds the palm key's signature, and the gas account builds the
   * wallet if it is not built yet and submits the transfer.
   */
  async function palmWalletSignature(op, user, body) {
    const account = await one('accountOn', op.wallet_user_id, op.network);
    if (account?.lock_kind !== 'palm' || !account.required) throw new HttpError(409, 'That account is not a Palm Wallet.');
    const pw = palmWalletOf(account);
    const stored = JSON.parse(op.payload);
    if (stored.chain !== 'evm-palm' || String(stored.wallet).toLowerCase() !== pw.address) {
      throw new HttpError(409, 'That request is not for this Palm Wallet.');
    }
    const digest = evmTransferDigest({ chainId: pw.chainId, wallet: pw.address, transfer: stored.transfer });
    if (digest !== stored.transactionHash || digest !== JSON.parse(op.details).transaction_hash) {
      throw new HttpError(409, 'The stored transfer no longer matches the one that was approved.');
    }
    const member = await one('memberIn', op.wallet_user_id, user.id);
    if (!member?.public_key || !pw.keys.includes(member.public_key)) {
      throw new HttpError(403, 'Your key is not one of the ones this wallet is locked to.');
    }
    const approvals = await all('approvalsOf', op.id);
    if (!approvals.some(a => a.user_id === user.id && a.status === 'approved')) throw new HttpError(409, 'Put your palm to this request first.');

    const collected = collectedOf(op);
    const signerAddress = evmAddressOfPublicKey(member.public_key);
    if (body.signature !== undefined && !collected[signerAddress]) {
      const typed = eip712TransferDigest({ chainId: pw.chainId, wallet: pw.address, transfer: stored.transfer });
      let from;
      try {
        from = recoverAddress(typed, String(body.signature));
      } catch (error) {
        throw new HttpError(400, error instanceof PalmWalletError ? error.message : 'That is not a signature.');
      }
      if (from !== signerAddress) throw new HttpError(400, 'A browser may only add a signature from its own key.');
      collected[signerAddress] = String(body.signature);
      await query('setPsbt', JSON.stringify(collected), op.id);
    }
    const signatures = Object.keys(collected).length;
    if (signatures < pw.threshold) return { signatures, required: pw.threshold, txid: null };

    // Enough signers. The palm key's signature, from Veyns' own decisions, never this server's word.
    const signer = await palmSigner();
    if (signer.palmAddressFor(account.palm_vault_id) !== pw.palmSigner) {
      throw new HttpError(409, 'The palm signer no longer holds this wallet\'s palm key. Nothing was signed.');
    }
    const subjects = [];
    for (const holder of keyHoldersOf(account, await all('membersOf', op.wallet_user_id))) {
      const person = await one('userById', holder.member_id);
      if (person?.sub) subjects.push([person.sub, approvalSubject(person.sub)]);
    }
    let palm;
    try {
      palm = signer.signEvmTransfer({
        vaultId: account.palm_vault_id,
        wallet: { address: pw.address, chainId: pw.chainId, threshold: pw.threshold, signerSubs: subjects },
        transfer: stored.transfer,
        action: { statement: op.statement, details: JSON.parse(op.details) },
        decisions: approvals.filter(a => a.status === 'approved' && !a.invalidated_at && a.decision_token).map(a => a.decision_token),
      });
    } catch (error) {
      if (error instanceof PalmRefused) throw new HttpError(409, `The palm key refused to sign: ${error.message}.`);
      throw error;
    }
    const ordered = Object.keys(collected).sort().slice(0, pw.threshold).map(address => collected[address]);
    const txid = await relay(op.network, pw, transferCallOf(stored.transfer, ordered, palm.signature));
    await query('finishOperation', 'done', txid, null, now(), op.id);
    await appendEvidence(EVIDENCE.BROADCAST_ACCEPTED, {
      actor: user.id, subjectKind: 'operation', subjectId: op.id,
      userId: user.id, vaultId: pw.address, kind: 'withdraw', network: op.network, chain: 'evm', txid, transactionHash: digest,
    });
    return { signatures, required: pw.threshold, txid };
  }

  /**
   * The gas account sends a call to a palm wallet, building the wallet first if it is not built.
   * The two go out back to back, the second with the next nonce, so a first payment needs no
   * waiting in between.
   */
  async function relay(networkId, pw, data) {
    const gas = gasAccount();
    if (!gas) throw new HttpError(503, 'The gas account needs WALLET_SEED.');
    const net = NETWORKS[networkId];
    const evm = evmChainFor(networkId);
    const empty = `Palm's gas account on ${net.label} ${net.chain} needs ${net.symbol} to pay the network fee. Send some from a faucet to ${gas.address}, then sign again.`;
    try {
      const [code, nonce, fees, balance] = await Promise.all([evm.code(pw.address), evm.nonce(gas.address), evm.fees(), evm.balance(gas.address)]);
      const built = code !== '0x';
      const deploy = built ? null : deployCallOf(pw, pw.salt);
      const deployGas = built ? 0n : BigInt(await evm.estimateGas({ from: gas.address, to: DEPLOYER, data: deploy })) * 6n / 5n;
      const callGas = built
        ? BigInt(await evm.estimateGas({ from: gas.address, to: pw.address, data })) * 6n / 5n
        : 300000n; // the wallet is not there to estimate against until the first transaction lands
      if (BigInt(balance) < (deployGas + callGas) * BigInt(fees.maxFeePerGas)) throw new HttpError(409, empty);
      const send = async (to, callData, gasLimit, n) => {
        const { raw } = signRelayed({
          chainId: String(net.chainId), nonce: String(n), maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
          maxFeePerGas: fees.maxFeePerGas, gasLimit: gasLimit.toString(10), to, value: '0', data: callData,
        }, gas.key);
        return evm.broadcast(raw);
      };
      let next = BigInt(nonce);
      if (!built) await send(DEPLOYER, deploy, deployGas, next++);
      return await send(pw.address, data, callGas, next);
    } catch (error) {
      if (error instanceof HttpError) throw error;
      if (error instanceof EvmChainError) {
        if (/insufficient funds/i.test(error.message)) throw new HttpError(409, empty);
        throw new HttpError(502, error.message);
      }
      throw error;
    }
  }

  async function ownOperation(id, user) {
    const op = await one('operationById', id);
    if (!op) throw new HttpError(404, 'Request not found.');
    // The vault owner, anyone on its roster, and whoever started the request — an invited
    // person is none of the first two until their palm has landed.
    const allowed = op.wallet_user_id === user.id
      || op.started_by === user.id
      || await one('memberIn', op.wallet_user_id, user.id);
    if (!allowed) throw new HttpError(404, 'Request not found.');
    return op;
  }

  /** Puts your name to a pending request: creates your own approval row. */
  async function joinOperation({ user, params: [id] }) {
    requirePalmReady();
    const op = await ownOperation(id, user);
    if (op.kind !== 'unfreeze') await assertNotFrozen(op.wallet_user_id);
    if (op.status !== 'collecting') throw new HttpError(409, 'This request is no longer collecting approvals.');
    if (op.expires_at <= now()) throw new HttpError(409, 'This request has expired.');
    if (op.kind === 'join') {
      // The vault authorised the invitation; this palm is the invited person proving it is them.
      if (op.started_by !== user.id) throw new HttpError(403, 'Only the invited person can accept this.');
    } else if (op.kind !== 'create') {
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
        // Coins the chain guards move on the signatures of the keys they are locked to, and each
        // signer signs only after their own palm: a palm from anyone else could never be followed
        // by a signature, so it is not asked for.
        if (op.kind === 'withdraw' && account?.required
          && !keyHoldersOf(account, members).some(m => m.member_id === user.id)) {
          throw new HttpError(403, 'Your key is not one of the ones this vault is locked to, so your palm cannot count towards moving its coins.');
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

    // Veyns' own signed decision is kept, so a palm vault's signer can check it rather than trust this server.
    await query('setDecision', remote.decision_id, a.id, remote.decision);
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
    { method: 'POST', path: '/api/login/start', handler: loginStart, limit: RATE.login },
    { method: 'POST', path: '/api/login/finish', handler: loginFinish, limit: RATE.login },
    { method: 'POST', path: '/api/logout', handler: logout },
    { method: 'GET', path: '/api/price', handler: getPrice, auth: true, limit: RATE.upstream },
    { method: 'GET', path: '/api/scanner', handler: getScanner, auth: true },
    { method: 'GET', path: '/api/evidence', handler: exportAllEvidence, auth: true, limit: RATE.upstream },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/reconcile$/, handler: reconcileOne, auth: true, limit: RATE.unlock },
    { method: 'GET', path: '/api/evidence/checkpoint', handler: checkpointTarget, auth: true, limit: RATE.upstream },
    { method: 'POST', path: '/api/evidence/checkpoint', handler: registerCheckpoint, auth: true, limit: RATE.write },
    { method: 'GET', path: '/api/evidence/anchor', handler: anchorStatus, auth: true, limit: RATE.upstream },
    { method: 'POST', path: '/api/evidence/anchor/retry', handler: retryAnchors, auth: true, limit: RATE.write },
    { method: 'GET', path: /^\/api\/operations\/([\w-]{8,64})\/evidence$/, handler: exportEvidence, auth: true, limit: RATE.upstream },
    { method: 'GET', path: '/api/random', handler: getRandom, auth: true, limit: RATE.upstream },
    { method: 'GET', path: '/api/wallet', handler: getWallet, auth: true },
    { method: 'POST', path: '/api/wallet/approval', handler: requestWallet, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/wallet/register', handler: registerWallet, auth: true, limit: RATE.write },
    { method: 'POST', path: '/api/wallet/upgrade/approval', handler: requestUpgrade, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/wallet/upgrade', handler: completeUpgrade, auth: true, limit: RATE.unlock },
    { method: 'POST', path: '/api/invites/approval', handler: requestInvite, auth: true, limit: RATE.palm },
    { method: 'GET', path: '/api/invites', handler: listInvites, auth: true },
    { method: 'POST', path: '/api/invites/cancel', handler: cancelInvite, auth: true, limit: RATE.write },
    { method: 'POST', path: '/api/invites/join', handler: requestJoin, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/accounts/lock', handler: requestLock, auth: true, limit: RATE.spend },
    { method: 'POST', path: '/api/addresses/approval', handler: requestAddressName, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/vault/freeze', handler: freezeVault, auth: true, limit: RATE.write },
    { method: 'POST', path: '/api/vault/refresh/approval', handler: requestRefresh, auth: true, limit: RATE.spend },
    { method: 'POST', path: '/api/vault/move/approval', handler: requestMove, auth: true, limit: RATE.spend },
    { method: 'POST', path: '/api/vault/inheritance', handler: inheritanceSheet, auth: true, limit: RATE.upstream },
    { method: 'POST', path: '/api/recovery-door/plan', handler: recoveryDoorPlan, auth: true, limit: RATE.spend },
    { method: 'POST', path: '/api/recovery-door/send', handler: recoveryDoorSend, auth: true, limit: RATE.unlock },
    { method: 'GET', path: '/api/cron/reminders', handler: sendReminders },
    { method: 'POST', path: '/api/vault/unfreeze/approval', handler: requestUnfreeze, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/push/subscribe', handler: subscribePush, auth: true, limit: RATE.write },
    { method: 'POST', path: '/api/push/unsubscribe', handler: unsubscribePush, auth: true, limit: RATE.write },
    { method: 'POST', path: '/api/signing-key/approval', handler: requestSigningKey, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/signing-key/register', handler: registerSigningKey, auth: true, limit: RATE.write },
    { method: 'POST', path: '/api/attestation/approval', handler: requestAttestationRotation, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/attestation/register', handler: registerAttestationKey, auth: true, limit: RATE.write },
    { method: 'POST', path: '/api/wallet/reset/approval', handler: requestReset, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/wallet/reset', handler: completeReset, auth: true, limit: RATE.unlock },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/unlock$/, handler: unlockFor, auth: true, limit: RATE.unlock },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/broadcast$/, handler: broadcastSigned, auth: true, limit: RATE.unlock },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/signature$/, handler: addSignature, auth: true, limit: RATE.unlock },
    { method: 'GET', path: /^\/api\/operations\/([\w-]{8,64})\/receipt$/, handler: getReceipt, auth: true },
    { method: 'GET', path: /^\/api\/chain\/tx\/([0-9a-f]{64})$/, handler: chainTransaction, auth: true },
    { method: 'POST', path: '/api/policy', handler: requestPolicy, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/recovery', handler: requestRecovery, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/accounts/approval', handler: requestAccount, auth: true, limit: RATE.palm },
    { method: 'POST', path: '/api/accounts/register', handler: registerAccount, auth: true, limit: RATE.write },
    { method: 'POST', path: '/api/withdrawals', handler: requestWithdrawal, auth: true, limit: RATE.spend },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/approval$/, handler: joinOperation, auth: true, limit: RATE.palm },
    { method: 'POST', path: /^\/api\/operations\/([\w-]{8,64})\/cancel$/, handler: cancelOperation, auth: true, limit: RATE.write },
    { method: 'GET', path: /^\/api\/approvals\/([\w-]{8,64})$/, handler: readApproval, auth: true },
    { method: 'POST', path: /^\/api\/approvals\/([\w-]{8,64})\/palm$/, handler: startPalm, auth: true, limit: RATE.palm },
    { method: 'POST', path: /^\/api\/approvals\/([\w-]{8,64})\/cancel$/, handler: cancelApproval, auth: true, limit: RATE.write },
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

  function sendJson(res, status, body, cookies = [], extra = {}) {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...(cookies.length ? { 'set-cookie': cookies } : {}),
      ...extra,
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
      const user = route.auth ? await requireUser(cookies) : null;
      // After the session is resolved, so a user-keyed policy has a user to key on, and an
      // unauthenticated caller is turned away by the cheaper check first.
      await enforceLimit(route, req, user);
      const ctx = {
        params: route.params,
        cookies,
        body: req.method === 'POST' ? await readJson(req) : {},
        setCookie: (name, value, maxAge) => outCookies.push(cookieString(name, value, maxAge)),
        user,
        headers: req.headers,
      };
      sendJson(res, 200, await route.handler(ctx), outCookies);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : error instanceof ChainError ? 502 : 500;
      if (status === 500) log.error(error);
      sendJson(res, status, { error: status === 500 ? 'Something went wrong on the server.' : error.message }, outCookies,
        error.retryAfter ? { 'retry-after': String(error.retryAfter) } : {});
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
    // Idempotent: a test that closes an app explicitly, and a harness that closes it again on
    // teardown, must not between them turn a passing test into a double-close failure.
    async close() {
      if (closed) return;
      closed = true;
      await new Promise(resolve => {
        server.close(resolve);
        server.closeAllConnections();
      });
      if (dbPromise) await (await dbPromise.catch(() => null))?.close();
    },
  };
}
