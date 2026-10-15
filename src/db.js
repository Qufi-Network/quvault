/*
 * One small interface over Postgres: query(text, params) -> { rows, count } and transaction(fn).
 * Hosted: node-postgres with DATABASE_URL. Local and tests: PGlite (see db-local.js).
 */
import crypto from 'node:crypto';
import {
  buildDescriptor, checkDescriptorStability, descriptorBytes, SELF_APPROVAL,
} from './policy-descriptor.js';
import { requiredToChange as quorumToChange, DEFAULT_POLICY } from './policy.js';

const newId = (bytes = 12) => crypto.randomBytes(bytes).toString('base64url');
const sha256Base64Url = text => crypto.createHash('sha256').update(text, 'utf8').digest('base64url');

/**
 * `ALTER TABLE … ADD CONSTRAINT` has no IF NOT EXISTS, and the whole schema re-runs on every
 * cold start, so the second run would fail on a constraint the first one added. Guarding on
 * the catalogue is the idempotent form.
 */
const addConstraint = (table, name, definition) => `DO $do$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${name}') THEN
    ALTER TABLE ${table} ADD CONSTRAINT ${name} ${definition};
  END IF;
END $do$`;

/**
 * The tenant key on a child table, and the composite foreign key that stops it disagreeing
 * with its parent.
 *
 * This is the load-bearing line of the whole tenancy design. The column is denormalised onto
 * every tenant-owned table so a query can scope directly — `WHERE organisation_id = $1` — which
 * means a MISSED scope returns nothing rather than everything. Denormalising normally costs you
 * a second copy of a fact that can drift; the composite FK removes that, because the database
 * refuses a child row naming an organisation its parent is not in, and refuses moving one later.
 *
 * A NULL organisation is still accepted, which is what lets this step be additive: the column
 * arrives, nothing reads it, and the backfill fills it in the same migration.
 */
const tenantColumn = (table, parentKey, parentTable, parentColumns, name) => [
  `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS organisation_id TEXT`,
  addConstraint(table, name,
    `FOREIGN KEY (organisation_id, ${parentKey}) REFERENCES ${parentTable} (${parentColumns})`),
];

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    sub        TEXT NOT NULL UNIQUE,            -- pairwise Veyns subject: only meaningful to this app
    created_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS sessions (
    id_hash    TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    expires_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS login_nonces (
    id         TEXT PRIMARY KEY,
    nonce      TEXT NOT NULL,
    expires_at BIGINT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS wallets (
    user_id     TEXT PRIMARY KEY REFERENCES users(id),
    network     TEXT NOT NULL,
    address     TEXT NOT NULL UNIQUE,
    public_key  TEXT NOT NULL,                  -- hex; safe to hold in the open
    sealed_key  TEXT NOT NULL,                  -- ML-KEM-768 + X25519 + AES-256-GCM envelope
    bound_sub   TEXT NOT NULL,                  -- the palm-verified account this wallet belongs to
    bound_decision TEXT NOT NULL,               -- Veyns decision id from the palm scan that created it
    created_at  BIGINT NOT NULL
  )`,
  // v2 replaced one-approval-per-action with operations that collect a quorum of palm approvals.
  // Nothing of value was stored under v1: a wallet only ever existed with an approval attached.
  `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'approvals' AND column_name = 'kind') THEN
      DROP TABLE approvals;
    END IF;
  END $$`,
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS policy TEXT',

  `CREATE TABLE IF NOT EXISTS members (
    wallet_user_id TEXT NOT NULL REFERENCES users(id),   -- the wallet this person can approve for
    member_id      TEXT NOT NULL REFERENCES users(id),
    label          TEXT NOT NULL,
    is_owner       BOOLEAN NOT NULL DEFAULT false,
    added_at       BIGINT NOT NULL,
    PRIMARY KEY (wallet_user_id, member_id)
  )`,
  'CREATE INDEX IF NOT EXISTS members_member ON members (member_id)',

  `CREATE TABLE IF NOT EXISTS operations (
    id             TEXT PRIMARY KEY,
    seq            BIGSERIAL,                            -- order of events, when two share a timestamp
    wallet_user_id TEXT NOT NULL REFERENCES users(id),
    started_by     TEXT NOT NULL REFERENCES users(id),
    kind           TEXT NOT NULL CHECK (kind IN ('create', 'withdraw', 'policy')),
    statement      TEXT NOT NULL,
    details        TEXT NOT NULL,
    digest         TEXT NOT NULL,                        -- every approver signs this exact action
    payload        TEXT,                                 -- the spend plan, or the proposed policy
    required       INTEGER NOT NULL CHECK (required >= 1),
    status         TEXT NOT NULL CHECK (status IN ('collecting', 'running', 'done', 'failed', 'cancelled')),
    txid           TEXT,
    error          TEXT,
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    closed_at      BIGINT
  )`,
  'CREATE INDEX IF NOT EXISTS operations_wallet ON operations (wallet_user_id, status)',

  `CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT PRIMARY KEY,              -- also the Veyns idempotency key and operation id
    operation_id TEXT NOT NULL REFERENCES operations(id),
    user_id      TEXT NOT NULL REFERENCES users(id),
    status       TEXT NOT NULL CHECK (status IN ('open', 'approved', 'failed', 'cancelled')),
    request_id   TEXT,
    challenge    TEXT,
    approval_url TEXT,
    decision_id  TEXT,
    acked        BOOLEAN NOT NULL DEFAULT false,
    proof_id     TEXT UNIQUE,                   -- one palm decision settles one approval
    error        TEXT,
    created_at   BIGINT NOT NULL,
    closed_at    BIGINT
  )`,
  'CREATE INDEX IF NOT EXISTS approvals_operation ON approvals (operation_id, status)',

  /*
   * v3: the key moved into the person's browser. The server keeps an address, a public key and
   * a sealed unlock secret that is useless without the encrypted blob on that device.
   * Approvals gained a slot, so one person can scan twice for the two-hand recovery ceremony.
   */
  'ALTER TABLE wallets ALTER COLUMN sealed_key DROP NOT NULL',
  "ALTER TABLE wallets ADD COLUMN IF NOT EXISTS custody TEXT NOT NULL DEFAULT 'server'",
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS unlock_sealed TEXT',
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS salt TEXT',
  'ALTER TABLE approvals ADD COLUMN IF NOT EXISTS slot INTEGER NOT NULL DEFAULT 1',
  'DROP INDEX IF EXISTS approvals_one_per_person',
  'CREATE UNIQUE INDEX IF NOT EXISTS approvals_one_per_slot ON approvals (operation_id, user_id, slot)',
  // v4: one vault, several accounts, one per network, all from the same phrase.
  `CREATE TABLE IF NOT EXISTS accounts (
    wallet_user_id TEXT NOT NULL REFERENCES users(id),
    network        TEXT NOT NULL,
    address        TEXT NOT NULL,
    public_key     TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    PRIMARY KEY (wallet_user_id, network)
  )`,
  /*
   * v5: a wallet made before the key moved into the browser can be moved in, which is its
   * own kind of operation. Older wallets also predate the accounts table, so the Bitcoin
   * account every wallet has is filled in from the wallet itself.
   */
  `INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at)
   SELECT user_id, 'bitcoin', address, public_key, created_at FROM wallets
   ON CONFLICT (wallet_user_id, network) DO NOTHING`,

  /*
   * v6: signers and thresholds belong to an account, not to the vault as a whole, so one
   * account can need two palms while another needs one. Accounts that predate this keep
   * exactly what the vault had. Operations record which account they are about.
   */
  'ALTER TABLE accounts ADD COLUMN IF NOT EXISTS policy TEXT',
  'ALTER TABLE accounts ADD COLUMN IF NOT EXISTS signers TEXT',
  'ALTER TABLE operations ADD COLUMN IF NOT EXISTS network TEXT',
  // The identity a person is given the first time they put their palm to this vault.
  'ALTER TABLE members ADD COLUMN IF NOT EXISTS palm_id TEXT',
  'ALTER TABLE members ADD COLUMN IF NOT EXISTS palm_at BIGINT',
  `UPDATE accounts a SET policy = w.policy FROM wallets w
   WHERE a.wallet_user_id = w.user_id AND a.policy IS NULL AND w.policy IS NOT NULL`,
  `UPDATE accounts a SET signers = (
     SELECT json_agg(m.member_id)::text FROM members m WHERE m.wallet_user_id = a.wallet_user_id
   ) WHERE a.signers IS NULL`,

  // v8: the signed record of the human authorisation that released a transaction.
  'ALTER TABLE operations ADD COLUMN IF NOT EXISTS human_authorization TEXT',

  /*
   * Every vault needs its owner on its roster. Vaults made by the first version — and any
   * made before the members table existed at all — never got that row, which left their
   * owners unable to approve anything at all, including erasing the vault. This puts it back.
   */
  `INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at)
   SELECT w.user_id, w.user_id, 'Owner', true, w.created_at FROM wallets w
   WHERE NOT EXISTS (SELECT 1 FROM members m WHERE m.wallet_user_id = w.user_id AND m.member_id = w.user_id)
   ON CONFLICT (wallet_user_id, member_id) DO NOTHING`,

  /*
   * v9: the key that signs those records belongs to the owner's browser. The server keeps the
   * public half and the epoch it was registered under, and holds nothing it could sign with.
   */
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS attestation_public_key TEXT',
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS attestation_epoch INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS attestation_at BIGINT',

  /*
   * v10: which attestation key is authoritative is decided by a signed chain of registrations,
   * not by a column. Epoch 1 signs its own registration; every later epoch is signed by the key
   * it replaces. A rewritten row cannot promote a key that no previous key vouched for.
   */
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS attestation_chain TEXT',
  // The root of that chain, sealed with the server seed, which lives outside the database.
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS attestation_root_seal TEXT',

  /*
   * v11: a signer joins by invitation. The vault's quorum authorises an invitation, which
   * carries a code; whoever holds that code proves their own palm to redeem it. The code is
   * the only secret, it is single use, and it expires.
   */
  `CREATE TABLE IF NOT EXISTS invites (
    code           TEXT PRIMARY KEY,
    wallet_user_id TEXT NOT NULL REFERENCES users(id),
    network        TEXT NOT NULL,
    label          TEXT NOT NULL,
    created_by     TEXT NOT NULL REFERENCES users(id),
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('open', 'used', 'cancelled')),
    used_by        TEXT REFERENCES users(id),
    used_at        BIGINT
  )`,
  'CREATE INDEX IF NOT EXISTS invites_wallet ON invites (wallet_user_id, status)',

  /*
   * v12: when the key was first opened for a request. One palm approval opens the key once,
   * for a few minutes; before this, a finished request went on handing out the same unlock
   * secret for as long as the browser's session lasted.
   */
  'ALTER TABLE operations ADD COLUMN IF NOT EXISTS unlocked_at BIGINT',

  /*
   * v13: the key a signer signs Bitcoin with, as opposed to the palm that says they meant to.
   * A quorum the chain keeps needs a public key per signer, derived in their own browser from
   * their own phrase on a branch of its own, so one person signing for several vaults keeps
   * one phrase and no two vaults share a key. The server holds the public half and the branch
   * number, both of which are safe in the open.
   */
  'ALTER TABLE members ADD COLUMN IF NOT EXISTS public_key TEXT',
  'ALTER TABLE members ADD COLUMN IF NOT EXISTS key_index INTEGER',
  'ALTER TABLE members ADD COLUMN IF NOT EXISTS key_at BIGINT',

  /*
   * v14: an account whose threshold the chain keeps rather than this server. The coins sit in
   * a P2WSH output holding an m-of-n script; 'required' and 'quorum_keys' are that script
   * written out, and public_key holds the script itself, so anyone can rebuild the address
   * without us. The address the account used before is kept: coins sent to it by somebody
   * working from an old note still arrive there, and the owner's key still opens them.
   */
  'ALTER TABLE accounts ADD COLUMN IF NOT EXISTS required INTEGER',
  'ALTER TABLE accounts ADD COLUMN IF NOT EXISTS quorum_keys TEXT',
  'ALTER TABLE accounts ADD COLUMN IF NOT EXISTS previous_address TEXT',

  /*
   * v15: the half-signed transaction a quorum is collecting. Signatures arrive one browser at
   * a time and have to wait somewhere for the rest; the partly signed transaction is that
   * place. It is not a secret — it is the approved transaction plus the signatures so far.
   */
  'ALTER TABLE operations ADD COLUMN IF NOT EXISTS psbt TEXT',

  /*
   * Which kinds of operation exist is decided by the code that is running, so the constraint
   * is simply restated on every migration: one statement, every old name dropped, today's
   * list added. Versioned names were a trap — a later version dropping an earlier one made
   * that earlier block think its work was undone, and it put the old, narrower list back.
   */
  `ALTER TABLE operations
     DROP CONSTRAINT IF EXISTS operations_kind_check,
     DROP CONSTRAINT IF EXISTS operations_kind_v3,
     DROP CONSTRAINT IF EXISTS operations_kind_v4,
     DROP CONSTRAINT IF EXISTS operations_kind_v5,
     DROP CONSTRAINT IF EXISTS operations_kind_v7,
     DROP CONSTRAINT IF EXISTS operations_kind,
     ADD CONSTRAINT operations_kind
       CHECK (kind IN ('create', 'withdraw', 'policy', 'recovery', 'account', 'upgrade', 'reset', 'attestation', 'invite', 'join', 'signing', 'lock'))`,

  /*
   * v14: rate limiting. One row per (policy, caller, window), counting requests.
   *
   * It lives here rather than in memory because this runs as a serverless function, where each
   * instance would keep its own count and a cold start would forget it — see src/rate-limit.js.
   *
   * The window start is part of the key, so a new window is a new row and an expired window is
   * simply a row with a past `expires_at`. Nothing in this table is a secret: a bucket names a
   * policy, a caller and a time, and holds an integer.
   */
  `CREATE TABLE IF NOT EXISTS rate_limits (
    bucket     TEXT PRIMARY KEY,
    hits       INTEGER NOT NULL,
    expires_at BIGINT NOT NULL
  )`,
  'CREATE INDEX IF NOT EXISTS rate_limits_expiry ON rate_limits (expires_at)',

  /*
   * v16: the evidence log. What happened, in an order nobody can quietly change.
   *
   * Append only, and enforced rather than asserted — the trigger below refuses UPDATE and
   * DELETE. That holds against every connection this application makes. It does NOT hold
   * against somebody privileged enough to drop the trigger, and `src/evidence.js` and
   * EVIDENCE.md both say so; this comment is not the place that overclaims it.
   *
   * `prev_hash` is UNIQUE, which is what orders concurrent writers without a lock: two
   * requests racing to append after the same entry both try to claim it as their predecessor,
   * one wins, the other retries against the new head. `scope` is null today and exists so an
   * organisation identifier can be recorded later without touching entries that predate
   * organisations.
   */
  `CREATE TABLE IF NOT EXISTS evidence (
    id              TEXT PRIMARY KEY,
    seq             BIGSERIAL,
    at              BIGINT NOT NULL,
    kind            TEXT NOT NULL,
    actor           TEXT,                       -- opaque user id, or null for the system
    scope           TEXT,                       -- organisation, when there are organisations
    subject_kind    TEXT,                       -- 'operation', 'wallet', …
    subject_id      TEXT,
    payload         TEXT NOT NULL,              -- canonical JSON, allowlisted and scrubbed
    prev_hash       TEXT NOT NULL,
    hash            TEXT NOT NULL UNIQUE,
    idempotency_key TEXT NOT NULL UNIQUE        -- a retry writes nothing new
  )`,
  'CREATE UNIQUE INDEX IF NOT EXISTS evidence_prev ON evidence (prev_hash)',
  'CREATE INDEX IF NOT EXISTS evidence_subject ON evidence (subject_id, seq)',
  'CREATE INDEX IF NOT EXISTS evidence_seq ON evidence (seq)',
  `CREATE OR REPLACE FUNCTION quvault_evidence_is_append_only() RETURNS trigger AS $quvault$
    BEGIN
      RAISE EXCEPTION 'the evidence log is append only: % is not permitted', TG_OP;
    END
  $quvault$ LANGUAGE plpgsql`,
  'DROP TRIGGER IF EXISTS evidence_append_only ON evidence',
  `CREATE TRIGGER evidence_append_only
     BEFORE UPDATE OR DELETE ON evidence
     FOR EACH ROW EXECUTE FUNCTION quvault_evidence_is_append_only()`,

  /*
   * v17: evidence checkpoints. A signed commitment to the log, made by a key the server has
   * never held — the owner's ML-DSA attestation key, derived from their recovery phrase.
   *
   * This is what the hash chain alone cannot do. An operator who rewrites every entry and
   * recomputes the chain still cannot produce a checkpoint matching the new head, because that
   * needs a post-quantum signature under a key they do not have. Append only, for the same
   * reason the evidence is: a checkpoint that can be replaced is not a commitment.
   */
  `CREATE TABLE IF NOT EXISTS evidence_checkpoints (
    id          TEXT PRIMARY KEY,
    wallet_user_id TEXT NOT NULL REFERENCES users(id),
    head        TEXT NOT NULL,              -- the evidence chain head it commits to
    entry_count INTEGER NOT NULL,
    at          BIGINT NOT NULL,
    key_id      TEXT NOT NULL,              -- which attestation key signed it
    checkpoint  TEXT NOT NULL,              -- the signed record, verbatim
    UNIQUE (wallet_user_id, head)
  )`,
  'CREATE INDEX IF NOT EXISTS evidence_checkpoints_wallet ON evidence_checkpoints (wallet_user_id, at)',
  'DROP TRIGGER IF EXISTS evidence_checkpoints_append_only ON evidence_checkpoints',
  `CREATE TRIGGER evidence_checkpoints_append_only
     BEFORE UPDATE OR DELETE ON evidence_checkpoints
     FOR EACH ROW EXECUTE FUNCTION quvault_evidence_is_append_only()`,

  /*
   * v18: what happened when a checkpoint was forwarded to an external sink.
   *
   * A separate table rather than columns on `evidence_checkpoints`, because that table is
   * append-only and recording an outcome later would mean updating a row the trigger forbids.
   * One row per attempt, so a sink outage followed by a success reads as exactly that — two
   * facts, in order — rather than a mutable "status" field that forgets the outage happened.
   *
   * `ref` is whatever the sink handed back. It is a convenience for an operator chasing a
   * record and is NOT evidence: this deployment could invent one. The proof that a checkpoint
   * is externally retained is a verifier fetching it from the sink themselves.
   */
  `CREATE TABLE IF NOT EXISTS evidence_anchors (
    id             TEXT PRIMARY KEY,
    checkpoint_id  TEXT NOT NULL REFERENCES evidence_checkpoints(id),
    wallet_user_id TEXT NOT NULL REFERENCES users(id),
    sink           TEXT NOT NULL,          -- which sink, by name
    result         TEXT NOT NULL,          -- STORED | REFUSED | UNREACHABLE | NOT_CONFIGURED
    ref            TEXT,                   -- the sink's own reference, if it gave one
    detail         TEXT,
    at             BIGINT NOT NULL
  )`,
  'CREATE INDEX IF NOT EXISTS evidence_anchors_checkpoint ON evidence_anchors (checkpoint_id, at)',
  'CREATE INDEX IF NOT EXISTS evidence_anchors_wallet ON evidence_anchors (wallet_user_id, at)',
  'DROP TRIGGER IF EXISTS evidence_anchors_append_only ON evidence_anchors',
  `CREATE TRIGGER evidence_anchors_append_only
     BEFORE UPDATE OR DELETE ON evidence_anchors
     FOR EACH ROW EXECUTE FUNCTION quvault_evidence_is_append_only()`,

  /* ==================================================================== v19 — organisations
   *
   * The tenant boundary gets its own identity. Until now the tenant key WAS a user id — every
   * table hangs off `wallet_user_id`, the owner's row in `users` — which means a treasury whose
   * identity is its founder's account cannot survive that person leaving and cannot hold two
   * owners. An organisation id is generated and is never a user id.
   *
   * Nothing reads any of this yet. v19–v24 are additive by design: they can be deployed, run
   * and left alone for a release while the backfill is proven under real traffic.
   */
  `CREATE TABLE IF NOT EXISTS organisations (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    /*
     * 'institutional' is the maker-checker default for anything created from now on.
     * 'single_owner' and 'migrated' are the two explicit exceptions the backfill writes, and
     * both of them permit self-approval. Three values rather than two: calling a grandfathered
     * three-member vault 'single_owner' would be a false statement in the data, and a vault
     * that permits self-approval because it predates the control is a different thing from one
     * that permits it because it has one member. See v20.
     */
    kind       TEXT NOT NULL DEFAULT 'institutional'
                 CHECK (kind IN ('institutional', 'single_owner', 'migrated')),
    created_at BIGINT NOT NULL
  )`,

  `CREATE TABLE IF NOT EXISTS org_members (
    organisation_id TEXT NOT NULL REFERENCES organisations(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    label           TEXT NOT NULL,
    added_by        TEXT REFERENCES users(id),
    added_at        BIGINT NOT NULL,
    /*
     * Revocation is a timestamp, not a deletion. Deleting the row would erase who was ever in
     * the organisation, leaving the append-only evidence log as the only record of a person the
     * operational tables deny existed. Nothing reads these two columns until the revocation
     * work lands; they are here so the shape is settled before anything depends on it.
     */
    revoked_at      BIGINT,
    revoked_by      TEXT REFERENCES users(id),
    PRIMARY KEY (organisation_id, user_id)
  )`,
  // Partial, because every live lookup is for a membership that has not been revoked.
  'CREATE INDEX IF NOT EXISTS org_members_user ON org_members (user_id) WHERE revoked_at IS NULL',

  `CREATE TABLE IF NOT EXISTS org_member_roles (
    organisation_id TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN
                      ('owner', 'administrator', 'operator', 'approver', 'auditor', 'viewer')),
    granted_by      TEXT REFERENCES users(id),
    granted_at      BIGINT NOT NULL,
    PRIMARY KEY (organisation_id, user_id, role),
    /*
     * One path to the organisation: a role reaches it THROUGH the membership, never beside it.
     * Two paths would mean two answers to "whose is this?", and eventually they disagree. The
     * cascade means a membership cannot be deleted leaving a role behind — though revocation
     * sets a timestamp rather than deleting, so the cascade is a backstop, not the mechanism.
     */
    FOREIGN KEY (organisation_id, user_id)
      REFERENCES org_members (organisation_id, user_id) ON DELETE CASCADE
  )`,

  /* ============================================================ v20 — one organisation each
   *
   * `wallets.organisation_id` lands here rather than with the other five tables, which is a
   * correction to the approved plan. The plan had v20 create organisations and v21 link them,
   * but then nothing connects the two: at v21 the only way to find which organisation belongs
   * to a wallet would be "the one whose sole owner-roled member is this wallet's user", which
   * is unambiguous only because v20 just created them, or a provenance column that could later
   * be mistaken for an authorisation path. Putting the link in the same step as the creation
   * removes the question. The five child tables follow in v21, unchanged.
   */
  'ALTER TABLE wallets ADD COLUMN IF NOT EXISTS organisation_id TEXT REFERENCES organisations(id)',
  // The parent key every child's composite foreign key points at.
  addConstraint('wallets', 'wallets_org_user', 'UNIQUE (organisation_id, user_id)'),
  'CREATE INDEX IF NOT EXISTS wallets_org ON wallets (organisation_id)',

  /*
   * The backfill. A function step rather than SQL because each wallet needs a fresh random id
   * and three dependent inserts that all have to name it; `WHERE organisation_id IS NULL` is
   * what makes it idempotent, so a second cold start finds nothing to do.
   *
   * What an existing user experiences afterwards must be exactly what they experience now.
   * That is the constraint that decides `selfApproval`, below.
   */
  async q => {
    const { rows } = await q(`SELECT user_id, created_at FROM wallets WHERE organisation_id IS NULL`);
    for (const wallet of rows) {
      const orgId = `org_${newId()}`;
      const at = Number(wallet.created_at);
      /*
       * Everyone who can approve for this vault today becomes a member who can approve for the
       * organisation. `members` is the signer roster and includes the owner; a vault old enough
       * to predate that table has no rows, so the owner stands alone.
       */
      const roster = await q(
        `SELECT member_id, label, is_owner FROM members WHERE wallet_user_id = $1 ORDER BY is_owner DESC, added_at`,
        [wallet.user_id]);
      const people = roster.rows.length
        ? roster.rows
        : [{ member_id: wallet.user_id, label: 'Owner', is_owner: true }];

      await q(
        `INSERT INTO organisations (id, name, kind, created_at) VALUES ($1, $2, $3, $4)`,
        [orgId, 'Treasury', people.length === 1 ? 'single_owner' : 'migrated', at]);

      for (const person of people) {
        await q(
          `INSERT INTO org_members (organisation_id, user_id, label, added_by, added_at)
           VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
          [orgId, person.member_id, person.label, wallet.user_id, at]);
        /*
         * Roles backfill to what the person can already do and no more: every signer approves
         * today, so every signer is an approver. Narrowing happens deliberately later, never by
         * a migration deciding somebody has lost a capability.
         */
        const roles = person.is_owner ? ['owner', 'approver'] : ['approver'];
        for (const role of roles) {
          await q(
            `INSERT INTO org_member_roles (organisation_id, user_id, role, granted_by, granted_at)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
            [orgId, person.member_id, role, wallet.user_id, at]);
        }
      }
      await q('UPDATE wallets SET organisation_id = $1 WHERE user_id = $2 AND organisation_id IS NULL',
        [orgId, wallet.user_id]);
    }
  },

  /* ======================================================== v21 — the tenant key on the rest
   *
   * Nullable, with the composite foreign key of `tenantColumn`, then populated from the wallet.
   * Still nothing reads it.
   */
  ...tenantColumn('accounts', 'wallet_user_id', 'wallets', 'organisation_id, user_id', 'accounts_in_org'),
  ...tenantColumn('operations', 'wallet_user_id', 'wallets', 'organisation_id, user_id', 'operations_in_org'),
  ...tenantColumn('invites', 'wallet_user_id', 'wallets', 'organisation_id, user_id', 'invites_in_org'),
  ...tenantColumn('members', 'wallet_user_id', 'wallets', 'organisation_id, user_id', 'members_in_org'),

  /*
   * An approval reaches its organisation through its operation, not through a wallet, so its
   * parent key is the operation and `operations` needs a composite UNIQUE for it to point at.
   */
  addConstraint('operations', 'operations_org_id', 'UNIQUE (organisation_id, id)'),
  ...tenantColumn('approvals', 'operation_id', 'operations', 'organisation_id, id', 'approvals_in_org'),

  /*
   * Populated as set-based statements: the database can do this itself, so a function step
   * would only be a slower way to get the same rows. Each is idempotent on IS NULL.
   *
   * Order matters: `approvals` reads `operations.organisation_id`, so operations go first.
   */
  `UPDATE accounts a SET organisation_id = w.organisation_id
     FROM wallets w WHERE w.user_id = a.wallet_user_id AND a.organisation_id IS NULL`,
  `UPDATE operations o SET organisation_id = w.organisation_id
     FROM wallets w WHERE w.user_id = o.wallet_user_id AND o.organisation_id IS NULL`,
  `UPDATE invites i SET organisation_id = w.organisation_id
     FROM wallets w WHERE w.user_id = i.wallet_user_id AND i.organisation_id IS NULL`,
  `UPDATE members m SET organisation_id = w.organisation_id
     FROM wallets w WHERE w.user_id = m.wallet_user_id AND m.organisation_id IS NULL`,
  `UPDATE approvals ap SET organisation_id = o.organisation_id
     FROM operations o WHERE o.id = ap.operation_id AND ap.organisation_id IS NULL`,

  'CREATE INDEX IF NOT EXISTS accounts_org ON accounts (organisation_id, network)',
  'CREATE INDEX IF NOT EXISTS operations_org ON operations (organisation_id, status)',
  'CREATE INDEX IF NOT EXISTS invites_org ON invites (organisation_id, status)',
  'CREATE INDEX IF NOT EXISTS members_org ON members (organisation_id)',
  'CREATE INDEX IF NOT EXISTS approvals_org ON approvals (organisation_id, operation_id)',

  /* ============================================================= v22 — versioned policies
   *
   * A policy stops being a column and becomes an immutable version. `digest` is taken over the
   * canonical descriptor and a later authorisation receipt will name the same digest, so these
   * bytes are frozen the moment the first row is written — with no migration available
   * afterwards, because the trigger forbids rewriting one.
   */
  `CREATE TABLE IF NOT EXISTS policies (
    id               TEXT PRIMARY KEY,
    organisation_id  TEXT NOT NULL REFERENCES organisations(id),
    wallet_user_id   TEXT NOT NULL REFERENCES users(id),
    network          TEXT NOT NULL,
    version          INTEGER NOT NULL CHECK (version >= 1),
    descriptor       TEXT NOT NULL,              -- canonical JSON; see src/policy-descriptor.js
    digest           TEXT NOT NULL,              -- base64url SHA-256 over exactly those bytes
    effective_from   BIGINT NOT NULL,
    created_by       TEXT NOT NULL REFERENCES users(id),
    /*
     * The palm-approved operation that produced this version. Null only for the version 1 row
     * the backfill writes, which records a policy that was already in force before policies
     * were versioned — there is no operation to point at, and inventing one would be a lie.
     */
    operation_id     TEXT REFERENCES operations(id),
    UNIQUE (organisation_id, wallet_user_id, network, version)
  )`,
  'CREATE INDEX IF NOT EXISTS policies_live ON policies (organisation_id, wallet_user_id, network, version DESC)',
  'DROP TRIGGER IF EXISTS policies_are_immutable ON policies',
  // Same guarantee and the same function as the evidence tables: a change writes a new row.
  `CREATE TRIGGER policies_are_immutable
     BEFORE UPDATE OR DELETE ON policies
     FOR EACH ROW EXECUTE FUNCTION quvault_evidence_is_append_only()`,

  /*
   * The version 1 backfill — and, before it writes anything, the stability guard.
   *
   * `checkDescriptorStability` recomputes a fixed reference descriptor, checks its exact bytes
   * against a locked value, checks that those bytes are valid JSON, that they survive a JSON
   * round trip, that the order the fields were supplied in does not change them, and that the
   * digest matches a locked vector deterministically. If any of that has moved, it throws and
   * the migration writes nothing: digests nobody can reproduce are worse than no digests, and
   * these rows cannot be corrected.
   */
  q => backfillPolicyVersions(q),

  /* ===================================================== v23 — a proposal names its version
   *
   * A proposal is judged against the rules that were in force when it was raised, so it points
   * at a policy VERSION rather than at a policy. Pending operations get the version 1 row,
   * which is the one that was in force when they were raised.
   */
  'ALTER TABLE operations ADD COLUMN IF NOT EXISTS policy_id TEXT REFERENCES policies(id)',
  'CREATE INDEX IF NOT EXISTS operations_policy ON operations (policy_id)',
  `UPDATE operations o SET policy_id = p.id
     FROM policies p
    WHERE p.wallet_user_id = o.wallet_user_id
      AND p.network = COALESCE(o.network, 'bitcoin')
      AND p.version = 1
      AND o.policy_id IS NULL`,

  /* ================================================== v24 — an approval that no longer counts
   *
   * Revocation has to take effect on proposals already in flight without touching the evidence
   * that the approval happened. The evidence entry is permanent and stays true; these columns
   * are what decides whether it still counts toward a quorum. Nothing reads them yet.
   *
   * `operations.required` is deliberately NOT given a way to change: a threshold lowered to
   * rescue a proposal is the silent weakening this whole design refuses.
   */
  'ALTER TABLE approvals ADD COLUMN IF NOT EXISTS invalidated_at BIGINT',
  'ALTER TABLE approvals ADD COLUMN IF NOT EXISTS invalidated_by TEXT REFERENCES users(id)',
  'ALTER TABLE approvals ADD COLUMN IF NOT EXISTS invalidated_reason TEXT',
  addConstraint('approvals', 'approvals_invalidated_reason',
    `CHECK (invalidated_reason IS NULL OR invalidated_reason IN
      ('approver_revoked', 'role_removed', 'policy_changed', 'plan_changed'))`),
  // Every live quorum count reads only the approvals that still stand.
  'CREATE INDEX IF NOT EXISTS approvals_standing ON approvals (operation_id) WHERE invalidated_at IS NULL',
];

/**
 * v22's backfill: one immutable version 1 policy per account, and the guard that runs first.
 *
 * Exported and taking its dependencies, for one reason: the guard's whole value is that it
 * runs BEFORE anything is persisted, and that ordering is a claim worth a test rather than a
 * comment. A test passes a failing `check` and asserts the table is still empty.
 *
 * `digest` is taken over the canonical descriptor and a later receipt will name the same
 * digest, so these bytes are frozen once the first row exists — the trigger forbids rewriting
 * one. Digests nobody can reproduce would be worse than no digests at all, so if the canonical
 * form has moved this writes nothing and the migration fails loudly.
 */
export async function backfillPolicyVersions(q, {
  check = checkDescriptorStability, digestOf = sha256Base64Url, idOf = () => `pol_${newId()}`,
} = {}) {
  check(digestOf);

  const { rows } = await q(
    `SELECT a.wallet_user_id, a.network, a.policy AS account_policy, a.created_at,
            w.policy AS wallet_policy, w.organisation_id
       FROM accounts a JOIN wallets w ON w.user_id = a.wallet_user_id
      WHERE w.organisation_id IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM policies p
           WHERE p.wallet_user_id = a.wallet_user_id AND p.network = a.network AND p.version = 1)`);

  for (const row of rows) {
    // Exactly the fallback the application uses: the account's rules, else the vault's, else
    // the default. Reading it differently here would record a policy that was never in force.
    const stored = row.account_policy ?? row.wallet_policy;
    const policy = stored ? JSON.parse(stored) : DEFAULT_POLICY;
    const counted = await q(
      'SELECT count(*)::int AS n FROM org_members WHERE organisation_id = $1 AND revoked_at IS NULL',
      [row.organisation_id]);
    const approverCount = Math.max(1, counted.rows[0].n);

    /*
     * Every migrated organisation gets `selfApproval: 'permitted'`, and this is the one
     * decision in v22 worth arguing with.
     *
     * Today a proposer can approve their own proposal in any vault. Writing 'forbidden' here
     * would not merely tighten a control, it would make existing vaults UNSPENDABLE: three
     * members with a three-approval rule cannot reach three if the proposer is excluded. So the
     * grandfathered permission is preserved, written explicitly, and visible both in the
     * descriptor and in `organisations.kind`. Explicit and disclosed, not inherited silently.
     * Organisations created after this default to 'institutional' and 'forbidden'.
     */
    const descriptor = buildDescriptor({
      rules: policy.rules?.length ? policy.rules : DEFAULT_POLICY.rules,
      selfApproval: SELF_APPROVAL.PERMITTED,
      approverCount,
      requiredToChange: quorumToChange(policy, approverCount),
    });
    const bytes = descriptorBytes(descriptor);

    await q(
      `INSERT INTO policies (id, organisation_id, wallet_user_id, network, version,
                             descriptor, digest, effective_from, created_by, operation_id)
       VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8, NULL)
       ON CONFLICT (organisation_id, wallet_user_id, network, version) DO NOTHING`,
      [idOf(), row.organisation_id, row.wallet_user_id, row.network, bytes,
        digestOf(bytes), Number(row.created_at), row.wallet_user_id]);
  }
  return rows.length;
}

const INT8 = 20; // Timestamps are BIGINT; read them back as numbers.

export const isUniqueViolation = error => error?.code === '23505';

/**
 * Says where a database failure happened and what Postgres called it, without repeating
 * anything from the connection string: enough to act on, nothing worth hiding.
 */
export const describeDbError = error => {
  const stage = error?.dbStage ?? 'connect';
  const step = error?.dbStatement === undefined ? '' : ` at statement ${error.dbStatement}`;
  return `${stage}${step}: ${error?.code || error?.name || 'unknown'}`;
};

/*
 * Runs the schema in order, in one transaction, under one lock.
 *
 * A step is either a SQL string or a function `q => …`. The functions exist because two of the
 * v19–v24 backfills cannot be expressed in SQL: one needs a fresh random id per row plus three
 * dependent inserts, and one has to compute a SHA-256 over a canonical JSON descriptor and
 * refuse to write at all if that serialisation has moved. Everything that can be a single
 * set-based statement still is one — a function step is for computation, not for looping over
 * work the database could do itself.
 *
 * Every step, string or function, must be idempotent: the whole array runs on every cold start.
 */
async function migrate(db) {
  await db.transaction(async q => {
    // Several cold-starting instances may race to create the schema.
    await q('SELECT pg_advisory_xact_lock(4970)');
    for (const [index, step] of SCHEMA.entries()) {
      try {
        if (typeof step === 'function') await step(q);
        else await q(step);
      } catch (error) {
        error.dbStage = 'migrate';
        error.dbStatement = index;
        throw error;
      }
    }
  });
}

async function openPostgres(url) {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({
    connectionString: url,
    max: 5,
    idleTimeoutMillis: 5_000,
    connectionTimeoutMillis: 10_000,
    types: { getTypeParser: (oid, format) => (oid === INT8 ? Number : pg.types.getTypeParser(oid, format)) },
  });
  const wrap = result => ({ rows: result.rows, count: result.rowCount ?? 0 });
  return {
    query: async (text, params) => wrap(await pool.query(text, params)),
    async transaction(fn) {
      for (let attempt = 1; ; attempt++) {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          const result = await fn(async (text, params) => wrap(await client.query(text, params)));
          await client.query('COMMIT');
          return result;
        } catch (error) {
          await client.query('ROLLBACK').catch(() => {});
          if (error?.code === '40P01' && attempt < 3) continue; // deadlock victim: run it again
          throw error;
        } finally {
          client.release();
        }
      }
    },
    close: () => pool.end(),
  };
}

/** Opens Postgres when a URL is given, otherwise PGlite (in memory, or persisted under `dir`). */
export async function openDb({ url, dir }) {
  let db;
  if (url) {
    db = await openPostgres(url);
  } else {
    // A computed specifier keeps PGlite (a dev dependency) out of the deployed function bundle.
    const localModule = './db-local.js';
    const { openPglite } = await import(localModule);
    db = await openPglite(dir, INT8);
  }
  await migrate(db);
  return db;
}
