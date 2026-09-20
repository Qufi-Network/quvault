/*
 * One small interface over Postgres: query(text, params) -> { rows, count } and transaction(fn).
 * Hosted: node-postgres with DATABASE_URL. Local and tests: PGlite (see db-local.js).
 */

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
       CHECK (kind IN ('create', 'withdraw', 'policy', 'recovery', 'account', 'upgrade', 'reset', 'attestation', 'invite', 'join'))`,
];

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

async function migrate(db) {
  await db.transaction(async q => {
    // Several cold-starting instances may race to create the schema.
    await q('SELECT pg_advisory_xact_lock(4970)');
    for (const [index, statement] of SCHEMA.entries()) {
      try {
        await q(statement);
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
