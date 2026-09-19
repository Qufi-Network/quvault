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
  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'operations_kind_v3') THEN
      ALTER TABLE operations DROP CONSTRAINT IF EXISTS operations_kind_check;
      ALTER TABLE operations ADD CONSTRAINT operations_kind_v3
        CHECK (kind IN ('create', 'withdraw', 'policy', 'recovery'));
    END IF;
  END $$`,
];

const INT8 = 20; // Timestamps are BIGINT; read them back as numbers.

export const isUniqueViolation = error => error?.code === '23505';

async function migrate(db) {
  await db.transaction(async q => {
    // Several cold-starting instances may race to create the schema.
    await q('SELECT pg_advisory_xact_lock(4970)');
    for (const statement of SCHEMA) await q(statement);
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
