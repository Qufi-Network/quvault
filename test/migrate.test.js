/*
 * The upgrade path, not just the end state. A deployed database was built by an older copy of
 * this file, so every schema version this app has shipped is replayed in turn, with rows in
 * the tables, and the current schema has to land on top of each of them — twice, since every
 * cold start runs the migration again.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDb } from '../src/db.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const src = path.join(here, '..', 'src');

// Every commit that changed the schema, oldest first.
const RELEASES = [
  ['29fc91c', 'the first wallet'],
  ['d55f8ec', 'spending rules and quorums'],
  ['66972e4', 'keys heading for the browser'],
  ['9aed4a0', 'accounts on five networks'],
  ['48d4139', 'signers per account'],
];

/** Loads a past version of db.js beside the current one, so its relative imports still work. */
async function openAt(commit, dir) {
  const file = path.join(src, `_replay_${commit}.js`);
  writeFileSync(file, execFileSync('git', ['show', `${commit}:src/db.js`], { cwd: path.join(here, '..') }));
  try {
    const module = await import(`../src/_replay_${commit}.js?v=${commit}`);
    return await module.openDb({ dir });
  } finally {
    unlinkSync(file);
  }
}

/** The rows a real vault has, in the shape that version of the schema allowed. */
async function seed(db, tag) {
  const time = 1_700_000_000;
  await db.query('INSERT INTO users (id, sub, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [`u-${tag}`, `sub-${tag}`, time]);
  const columns = await db.query(
    `SELECT column_name FROM information_schema.columns WHERE table_name = 'wallets'`,
  );
  const names = columns.rows.map(row => row.column_name);
  const has = name => names.includes(name);
  const policy = JSON.stringify({ rules: [{ upToSats: null, approvals: 1 }] });
  await db.query(
    `INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at${has('policy') ? ', policy' : ''})
     VALUES ($1, 'testnet4', $2, $3, 'sealed', $4, 'decision', $5${has('policy') ? ', $6' : ''})
     ON CONFLICT DO NOTHING`,
    [`u-${tag}`, `tb1-${tag}`, 'aa'.repeat(33), `sub-${tag}`, time, ...(has('policy') ? [policy] : [])],
  );
  const tables = (await db.query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`)).rows.map(r => r.table_name);
  if (tables.includes('members')) {
    await db.query(
      'INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at) VALUES ($1, $1, $2, true, $3) ON CONFLICT DO NOTHING',
      [`u-${tag}`, 'Owner', time],
    );
  }
  if (tables.includes('operations')) {
    await db.query(
      `INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest, required, status, created_at, expires_at)
       VALUES ($1, $2, $2, 'create', 'Create a wallet', '{}', 'digest', 1, 'done', $3, $3) ON CONFLICT DO NOTHING`,
      [`op-${tag}`, `u-${tag}`, time],
    );
  }
}

for (const [commit, what] of RELEASES) {
  test(`a database built by "${what}" migrates to today`, async t => {
    const dir = mkdtempSync(path.join(tmpdir(), 'quvault-migrate-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const old = await openAt(commit, dir);
    await seed(old, commit.slice(0, 4));
    await old.close();

    const db = await openDb({ dir });
    // Everything today's code expects is there, and the rows survived.
    const columns = (await db.query(
      `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'`,
    )).rows.map(row => `${row.table_name}.${row.column_name}`);
    for (const column of ['accounts.policy', 'accounts.signers', 'operations.network', 'members.palm_id', 'wallets.custody']) {
      assert.ok(columns.includes(column), `${column} is missing after migrating from ${commit}`);
    }
    // The tenancy columns, which land on top of every one of these historical schemas.
    for (const column of [
      'wallets.organisation_id', 'accounts.organisation_id', 'operations.organisation_id',
      'approvals.organisation_id', 'invites.organisation_id', 'members.organisation_id',
      'operations.policy_id', 'approvals.invalidated_at', 'policies.digest',
    ]) {
      assert.ok(columns.includes(column), `${column} is missing after migrating from ${commit}`);
    }
    assert.equal((await db.query('SELECT count(*)::int AS n FROM wallets')).rows[0].n, 1);
    assert.equal(
      (await db.query(`SELECT count(*)::int AS n FROM accounts WHERE network = 'bitcoin'`)).rows[0].n, 1,
      'the Bitcoin account is filled in from the wallet',
    );
    // Vaults from before the members table, and from the first version, get their owner back:
    // without that row nobody can approve anything for them, including erasing them.
    const owner = (await db.query(`SELECT * FROM members WHERE is_owner = true`)).rows;
    assert.equal(owner.length, 1, `the owner is on the roster after migrating from ${commit}`);
    assert.equal(owner[0].wallet_user_id, owner[0].member_id);

    /*
     * The tenancy backfill, on data that existed before tenancy did. A fresh database cannot
     * show any of this, because every row in it was created after the migration.
     */
    const wallet = (await db.query('SELECT user_id, organisation_id FROM wallets')).rows[0];
    assert.ok(wallet.organisation_id, `the vault got an organisation migrating from ${commit}`);
    const roles = (await db.query(
      `SELECT role FROM org_member_roles WHERE organisation_id = $1 AND user_id = $2 ORDER BY role`,
      [wallet.organisation_id, wallet.user_id])).rows.map(r => r.role);
    assert.deepEqual(roles, ['approver', 'owner'],
      'the owner can still approve: a migration never removes a capability');

    // One immutable policy version per account, with a digest over exactly its own descriptor.
    const policies = (await db.query('SELECT network, version, descriptor, digest FROM policies')).rows;
    assert.ok(policies.length >= 1, `a policy version was recorded migrating from ${commit}`);
    for (const policy of policies) {
      assert.equal(policy.version, 1);
      assert.equal(policy.digest, createHash('sha256').update(policy.descriptor, 'utf8').digest('base64url'),
        'the stored digest must be reproducible from the stored descriptor');
      // Grandfathered vaults keep the self-approval they already had, stated rather than implied.
      assert.equal(JSON.parse(policy.descriptor).selfApproval, 'permitted');
    }

    // And every scoped child agrees with its wallet, which the composite keys enforce anyway.
    for (const table of ['accounts', 'operations', 'invites', 'members']) {
      const drift = await db.query(
        `SELECT count(*)::int AS n FROM ${table} t JOIN wallets w ON w.user_id = t.wallet_user_id
          WHERE t.organisation_id IS DISTINCT FROM w.organisation_id`);
      assert.equal(drift.rows[0].n, 0, `${table} drifted from its wallet migrating from ${commit}`);
    }

    // The newest operation kinds are allowed by whatever constraint now stands.
    for (const kind of ['upgrade', 'reset', 'account', 'recovery']) {
      await db.query(
        `INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest, required, status, created_at, expires_at)
         VALUES ($1, $2, $2, $3, 'Statement', '{}', 'digest', 1, 'collecting', 1, 2)`,
        [`op-${kind}-${commit}`, `u-${commit.slice(0, 4)}`, kind],
      );
    }
    await db.close();

    // Every cold start migrates again, so it has to be safe to repeat.
    const again = await openDb({ dir });
    assert.equal((await again.query('SELECT count(*)::int AS n FROM wallets')).rows[0].n, 1);
    await again.close();
  });
}
