/*
 * The upgrade path, not just the end state. A deployed database was built by an older copy of
 * this file, so every schema version this app has shipped is replayed in turn, with rows in
 * the tables, and the current schema has to land on top of each of them — twice, since every
 * cold start runs the migration again.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
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
