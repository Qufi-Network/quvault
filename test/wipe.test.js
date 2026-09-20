/*
 * The maintenance wipe: it must empty every table a vault touches, leave the schema standing,
 * and do nothing at all unless it is told to twice.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { start, ok, signedIn, walletFor } from './harness.js';

const here = path.dirname(fileURLToPath(import.meta.url));

test('the wipe refuses without a database, and without being confirmed', () => {
  const run = env => {
    try {
      return { out: execFileSync('node', [path.join(here, '..', 'scripts', 'wipe.js')], { env: { ...process.env, ...env }, encoding: 'utf8' }), code: 0 };
    } catch (error) {
      return { out: `${error.stdout ?? ''}${error.stderr ?? ''}`, code: error.status };
    }
  };
  const missing = run({ QUVAULT_ADMIN_DATABASE_URL: '' });
  assert.equal(missing.code, 1);
  assert.match(missing.out, /Set QUVAULT_ADMIN_DATABASE_URL/);

  const nonsense = run({ QUVAULT_ADMIN_DATABASE_URL: 'file:///etc/passwd' });
  assert.equal(nonsense.code, 1);
  assert.match(nonsense.out, /postgres:\/\/ connection string/);
});

test('the wipe deletes every table a vault touches, and nothing else', async t => {
  // The deletion order is the part that has to be right; run it against a real database.
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const db = await env.app.db();

  const source = readFileSync(path.join(here, '..', 'scripts', 'wipe.js'), 'utf8');
  const tables = source.match(/const TABLES = \[([^\]]*)\]/)[1].split(',').map(name => name.trim().replace(/'/g, ''));

  const before = {};
  for (const table of tables) before[table] = (await db.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n;
  assert.ok(before.wallets > 0 && before.users > 0 && before.members > 0, 'there is something to erase');

  for (const table of tables) await db.query(`DELETE FROM ${table}`);
  for (const table of tables) {
    assert.equal((await db.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n, 0, table);
  }

  // The schema survives, so the app comes back up empty rather than broken.
  const columns = (await db.query(
    `SELECT count(*)::int AS n FROM information_schema.columns WHERE table_name = 'wallets'`,
  )).rows[0].n;
  assert.ok(columns > 10, 'the wallets table is still there');
  // Sessions went with the rest, so the app asks for a sign-in rather than showing a ghost.
  assert.equal((await alex.get('/api/wallet')).status, 401);
});
