/*
 * The additive tenancy migrations, v19 to v24.
 *
 * These add an organisation boundary and nothing reads it yet, which is the point: they can be
 * deployed and left alone for a release while the backfill is proven under real traffic. So
 * what these tests check is not behaviour — there is no new behaviour — but the three things
 * that are expensive to get wrong and impossible to fix later:
 *
 *   1. the constraints actually hold, in this engine, against rows that try to break them;
 *   2. the backfill preserves exactly what each existing vault could already do;
 *   3. the canonical policy descriptor is frozen before a single digest is persisted.
 *
 * A populated database is the case that matters. A fresh one cannot show any of this, because
 * every row in it was created after the migration.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDb, backfillPolicyVersions } from '../src/db.js';
import {
  buildDescriptor, checkDescriptorStability, descriptorBytes, DescriptorError,
  REFERENCE_BYTES, REFERENCE_DIGEST, REFERENCE_INPUT, SELF_APPROVAL,
} from '../src/policy-descriptor.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const digestOf = text => crypto.createHash('sha256').update(text, 'utf8').digest('base64url');

/** A database at the current schema, cleaned up afterwards. */
async function fresh(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'qv-org-'));
  const db = await openDb({ dir });
  t.after(async () => {
    await db.close?.().catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  });
  return { db, dir };
}

/* ------------------------------------------------- the descriptor, before anything is written */

test('the policy descriptor digest is locked to a vector, and the guard catches a change', () => {
  // The guard the v22 migration runs before it persists anything.
  const { bytes, digest } = checkDescriptorStability(digestOf);
  assert.equal(bytes, REFERENCE_BYTES);
  assert.equal(digest, REFERENCE_DIGEST);

  /*
   * The vector earns its place only if it fails when the form moves. Each of these is a change
   * somebody could plausibly make, and each must be caught rather than silently producing
   * digests that no longer describe the rows already stored.
   */
  assert.throws(() => checkDescriptorStability(() => 'a-different-digest'),
    /digest has changed/, 'a changed hash must be caught');
  assert.throws(() => checkDescriptorStability(text => digestOf(`${text} `)),
    /digest has changed/, 'a changed input to the hash must be caught');
  let calls = 0;
  assert.throws(() => checkDescriptorStability(text => (calls++ ? 'x' : digestOf(text))),
    /not deterministic|digest has changed/, 'a non-deterministic hash must be caught');
  assert.throws(() => checkDescriptorStability('not a function'), /needs a digest function/);
});

test('a descriptor survives the round trip a database and a network make of it', () => {
  const descriptor = buildDescriptor(REFERENCE_INPUT);
  const bytes = descriptorBytes(descriptor);

  // The exact path a stored descriptor takes: canonicalised, written as text, parsed back.
  assert.equal(descriptorBytes(JSON.parse(JSON.stringify(descriptor))), bytes);
  assert.equal(descriptorBytes(JSON.parse(bytes)), bytes);
  assert.deepEqual(JSON.parse(bytes), descriptor);
  assert.ok(!bytes.includes('undefined'), 'the bytes must be JSON, not JavaScript');

  // The order fields and roles were supplied in must not reach the digest.
  const reordered = buildDescriptor({
    requiredToChange: REFERENCE_INPUT.requiredToChange,
    selfApproval: REFERENCE_INPUT.selfApproval,
    approverCount: REFERENCE_INPUT.approverCount,
    rules: REFERENCE_INPUT.rules.map(r => ({
      requiredRoles: [...r.requiredRoles].reverse(), approvals: r.approvals, upToSats: r.upToSats,
    })),
  });
  assert.equal(descriptorBytes(reordered), bytes, 'role order is a set, not a sequence');

  // But the rule ladder IS a sequence, and reversing it is a different policy.
  const swapped = buildDescriptor({
    ...REFERENCE_INPUT,
    rules: [REFERENCE_INPUT.rules[1], { ...REFERENCE_INPUT.rules[0], upToSats: null }],
  });
  assert.notEqual(descriptorBytes(swapped), bytes, 'rule order is significant and must reach the digest');
});

test('the permissive self-approval value is never reachable by omission', () => {
  // The institutional default is maker-checker. A field that fell back to 'permitted' when
  // absent would be a control that disappears whenever somebody forgets to state it.
  for (const bad of [undefined, null, '', 'yes', 'allowed', true]) {
    assert.throws(() => buildDescriptor({ ...REFERENCE_INPUT, selfApproval: bad }),
      DescriptorError, `selfApproval: ${String(bad)} must be refused`);
  }
  assert.ok(buildDescriptor({ ...REFERENCE_INPUT, selfApproval: SELF_APPROVAL.FORBIDDEN }));
  assert.ok(buildDescriptor({ ...REFERENCE_INPUT, selfApproval: SELF_APPROVAL.PERMITTED }));

  // And the rest of the shape is checked rather than coerced.
  assert.throws(() => buildDescriptor({ ...REFERENCE_INPUT, rules: [] }), /at least one rule/);
  assert.throws(() => buildDescriptor({ ...REFERENCE_INPUT, approverCount: 0 }), /count its approvers/);
  assert.throws(() => buildDescriptor({ ...REFERENCE_INPUT, requiredToChange: 0 }), /how many approvals/);
  assert.throws(() => buildDescriptor({
    ...REFERENCE_INPUT, rules: [{ upToSats: null, approvals: 1, requiredRoles: ['wizard'] }],
  }), /Unknown role/);
  assert.throws(() => buildDescriptor({
    ...REFERENCE_INPUT, rules: [{ upToSats: null, approvals: 1, requiredRoles: [] }],
  }), /at least one role/);
  assert.throws(() => buildDescriptor({
    ...REFERENCE_INPUT, rules: [{ upToSats: 1.5, approvals: 1 }],
  }), /whole number of satoshis/);
});

test('v22 persists no digest at all if the canonical form has moved', async t => {
  const { db } = await fresh(t);
  const q = (text, params) => db.query(text, params);

  /*
   * The ordering claim, tested rather than asserted in a comment: the stability guard runs
   * BEFORE anything is written, so a deployment whose canonical form has drifted writes no
   * digests instead of writing ones nobody can reproduce. It matters because `policies` rows
   * are immutable — there is no second chance to correct them.
   *
   * The fresh database has a vault and an account with no policy version yet, so there is
   * genuinely something for the backfill to write.
   */
  await q(`INSERT INTO organisations (id, name, kind, created_at) VALUES ('o1', 'A', 'institutional', 1)`);
  await q(`INSERT INTO users (id, sub, created_at) VALUES ('u1', 's1', 1)`);
  await q(`INSERT INTO org_members (organisation_id, user_id, label, added_at) VALUES ('o1', 'u1', 'Owner', 1)`);
  await q(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, organisation_id)
           VALUES ('u1', 'testnet4', 'tb1a', 'aa', 'k', 's1', 'd', 1, 'o1')`);
  await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at, organisation_id)
           VALUES ('u1', 'bitcoin', 'tb1a', 'aa', 1, 'o1')`);

  const before = await q('SELECT count(*)::int AS n FROM policies');

  await assert.rejects(
    () => backfillPolicyVersions(q, { check: () => { throw new DescriptorError('the form moved'); } }),
    /the form moved/, 'the backfill must refuse rather than write');

  const after = await q('SELECT count(*)::int AS n FROM policies');
  assert.equal(after.rows[0].n, before.rows[0].n, 'not one row may be written past a failed guard');
  assert.equal(after.rows[0].n, 0);

  // The control: with the real guard, the same call writes exactly what was missing. Without
  // this, the test above would pass against a backfill that never writes anything at all.
  const written = await backfillPolicyVersions(q);
  assert.equal(written, 1);
  const rows = await q('SELECT descriptor, digest FROM policies');
  assert.equal(rows.rows.length, 1);
  assert.equal(rows.rows[0].digest, digestOf(rows.rows[0].descriptor));
});

/* ------------------------------------------------------------------- the constraints hold */

test('a child row cannot claim an organisation its parent is not in', async t => {
  const { db } = await fresh(t);
  const q = (text, params) => db.query(text, params);

  await q(`INSERT INTO organisations (id, name, kind, created_at) VALUES ('oA', 'A', 'institutional', 1)`);
  await q(`INSERT INTO organisations (id, name, kind, created_at) VALUES ('oB', 'B', 'institutional', 1)`);
  await q(`INSERT INTO users (id, sub, created_at) VALUES ('uA', 'sA', 1)`);
  await q(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, organisation_id)
           VALUES ('uA', 'testnet4', 'tbA', 'aa', 'k', 'sA', 'd', 1, 'oA')`);

  // The one that must work.
  await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at, organisation_id)
           VALUES ('uA', 'bitcoin', 'tbA', 'aa', 1, 'oA')`);

  /*
   * This is the load-bearing guarantee of the whole tenancy design: the tenant key is
   * denormalised onto every table so a query scopes directly and a MISSED scope returns
   * nothing — and the composite foreign key is what stops the denormalised copy drifting from
   * its parent. Cross-tenant corruption is refused by the database, not by discipline.
   */
  await assert.rejects(
    () => q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at, organisation_id)
             VALUES ('uA', 'litecoin', 'tbX', 'bb', 1, 'oB')`),
    /foreign key constraint/, 'a child naming another organisation must be refused');

  await assert.rejects(
    () => q(`UPDATE accounts SET organisation_id = 'oB' WHERE wallet_user_id = 'uA' AND network = 'bitcoin'`),
    /foreign key constraint/, 'moving a child to another organisation must be refused');

  /*
   * The limit of the guarantee, stated so nobody over-reads it: the composite key prevents
   * DISAGREEMENT, not ABSENCE. A child with no organisation is accepted even under a scoped
   * parent, which is exactly what lets v21 be additive — and exactly what v25's NOT NULL
   * closes. v25 is deliberately not in this stage, so an unscoped row is reachable today and
   * the next stage must not assume otherwise.
   */
  await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at)
           VALUES ('uA', 'dogecoin', 'tbD', 'cc', 1)`);
  const unscoped = await q(
    `SELECT count(*)::int AS n FROM accounts WHERE wallet_user_id = 'uA' AND organisation_id IS NULL`);
  assert.equal(unscoped.rows[0].n, 1,
    'an unscoped child under a scoped parent is still possible until v25 makes the column NOT NULL');

  /*
   * An approval reaches its organisation through its operation, not through a wallet, so that
   * edge needs its own check.
   *
   * The second approval uses a DIFFERENT user on purpose. Written with the same user, the
   * insert is refused by `approvals_one_per_slot` — one approval per operation, user and slot —
   * and the test passes without the tenant constraint ever being consulted. The first version
   * of this test did exactly that.
   */
  await q(`INSERT INTO users (id, sub, created_at) VALUES ('uB', 'sB', 1)`);
  await q(`INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest, required, status, network, created_at, expires_at, organisation_id)
           VALUES ('opA', 'uA', 'uA', 'withdraw', 's', '{}', 'dg', 1, 'collecting', 'bitcoin', 1, 2, 'oA')`);
  await q(`INSERT INTO approvals (id, operation_id, user_id, status, created_at, organisation_id)
           VALUES ('apA', 'opA', 'uA', 'open', 1, 'oA')`);
  await assert.rejects(
    () => q(`INSERT INTO approvals (id, operation_id, user_id, status, created_at, organisation_id)
             VALUES ('apB', 'opA', 'uB', 'open', 1, 'oB')`),
    /foreign key constraint/, 'an approval cannot sit in a different organisation from its operation');
  // The control: the same row in the RIGHT organisation is accepted, so the refusal above was
  // about the tenant and not about the row being unwelcome for some other reason.
  await q(`INSERT INTO approvals (id, operation_id, user_id, status, created_at, organisation_id)
           VALUES ('apB', 'opA', 'uB', 'open', 1, 'oA')`);
});

test('a role cannot exist without the membership it belongs to', async t => {
  const { db } = await fresh(t);
  const q = (text, params) => db.query(text, params);
  await q(`INSERT INTO organisations (id, name, kind, created_at) VALUES ('o1', 'A', 'institutional', 1)`);
  await q(`INSERT INTO users (id, sub, created_at) VALUES ('u1', 's1', 1)`);

  // One path to the organisation: the role reaches it through the membership, never beside it.
  await assert.rejects(
    () => q(`INSERT INTO org_member_roles (organisation_id, user_id, role, granted_at)
             VALUES ('o1', 'u1', 'approver', 1)`),
    /foreign key constraint/, 'a role with no membership must be refused');

  await q(`INSERT INTO org_members (organisation_id, user_id, label, added_at) VALUES ('o1', 'u1', 'Owner', 1)`);
  await q(`INSERT INTO org_member_roles (organisation_id, user_id, role, granted_at) VALUES ('o1', 'u1', 'approver', 1)`);
  await assert.rejects(
    () => q(`INSERT INTO org_member_roles (organisation_id, user_id, role, granted_at)
             VALUES ('o1', 'u1', 'wizard', 1)`),
    /check constraint|violates/, 'an unknown role must be refused');

  // Deleting the membership cannot leave the role behind.
  await q(`DELETE FROM org_members WHERE organisation_id = 'o1' AND user_id = 'u1'`);
  const left = await q(`SELECT count(*)::int AS n FROM org_member_roles WHERE organisation_id = 'o1'`);
  assert.equal(left.rows[0].n, 0, 'the cascade must remove the roles');
});

test('a policy version cannot be rewritten or removed', async t => {
  const { db } = await fresh(t);
  const q = (text, params) => db.query(text, params);
  await q(`INSERT INTO organisations (id, name, kind, created_at) VALUES ('o1', 'A', 'institutional', 1)`);
  await q(`INSERT INTO users (id, sub, created_at) VALUES ('u1', 's1', 1)`);
  const bytes = descriptorBytes(buildDescriptor(REFERENCE_INPUT));
  await q(`INSERT INTO policies (id, organisation_id, wallet_user_id, network, version, descriptor, digest, effective_from, created_by)
           VALUES ('p1', 'o1', 'u1', 'bitcoin', 1, $1, $2, 1, 'u1')`, [bytes, digestOf(bytes)]);

  /*
   * The reason the digest has to be right before anything is written: it cannot be corrected
   * afterwards. A change writes a new version.
   */
  await assert.rejects(() => q(`UPDATE policies SET digest = 'x' WHERE id = 'p1'`), /append only/);
  await assert.rejects(() => q(`DELETE FROM policies WHERE id = 'p1'`), /append only/);

  // A second version is how a change is recorded, and the pair is unique per account.
  await q(`INSERT INTO policies (id, organisation_id, wallet_user_id, network, version, descriptor, digest, effective_from, created_by)
           VALUES ('p2', 'o1', 'u1', 'bitcoin', 2, $1, $2, 2, 'u1')`, [bytes, digestOf(bytes)]);
  await assert.rejects(
    () => q(`INSERT INTO policies (id, organisation_id, wallet_user_id, network, version, descriptor, digest, effective_from, created_by)
             VALUES ('p3', 'o1', 'u1', 'bitcoin', 2, $1, $2, 3, 'u1')`, [bytes, digestOf(bytes)]),
    /duplicate key|unique/, 'one version number per account');
});

/* --------------------------------------------------------- a populated database, migrated */

/**
 * Builds a database at the schema of a past release, with rows in it, then opens it with the
 * current code so the migration runs over real data.
 *
 * `test/migrate.test.js` already proves every historical schema lands; this is about what the
 * BACKFILL decides, which only shows up when there is something to back-fill.
 */
async function populatedAt(commit, t, seed) {
  const dir = mkdtempSync(path.join(tmpdir(), 'qv-pop-'));
  const file = path.join(root, 'src', `_seed_${commit}.js`);
  writeFileSync(file, execFileSync('git', ['show', `${commit}:src/db.js`], { cwd: root }));
  try {
    const past = await import(`../src/_seed_${commit}.js?v=${commit}-${Date.now()}`);
    const old = await past.openDb({ dir });
    await seed((text, params) => old.query(text, params));
    await old.close?.();
  } finally {
    unlinkSync(file);
  }
  // Now the current code opens it: the migration runs, including the backfill.
  const db = await openDb({ dir });
  t.after(async () => {
    await db.close?.().catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  });
  return db;
}

// The last schema before tenancy: v18, the external anchor commit.
const V18 = '398d7b7';

test('a populated v18 database gets one organisation per vault, preserving who can approve', async t => {
  const db = await populatedAt(V18, t, async q => {
    // Two vaults with different shapes, because the backfill treats them differently.
    // A: a single-owner vault, which is what most existing rows are.
    await q(`INSERT INTO users (id, sub, created_at) VALUES ('solo', 'sub-solo', 1700000000)`);
    await q(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, custody, policy)
             VALUES ('solo', 'testnet4', 'tb1solo', 'aa', 'k', 'sub-solo', 'd', 1700000000, 'client', $1)`,
      [JSON.stringify({ rules: [{ upToSats: null, approvals: 1 }] })]);
    await q(`INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at)
             VALUES ('solo', 'solo', 'Owner', true, 1700000000)`);
    await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at, policy)
             VALUES ('solo', 'bitcoin', 'tb1solo', 'aa', 1700000000, $1)`,
      [JSON.stringify({ rules: [{ upToSats: null, approvals: 1 }] })]);

    // B: a three-member vault with a two-approval ladder — the shape that makes the
    // self-approval decision load-bearing.
    await q(`INSERT INTO users (id, sub, created_at) VALUES ('own', 'sub-own', 1700000100), ('bob', 'sub-bob', 1700000100), ('cat', 'sub-cat', 1700000100)`);
    await q(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, custody, policy)
             VALUES ('own', 'testnet4', 'tb1team', 'bb', 'k', 'sub-own', 'd', 1700000100, 'client', $1)`,
      [JSON.stringify({ rules: [{ upToSats: 100000, approvals: 1 }, { upToSats: null, approvals: 3 }] })]);
    await q(`INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at)
             VALUES ('own', 'own', 'Owner', true, 1700000100), ('own', 'bob', 'Bob', false, 1700000101), ('own', 'cat', 'Cat', false, 1700000102)`);
    await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at, policy)
             VALUES ('own', 'bitcoin', 'tb1team', 'bb', 1700000100, $1)`,
      [JSON.stringify({ rules: [{ upToSats: 100000, approvals: 1 }, { upToSats: null, approvals: 3 }] })]);

    // A pending proposal with two approvals, one of them settled: v21 and v23 must reach it.
    await q(`INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest, required, status, network, created_at, expires_at)
             VALUES ('op-pending', 'own', 'own', 'withdraw', 'Send 1', '{}', 'dg1', 3, 'collecting', 'bitcoin', 1700000200, 1700002000)`);
    await q(`INSERT INTO approvals (id, operation_id, user_id, status, created_at)
             VALUES ('ap-own', 'op-pending', 'own', 'approved', 1700000200), ('ap-bob', 'op-pending', 'bob', 'open', 1700000201)`);
    await q(`INSERT INTO invites (code, wallet_user_id, network, label, created_by, created_at, expires_at, status)
             VALUES ('INV1', 'own', 'bitcoin', 'Dave', 'own', 1700000300, 1700009000, 'open')`);
  });
  const q = (text, params) => db.query(text, params);

  // One organisation per vault, and the two vaults are in different ones.
  const orgs = await q('SELECT id, kind FROM organisations ORDER BY created_at');
  assert.equal(orgs.rows.length, 2, 'one organisation per existing vault');
  const wallets = await q('SELECT user_id, organisation_id FROM wallets ORDER BY user_id');
  const orgOf = Object.fromEntries(wallets.rows.map(r => [r.user_id, r.organisation_id]));
  assert.ok(orgOf.solo && orgOf.own, 'every wallet is linked');
  assert.notEqual(orgOf.solo, orgOf.own, 'two vaults are two tenants');

  /*
   * `kind` tells the truth about each one. A grandfathered three-member vault is not
   * 'single_owner' — calling it that to reuse an existing value would be a false statement in
   * the data — and it is not 'institutional' either, because it permits self-approval.
   */
  const kindOf = Object.fromEntries(orgs.rows.map(r => [r.id, r.kind]));
  assert.equal(kindOf[orgOf.solo], 'single_owner');
  assert.equal(kindOf[orgOf.own], 'migrated');

  // Everyone who could approve before can approve now, and nobody gained anything else.
  const members = await q(
    `SELECT m.user_id, m.label, m.revoked_at,
            (SELECT string_agg(r.role, ',' ORDER BY r.role) FROM org_member_roles r
              WHERE r.organisation_id = m.organisation_id AND r.user_id = m.user_id) AS roles
       FROM org_members m WHERE m.organisation_id = $1 ORDER BY m.user_id`, [orgOf.own]);
  assert.deepEqual(members.rows.map(r => [r.user_id, r.roles]), [
    ['bob', 'approver'],
    ['cat', 'approver'],
    ['own', 'approver,owner'],
  ]);
  assert.ok(members.rows.every(r => r.revoked_at === null), 'nobody is revoked by a migration');

  // The child tables carry the same tenant as their wallet.
  for (const [table, key] of [['accounts', 'wallet_user_id'], ['operations', 'wallet_user_id'], ['invites', 'wallet_user_id'], ['members', 'wallet_user_id']]) {
    const bad = await q(
      `SELECT count(*)::int AS n FROM ${table} t JOIN wallets w ON w.user_id = t.${key}
        WHERE t.organisation_id IS DISTINCT FROM w.organisation_id`);
    assert.equal(bad.rows[0].n, 0, `${table} must agree with its wallet`);
  }
  const apBad = await q(
    `SELECT count(*)::int AS n FROM approvals a JOIN operations o ON o.id = a.operation_id
      WHERE a.organisation_id IS DISTINCT FROM o.organisation_id`);
  assert.equal(apBad.rows[0].n, 0, 'approvals must agree with their operation');
});

test('the backfilled policy records what was actually in force, and says so explicitly', async t => {
  const db = await populatedAt(V18, t, async q => {
    await q(`INSERT INTO users (id, sub, created_at) VALUES ('own', 'sub-own', 1700000100), ('bob', 'sub-bob', 1700000100)`);
    await q(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, custody, policy)
             VALUES ('own', 'testnet4', 'tb1team', 'bb', 'k', 'sub-own', 'd', 1700000100, 'client', $1)`,
      [JSON.stringify({ rules: [{ upToSats: 250000, approvals: 1 }, { upToSats: null, approvals: 2 }] })]);
    await q(`INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at)
             VALUES ('own', 'own', 'Owner', true, 1700000100), ('own', 'bob', 'Bob', false, 1700000101)`);
    await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at, policy)
             VALUES ('own', 'bitcoin', 'tb1team', 'bb', 1700000100, $1)`,
      [JSON.stringify({ rules: [{ upToSats: 250000, approvals: 1 }, { upToSats: null, approvals: 2 }] })]);
    // An account with no policy of its own, which must fall back to the vault's.
    await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at)
             VALUES ('own', 'litecoin', 'ltc1', 'cc', 1700000100)`);
  });
  const q = (text, params) => db.query(text, params);

  const rows = await q('SELECT network, version, descriptor, digest, operation_id FROM policies ORDER BY network');
  assert.equal(rows.rows.length, 2, 'one version 1 per account');

  for (const row of rows.rows) {
    assert.equal(row.version, 1);
    assert.equal(row.operation_id, null,
      'the backfilled version points at no operation, because there was none to point at');
    // The digest is over exactly the stored bytes, recomputed here rather than trusted.
    assert.equal(row.digest, digestOf(row.descriptor), 'the digest must match its descriptor');
    const d = JSON.parse(row.descriptor);
    assert.equal(descriptorBytes(d), row.descriptor, 'the stored bytes must already be canonical');

    /*
     * The decision worth arguing with, pinned here: every migrated organisation permits
     * self-approval. Writing 'forbidden' would not tighten a control, it would make this vault
     * unspendable — two members cannot reach a two-approval rule if the proposer is excluded.
     * So the grandfathered permission is preserved and stated, not inherited silently.
     */
    assert.equal(d.selfApproval, 'permitted');
    assert.equal(d.approverCount, 2);
  }

  const bitcoin = JSON.parse(rows.rows.find(r => r.network === 'bitcoin').descriptor);
  assert.deepEqual(bitcoin.rules, [
    { upToSats: 250000, approvals: 1, requiredRoles: ['approver'] },
    { upToSats: null, approvals: 2, requiredRoles: ['approver'] },
  ], 'the ladder is exactly what was in force');
  assert.equal(bitcoin.requiredToChange, 2, 'the strongest rule is what changes the policy');

  // The account with no policy of its own inherited the vault's, as the application does.
  const litecoin = JSON.parse(rows.rows.find(r => r.network === 'litecoin').descriptor);
  assert.deepEqual(litecoin.rules, bitcoin.rules, 'an account with no policy falls back to the vault');

  // A pending proposal names the version that was in force when it was raised.
  await q(`INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest, required, status, network, created_at, expires_at, organisation_id)
           SELECT 'op-later', 'own', 'own', 'withdraw', 's', '{}', 'dg', 2, 'collecting', 'bitcoin', 1, 2, organisation_id FROM wallets WHERE user_id = 'own'`);
});

test('an operation raised before the migration is pointed at version 1', async t => {
  const db = await populatedAt(V18, t, async q => {
    await q(`INSERT INTO users (id, sub, created_at) VALUES ('own', 'sub-own', 1700000100)`);
    await q(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, custody, policy)
             VALUES ('own', 'testnet4', 'tb1a', 'bb', 'k', 'sub-own', 'd', 1700000100, 'client', $1)`,
      [JSON.stringify({ rules: [{ upToSats: null, approvals: 1 }] })]);
    await q(`INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at) VALUES ('own', 'own', 'Owner', true, 1700000100)`);
    await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at)
             VALUES ('own', 'bitcoin', 'tb1a', 'bb', 1700000100)`);
    await q(`INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest, required, status, network, created_at, expires_at)
             VALUES ('op-old', 'own', 'own', 'withdraw', 's', '{}', 'dg', 1, 'collecting', 'bitcoin', 1700000200, 1700002000)`);
  });
  const q = (text, params) => db.query(text, params);

  const op = await q(`SELECT o.policy_id, p.version, p.network FROM operations o
                      LEFT JOIN policies p ON p.id = o.policy_id WHERE o.id = 'op-old'`);
  assert.equal(op.rows[0].version, 1, 'a pending proposal is judged against the rules it was raised under');
  assert.equal(op.rows[0].network, 'bitcoin');

  // And `required` is untouched: a migration never changes a threshold.
  const req = await q(`SELECT required FROM operations WHERE id = 'op-old'`);
  assert.equal(req.rows[0].required, 1);
});

/* ------------------------------------------------------ idempotency, restart and recovery */

test('the migration is idempotent across restarts and writes nothing the second time', async t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'qv-idem-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  // First open: create the schema and a vault to back-fill.
  let db = await openDb({ dir });
  await db.query(`INSERT INTO users (id, sub, created_at) VALUES ('u1', 's1', 1700000000)`);
  await db.query(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, custody, policy)
                  VALUES ('u1', 'testnet4', 'tb1a', 'aa', 'k', 's1', 'd', 1700000000, 'client', $1)`,
    [JSON.stringify({ rules: [{ upToSats: null, approvals: 1 }] })]);
  await db.query(`INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at) VALUES ('u1', 'u1', 'Owner', true, 1700000000)`);
  await db.query(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at) VALUES ('u1', 'bitcoin', 'tb1a', 'aa', 1700000000)`);
  await db.close?.();

  // Second open: the backfill runs for the first time over the rows above.
  db = await openDb({ dir });
  const snapshot = async () => ({
    orgs: (await db.query('SELECT id, kind, created_at FROM organisations ORDER BY id')).rows,
    members: (await db.query('SELECT organisation_id, user_id, label FROM org_members ORDER BY user_id')).rows,
    roles: (await db.query('SELECT organisation_id, user_id, role FROM org_member_roles ORDER BY role')).rows,
    policies: (await db.query('SELECT id, digest, descriptor, version FROM policies ORDER BY id')).rows,
    wallets: (await db.query('SELECT user_id, organisation_id FROM wallets ORDER BY user_id')).rows,
  });
  const first = await snapshot();
  assert.equal(first.orgs.length, 1);
  assert.equal(first.policies.length, 1);
  await db.close?.();

  /*
   * Third and fourth opens. Every step re-runs on every cold start, so a step that is not
   * idempotent shows up here — as a duplicate organisation, a second policy version, or a
   * constraint that cannot be added twice.
   */
  for (const pass of [3, 4]) {
    db = await openDb({ dir });
    assert.deepEqual(await snapshot(), first, `pass ${pass} must change nothing`);
    await db.close?.();
  }

  // A vault added after the migration is picked up by the next start, not left behind.
  db = await openDb({ dir });
  await db.query(`INSERT INTO users (id, sub, created_at) VALUES ('u2', 's2', 1700000500)`);
  await db.query(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, custody)
                  VALUES ('u2', 'testnet4', 'tb1b', 'bb', 'k', 's2', 'd', 1700000500, 'client')`);
  await db.query(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at) VALUES ('u2', 'bitcoin', 'tb1b', 'bb', 1700000500)`);
  await db.close?.();

  db = await openDb({ dir });
  const after = await snapshot();
  assert.equal(after.orgs.length, 2, 'a new vault gets an organisation on the next start');
  assert.equal(after.policies.length, 2);
  // The first vault's rows are byte-identical: a later backfill must not disturb earlier work.
  assert.deepEqual(after.policies.find(p => p.id === first.policies[0].id), first.policies[0]);
  await db.close?.();
});

test('a half-applied migration recovers on the next start rather than leaving a gap', async t => {
  const { db, dir } = await fresh(t);
  const q = (text, params) => db.query(text, params);

  /*
   * Simulating a crash between steps. The migration runs in one transaction, so a real crash
   * leaves nothing applied — but a deployment can still be interrupted after an earlier
   * release and resumed by a later one, which is what this models: the organisation rows exist
   * and the policy row does not.
   *
   * Nothing destructive is needed to recover. Re-running finds the gap through the same
   * IS NULL and NOT EXISTS guards that make it idempotent.
   */
  await q(`INSERT INTO users (id, sub, created_at) VALUES ('u1', 's1', 1700000000)`);
  await q(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at, custody)
           VALUES ('u1', 'testnet4', 'tb1a', 'aa', 'k', 's1', 'd', 1700000000, 'client')`);
  await q(`INSERT INTO members (wallet_user_id, member_id, label, is_owner, added_at) VALUES ('u1', 'u1', 'Owner', true, 1700000000)`);
  await q(`INSERT INTO accounts (wallet_user_id, network, address, public_key, created_at) VALUES ('u1', 'bitcoin', 'tb1a', 'aa', 1700000000)`);
  await db.close?.();

  let again = await openDb({ dir });
  const org = await again.query('SELECT organisation_id FROM wallets WHERE user_id = $1', ['u1']);
  assert.ok(org.rows[0].organisation_id, 'the wallet was linked');
  assert.equal((await again.query('SELECT count(*)::int AS n FROM policies')).rows[0].n, 1);

  /*
   * First, a property found by trying to write this test the obvious way: a linked wallet
   * CANNOT be un-linked while its children reference the organisation. The composite foreign
   * key refuses it. So the half-applied state "organisation exists, children scoped, wallet
   * unlinked" is not reachable at all — the database will not hold it.
   *
   * That is a better guarantee than recovering from it, and worth asserting rather than
   * working around.
   */
  await assert.rejects(
    () => again.query('UPDATE wallets SET organisation_id = NULL WHERE user_id = $1', ['u1']),
    /foreign key constraint/,
    'a wallet cannot be orphaned while its scoped children point at the organisation');

  /*
   * The only route to an unlinked wallet is to unscope EVERY child first — and the refusals
   * name them one at a time, so a partial attempt cannot succeed quietly. `members` blocked
   * this after `accounts` had been cleared, which is the web working: there is no order in
   * which a wallet loses its organisation while anything still points at it.
   */
  for (const table of ['accounts', 'operations', 'invites', 'members']) {
    await again.query(`UPDATE ${table} SET organisation_id = NULL WHERE wallet_user_id = $1`, ['u1']);
  }
  await again.query('UPDATE wallets SET organisation_id = NULL WHERE user_id = $1', ['u1']);
  await again.close?.();

  again = await openDb({ dir });
  const relinked = await again.query('SELECT organisation_id FROM wallets WHERE user_id = $1', ['u1']);
  assert.ok(relinked.rows[0].organisation_id, 'an unlinked wallet is linked again on the next start');
  /*
   * It gets a NEW organisation rather than reusing the orphan. The backfill does not guess
   * which organisation an unlinked wallet used to belong to — guessing is how a wallet would
   * silently land in somebody else's tenant — so it makes one, and the orphan is left visible.
   */
  const count = await again.query('SELECT count(*)::int AS n FROM organisations');
  assert.equal(count.rows[0].n, 2, 'recovery creates a fresh organisation rather than guessing');
  // The account is re-scoped to match, and no second policy version appears for it.
  const account = await again.query('SELECT organisation_id FROM accounts WHERE wallet_user_id = $1', ['u1']);
  assert.equal(account.rows[0].organisation_id, relinked.rows[0].organisation_id,
    'the child is re-scoped to the wallet it belongs to');
  assert.equal((await again.query('SELECT count(*)::int AS n FROM policies')).rows[0].n, 1,
    'and no second policy version is written for the same account');
  await again.close?.();
});

test('rollback of v19 to v24 is possible only while no immutable row has been written', async t => {
  const { db } = await fresh(t);
  const q = (text, params) => db.query(text, params);

  /*
   * What rollback actually means for this stage, verified rather than assumed.
   *
   * v19-v24 are additive and nothing reads them, so dropping them restores v18 — EXCEPT that
   * `policies` is immutable at the row level. Its rows cannot be deleted. The table can still
   * be dropped, which is the honest position: rollback is by DROP TABLE, not by DELETE, and
   * once a later stage writes evidence ABOUT the migration that evidence is permanent and no
   * rollback reaches it.
   */
  await q(`INSERT INTO organisations (id, name, kind, created_at) VALUES ('o1', 'A', 'institutional', 1)`);
  await q(`INSERT INTO users (id, sub, created_at) VALUES ('u1', 's1', 1)`);
  const bytes = descriptorBytes(buildDescriptor(REFERENCE_INPUT));
  await q(`INSERT INTO policies (id, organisation_id, wallet_user_id, network, version, descriptor, digest, effective_from, created_by)
           VALUES ('p1', 'o1', 'u1', 'bitcoin', 1, $1, $2, 1, 'u1')`, [bytes, digestOf(bytes)]);

  // Row-level rollback: refused, which is the guarantee working.
  await assert.rejects(() => q(`DELETE FROM policies WHERE id = 'p1'`), /append only/,
    'a policy version cannot be deleted, so rollback is never by DELETE');

  /*
   * Table-level rollback: available, and leaves v18 behind — in dependency order, which is its
   * own finding. `DROP TABLE policies` is refused while `operations.policy_id` references it,
   * so a rollback script has to drop the referencing column first. A `CASCADE` would also work
   * and is the wrong instinct here: it would silently drop whatever else had come to depend on
   * the table by then.
   */
  await assert.rejects(() => q('DROP TABLE policies'), /depend|dependent/,
    'policies cannot be dropped while an operation still references a version');
  // And an operation's tenant column cannot go while an approval's composite key points at it.
  await assert.rejects(() => q('ALTER TABLE operations DROP COLUMN organisation_id'), /depend|dependent/,
    'operations cannot lose its tenant column while approvals reference it');

  /*
   * So rollback has a required order — reverse dependency order — and taking it out of order
   * fails loudly rather than leaving a half-scoped database. A `CASCADE` would paper over both
   * refusals above and is the wrong instinct: it drops whatever else has come to depend on the
   * object by then, unseen.
   */
  await q('ALTER TABLE approvals DROP COLUMN IF EXISTS organisation_id');   // child of operations
  for (const table of ['accounts', 'operations', 'invites', 'members']) {   // children of wallets
    await q(`ALTER TABLE ${table} DROP COLUMN IF EXISTS organisation_id`);
  }
  await q('ALTER TABLE operations DROP COLUMN IF EXISTS policy_id');        // referencing policies
  await q('DROP TABLE policies');
  await q('ALTER TABLE approvals DROP COLUMN IF EXISTS invalidated_at');
  await q('ALTER TABLE approvals DROP COLUMN IF EXISTS invalidated_by');
  await q('ALTER TABLE approvals DROP COLUMN IF EXISTS invalidated_reason');
  await q('ALTER TABLE wallets DROP COLUMN IF EXISTS organisation_id');     // root
  await q('DROP TABLE org_member_roles');
  await q('DROP TABLE org_members');
  await q('DROP TABLE organisations');

  // v18's own tables are untouched by any of it.
  for (const table of ['users', 'wallets', 'accounts', 'operations', 'approvals', 'members', 'invites', 'evidence']) {
    const r = await q(
      `SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1`,
      [table]);
    assert.equal(r.rows[0].n, 1, `${table} must survive a rollback`);
  }
  /*
   * And the evidence log, which no rollback may touch, still refuses to be changed.
   *
   * The row matters. `BEFORE UPDATE … FOR EACH ROW` fires per row, so an UPDATE against an
   * empty table raises nothing and an assertion here passes vacuously — which is how this
   * test first "passed" while proving the opposite of what it claimed.
   */
  await q(`INSERT INTO evidence (id, at, kind, payload, prev_hash, hash, idempotency_key)
           VALUES ('e1', 1, 'proposal.created', '{}', 'GENESIS', 'h1', 'k1')`);
  await assert.rejects(
    () => q(`UPDATE evidence SET kind = 'x' WHERE id = 'e1'`), /append only/,
    'the evidence guarantee is independent of the tenancy migration');
  await assert.rejects(
    () => q(`DELETE FROM evidence WHERE id = 'e1'`), /append only/);
});

test('nothing in v19 to v24 changes wallet behaviour, custody or the network', async t => {
  const { db } = await fresh(t);
  const q = (text, params) => db.query(text, params);

  /*
   * The stage is additive, so the proof is about what did NOT change: the columns the wallet
   * actually runs on still hold what they held, and no default moved.
   */
  const columns = await q(
    `SELECT column_name, is_nullable, column_default FROM information_schema.columns
      WHERE table_name = 'wallets' ORDER BY column_name`);
  const byName = Object.fromEntries(columns.rows.map(c => [c.column_name, c]));
  assert.equal(byName.custody.column_default, "'server'::text", 'the custody default is untouched');
  assert.equal(byName.organisation_id.is_nullable, 'YES', 'the new column is nullable in this stage');

  // A wallet still inserts with no organisation at all, which is what makes the stage additive.
  await q(`INSERT INTO users (id, sub, created_at) VALUES ('u1', 's1', 1)`);
  await q(`INSERT INTO wallets (user_id, network, address, public_key, sealed_key, bound_sub, bound_decision, created_at)
           VALUES ('u1', 'testnet4', 'tb1a', 'aa', 'k', 's1', 'd', 1)`);
  const w = await q(`SELECT network, custody, organisation_id FROM wallets WHERE user_id = 'u1'`);
  assert.equal(w.rows[0].network, 'testnet4');
  assert.equal(w.rows[0].custody, 'server');
  assert.equal(w.rows[0].organisation_id, null);

  // The new tables say nothing about keys, signing, scanners or biometrics.
  const all = await q(
    `SELECT table_name, column_name FROM information_schema.columns
      WHERE table_name IN ('organisations', 'org_members', 'org_member_roles', 'policies')`);
  const names = all.rows.map(r => `${r.table_name}.${r.column_name}`).join(' ').toLowerCase();
  for (const word of ['key', 'seed', 'mnemonic', 'phrase', 'sealed', 'unlock', 'scanner', 'biometric', 'palm', 'pad']) {
    assert.ok(!names.includes(word), `the tenancy tables must not mention ${word}: ${names}`);
  }
});
