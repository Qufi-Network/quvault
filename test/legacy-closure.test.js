/*
 * Phase 1.5: the two risks the Phase 1 report named, tested rather than asserted.
 *
 *   1. A legacy wallet cannot be made to sign in normal operation, and cannot be made to sign
 *      by somebody who can write to the database.
 *   2. The signing boundary takes an authorisation and checks it, rather than taking the
 *      page's word for what was approved.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { INVENTORY_SQL, summarise, walletId } from '../src/legacy-inventory.js';
import { requestMatchesAuthorization, AUTHORIZATION_FIELDS, SignerError } from '../src/signer.js';
import { EVENT } from '../src/events.js';
import { actionDigest } from '../src/veyns.js';
import { restoreVaultKey, browserSigner, loadRecord, clearRecord, accountFrom } from '../client/wallet.js';
import {
  DEST, SEED, start, startWithMigration, ok, signedIn, palmApprove, legacyWallet, browserKey, walletFor,
} from './harness.js';

const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const b64 = n => Buffer.from(crypto.randomBytes(n)).toString('base64');

function installStorage() {
  const rows = new Map();
  const settle = (result, upgrade) => {
    const request = { result, onsuccess: null, onerror: null, onupgradeneeded: null };
    queueMicrotask(() => { if (upgrade) request.onupgradeneeded?.(); request.onsuccess?.(); });
    return request;
  };
  const store = {
    get: key => settle(rows.get(key)),
    put: (value, key) => { rows.set(key, value); return settle(undefined); },
    delete: key => { rows.delete(key); return settle(undefined); },
  };
  globalThis.indexedDB = { open: () => settle({ createObjectStore() {}, transaction: () => ({ objectStore: () => store }), close() {} }, true) };
}

/** A device holding the known phrase, and the unlock the palm gate would have released. */
async function deviceWithPhrase() {
  installStorage();
  await clearRecord();
  const unlock = b64(32);
  const salt = b64(16);
  const address = accountFrom(PHRASE).address;
  await restoreVaultKey(PHRASE, { unlock, salt }, address);
  return { record: await loadRecord(), unlock, salt, address };
}

/* ================================================ the inventory counts correctly */

test('the inventory query the operator runs is the one that is checked here', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);                    // client custody
  const sam = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, sam);                  // server custody, with a member

  const db = await env.app.db();
  const { rows } = await db.query(INVENTORY_SQL);
  const report = summarise(rows);

  assert.equal(report.totals.wallets, 2);
  assert.equal(report.totals.custodyClient, 1);
  assert.equal(report.totals.custodyServer, 1);
  assert.equal(report.totals.serverActive, 1, 'the legacy row still holds a key');
  assert.equal(report.totals.serverInactive, 0);
  assert.equal(report.totals.migratableAutomatically, 1, 'it has a member who can approve');
  assert.equal(report.totals.requiringManualRecovery, 0);
  assert.equal(report.totals.serverWithBalances, null, 'balances are not guessed at');

  // Identifiers are stable, redacted, and do not carry the address.
  const [entry] = report.legacyWallets;
  assert.match(entry.id, /^W-[0-9a-f]{12}$/);
  assert.equal(entry.id, walletId(rows.find(r => r.custody === 'server').address));
  assert.ok(!('address' in entry), 'no address unless it is asked for');
  assert.ok(!JSON.stringify(report).includes('sealed'), 'no key material anywhere in it');
});

/* ======================================= a legacy wallet cannot be made to sign */

test('a legacy wallet cannot sign, even where the migration capability is enabled', async t => {
  const env = await startWithMigration(t);
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 400_000 }];

  const refused = await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 });
  assert.equal(refused.status, 409);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing was signed');
});

test('without the migration seed nothing can open a legacy key at all', async t => {
  // The default deployment: legacySeed is absent, so there is nothing to open the key with.
  const env = await start(t);
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 400_000 }];

  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  await palmApprove(env, alex, operation.id);
  const made = browserKey();
  const refused = await alex.post('/api/wallet/upgrade', {
    operationId: operation.id, address: made.address, publicKey: made.publicKey,
    attestationRegistration: made.attestationRegistration,
  });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /migration is not enabled/);
  assert.equal(env.world.log.broadcast.length, 0, 'the key was never opened');

  // And the row is untouched, so the vault can still be migrated later by an operator.
  const db = await env.app.db();
  const { rows } = await db.query(INVENTORY_SQL);
  assert.equal(summarise(rows).totals.serverActive, 1, 'nothing was destroyed');
});

test('a forged operation row cannot make a legacy wallet sign', async t => {
  const env = await startWithMigration(t);
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 400_000 }];
  const db = await env.app.db();
  const made = browserKey();

  /*
   * The attacker here has write access to the database and nothing else. They cannot make
   * Veyns say a palm was scanned, which is the whole point of re-checking upstream.
   */
  const id = crypto.randomBytes(16).toString('base64url');
  await db.query(
    `INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest,
                             required, status, created_at, expires_at)
     VALUES ($1, $2, $2, 'upgrade', $3, $4, $5, 1, 'done', $6, $7)`,
    [id, alex.id, 'Move this vault into my browser and retire the key held on the server',
      JSON.stringify({ action: 'move key to browser', network: 'testnet4' }),
      'a-digest-they-chose', env.now(), env.now() + 1800]);
  await db.query(
    `INSERT INTO approvals (id, operation_id, user_id, status, request_id, decision_id, created_at, slot)
     VALUES ($1, $2, $3, 'approved', 'invented-request', 'invented-decision', $4, 1)`,
    [crypto.randomBytes(16).toString('base64url'), id, alex.id, env.now()]);

  const refused = await alex.post('/api/wallet/upgrade', {
    operationId: id, address: made.address, publicKey: made.publicKey,
    attestationRegistration: made.attestationRegistration,
  });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /altered since it was approved/, 'refused by the digest, not by luck');
  assert.equal(env.world.log.broadcast.length, 0, 'and the legacy key was never opened');

  /*
   * The stronger case. `actionDigest` is deterministic and the statement is public, so an
   * attacker who can write rows can also write a digest that matches them — the check above
   * is necessary and is not sufficient. What they cannot do is make Veyns agree that a palm
   * was scanned for that action, which is why the approvals are re-checked upstream.
   */
  const better = crypto.randomBytes(16).toString('base64url');
  const statement = 'Move this vault into my browser and retire the key held on the server';
  const details = { action: 'move key to browser', network: 'testnet4' };
  await db.query(
    `INSERT INTO operations (id, wallet_user_id, started_by, kind, statement, details, digest,
                             required, status, created_at, expires_at)
     VALUES ($1, $2, $2, 'upgrade', $3, $4, $5, 1, 'done', $6, $7)`,
    [better, alex.id, statement, JSON.stringify(details),
      actionDigest(statement, details), env.now(), env.now() + 1800]);
  await db.query(
    `INSERT INTO approvals (id, operation_id, user_id, status, request_id, decision_id, created_at, slot)
     VALUES ($1, $2, $3, 'approved', 'invented-request-2', 'invented-decision-2', $4, 1)`,
    [crypto.randomBytes(16).toString('base64url'), better, alex.id, env.now()]);

  const stillRefused = await alex.post('/api/wallet/upgrade', {
    operationId: better, address: made.address, publicKey: made.publicKey,
    attestationRegistration: made.attestationRegistration,
  });
  assert.notEqual(stillRefused.status, 200, 'a correct digest is not enough without a real palm');
  assert.equal(env.world.log.broadcast.length, 0, 'the legacy key was still never opened');

  const { rows } = await db.query(INVENTORY_SQL);
  assert.equal(summarise(rows).totals.serverActive, 1, 'the vault is still there, untouched');
});

test('an operation edited after its approval no longer matches its own digest', async t => {
  const env = await startWithMigration(t);
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'd'.repeat(64), vout: 0, value: 400_000 }];
  const db = await env.app.db();

  // A genuine, genuinely palm-approved migration.
  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  await palmApprove(env, alex, operation.id);

  // Now somebody edits the row the approval is attached to.
  await db.query('UPDATE operations SET statement = $1 WHERE id = $2',
    ['Move this vault into an address I control', operation.id]);

  const made = browserKey();
  const refused = await alex.post('/api/wallet/upgrade', {
    operationId: operation.id, address: made.address, publicKey: made.publicKey,
    attestationRegistration: made.attestationRegistration,
  });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /altered since it was approved/);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing moved');
});

test('an approval Veyns does not corroborate does not open a legacy key', async t => {
  const env = await startWithMigration(t);
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'e'.repeat(64), vout: 0, value: 400_000 }];

  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  await palmApprove(env, alex, operation.id);

  // The decision is still recorded here, but upstream it is no longer an approval.
  for (const [, record] of env.world.requests) record.status = 'expired';

  const made = browserKey();
  const refused = await alex.post('/api/wallet/upgrade', {
    operationId: operation.id, address: made.address, publicKey: made.publicKey,
    attestationRegistration: made.attestationRegistration,
  });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /Veyns does not record that approval as granted/);
  assert.equal(env.world.log.broadcast.length, 0);
});

test('the migration is recorded as a security event, with no key material in it', async t => {
  const seen = [];
  const env = await startWithMigration(t, { securitySink: r => seen.push(r) });
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'f'.repeat(64), vout: 0, value: 400_000 }];

  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  await palmApprove(env, alex, operation.id);
  const made = browserKey();
  const moved = ok(await alex.post('/api/wallet/upgrade', {
    operationId: operation.id, address: made.address, publicKey: made.publicKey,
    attestationRegistration: made.attestationRegistration,
  }));
  assert.equal(moved.wallet.custody, 'client');

  const migration = seen.find(e => e.event === EVENT.MIGRATION);
  assert.ok(migration, 'the migration was recorded');
  assert.equal(migration.custody, 'server');
  for (const record of seen) {
    const line = JSON.stringify(record);
    assert.ok(!/"(mnemonic|privateKey|seed|secretKey|sealedKey|unlock)"/.test(line), 'no secret field');
  }

  // And afterwards the inventory says there is nothing left to migrate.
  const db = await env.app.db();
  const { rows } = await db.query(INVENTORY_SQL);
  assert.equal(summarise(rows).totals.serverActive, 0, 'the server holds no key for it any more');
});

/* ================================ the signer checks the authorisation it is given */

test('the signer refuses a request that does not match the authorisation', async () => {
  const { record, unlock, salt, address } = await deviceWithPhrase();

  const authorization = {
    unlock,
    salt,
    authorizationId: 'op-1',
    walletId: address,
    transactionHash: 'digest-1',
    network: 'testnet4',
    chain: 'bitcoin',
    policyVersion: 'policy-1',
    authorizationVersion: 1,
    bindingNonce: 'digest-1',
  };
  const signer = browserSigner(record, authorization);
  const request = {
    authorizationId: 'op-1', walletId: address, transactionDigest: 'digest-1',
    network: 'testnet4', chain: 'bitcoin', policyVersion: 'policy-1',
    authorizationVersion: 1, bindingNonce: 'digest-1',
  };
  assert.equal(requestMatchesAuthorization(request, authorization), null, 'a matching request is accepted');

  // Change any one field and the signer refuses before it touches a key.
  for (const field of AUTHORIZATION_FIELDS) {
    const altered = { ...request, [field]: field === 'authorizationVersion' ? 2 : 'something-else' };
    assert.match(
      requestMatchesAuthorization(altered, authorization) ?? '',
      new RegExp(`different ${field}`),
      field,
    );
    await assert.rejects(() => signer.signTransaction(altered), SignerError, field);
  }
  // And a request with nothing in it at all.
  await assert.rejects(() => signer.signTransaction({}), SignerError);
  await assert.rejects(() => signer.signTransaction(undefined), SignerError);
});

test('the signer will not sign a message for a vault it does not hold', async () => {
  const { record, unlock, salt, address } = await deviceWithPhrase();
  const signer = browserSigner(record, { unlock, salt });

  await assert.rejects(
    () => signer.signMessage({ vaultId: 'tb1qsomeoneelse', epoch: 1 }),
    /does not hold the key for that vault/,
  );
  // Its own vault is fine, and what comes back is a registration, not a key.
  const registration = await signer.signMessage({ vaultId: address, epoch: 1 });
  assert.equal(registration.algorithm, 'ML-DSA-65');
  assert.equal(registration.record.vaultId, address);
  assert.ok(!JSON.stringify(registration).includes(PHRASE));
});

test('normal signing needs no WALLET_SEED in the browser, and the server never sends one', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));

  // The unlock carries what a signer needs to check a request, and no seed of any kind.
  for (const field of ['authorizationId', 'walletId', 'network', 'chain', 'policyVersion',
    'authorizationVersion', 'bindingNonce']) {
    assert.ok(unlocked[field] !== undefined && unlocked[field] !== null, field);
  }
  assert.equal(unlocked.bindingNonce, unlocked.transactionHash, 'version 1 binds to its own digest');
  const body = JSON.stringify(unlocked);
  assert.ok(!body.includes(SEED), 'the server seed is not in the unlock');
  assert.ok(!/"(walletSeed|WALLET_SEED|seed|legacySeed)"/.test(body), 'no seed field at all');
});

test('no configuration endpoint reports anything about the seeds', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  for (const path of ['/api/config', '/api/scanner']) {
    const body = JSON.stringify(ok(await alex.get(path)));
    assert.ok(!body.includes(SEED), `${path} does not carry the seed`);
    assert.ok(!/"(walletSeed|legacySeed|WALLET_SEED|QUVAULT_LEGACY_SEED)"/.test(body), path);
  }
  // /api/config says whether a vault seed is configured, which is a boolean and not the seed.
  const config = ok(await alex.get('/api/config'));
  assert.equal(typeof config.vaultReady, 'boolean');
});

/* ============================== nothing in the repository can hide from an audit */

test('no tracked source file contains a byte that makes grep skip it', () => {
  /*
   * A file with a control byte in it is binary to grep, ripgrep, most editors and most review
   * tools, and is silently skipped. A security sweep over such a file reports a confident
   * zero while never having read it — which is exactly what happened to src/authorization.js,
   * whose NUL separator hid `biometricVerified` from every search for it.
   */
  const root = new URL('..', import.meta.url);
  const tracked = execFileSync('git', ['ls-files'], { cwd: fileURLToPath(root), encoding: 'utf8' })
    .split('\n').map(line => line.trim()).filter(Boolean)
    .filter(file => /\.(js|mjs|cjs|json|md|css|html|txt|yml|yaml|example)$/i.test(file));

  assert.ok(tracked.length > 20, 'the file list looks right');
  const opaque = [];
  for (const file of tracked) {
    const bytes = readFileSync(new URL(file, root));
    const at = bytes.findIndex(b => b === 0 || b < 9 || (b > 13 && b < 32));
    if (at !== -1) opaque.push(`${file} (byte ${bytes[at]} at ${at})`);
  }
  assert.deepEqual(opaque, [], 'every tracked text file is readable by a search tool');
});
