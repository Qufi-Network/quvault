/*
 * The signing boundary, the security log, and the portability invariant.
 *
 * Where boundary.test.js asks whether the wallet module refuses the right things, this file
 * asks the questions a reviewer asks afterwards: does anything leak out of the API, does the
 * signer hand back anything it should not, does a log line carry a secret, and does the
 * wallet a palm opens depend on which scanner was used.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { ISOLATION, IMPLEMENTED_ISOLATION, assertSigner, sealResult, SignerError, describeIsolation } from '../src/signer.js';
import { EVENT, redact, createSecurityLog, ALLOWED_EVENT_FIELDS } from '../src/events.js';
import { createNullScanner, assertProvider, SCANNER } from '../src/scanner.js';
import { restoreVaultKey, browserSigner, loadRecord, clearRecord, revealPhrase, accountFrom } from '../client/wallet.js';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend, legacyWallet } from './harness.js';

const b64 = n => Buffer.from(crypto.randomBytes(n)).toString('base64');
const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** The same in-memory IndexedDB the other boundary tests use. */
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

/* ================================================== the signer hands back no keys */

/** The address this phrase really has, derived independently of anything being tested. */
const ADDRESS_OF_PHRASE = accountFrom(PHRASE).address;

/** Restores the known phrase onto a fresh device record and returns what was stored. */
async function restored() {
  installStorage();
  await clearRecord();
  const unlock = b64(32);
  const salt = b64(16);
  const made = await restoreVaultKey(PHRASE, { unlock, salt }, ADDRESS_OF_PHRASE);
  return { made, record: await loadRecord(), unlock, salt };
}

test('a signer exposes three questions and no way to ask for the key', async () => {
  const { record, unlock, salt } = await restored();
  const signer = browserSigner(record, { unlock, salt });

  assert.deepEqual(
    Object.keys(signer).sort(),
    ['getPublicKey', 'isolation', 'signMessage', 'signTransaction'],
    'the signer has exactly this surface',
  );
  assert.equal(signer.getPublicKey(), record.publicKey);
  assert.match(signer.getPublicKey(), /^0[23][0-9a-f]{64}$/, 'a public key, not a private one');

  // Nothing that could return key material exists, by any of its usual names.
  for (const name of ['getPrivateKey', 'privateKey', 'exportKey', 'getMnemonic', 'mnemonic', 'getSeed', 'seed', 'reveal', 'unlock']) {
    assert.equal(signer[name], undefined, name);
  }
  assert.equal(signer.isolation, ISOLATION.BROWSER_JAVASCRIPT, 'it says where it runs');
});

test('a signer must declare an isolation level it actually has', () => {
  const base = { isolation: ISOLATION.BROWSER_JAVASCRIPT, signTransaction() {}, signMessage() {}, getPublicKey() {} };
  assert.ok(assertSigner({ ...base }), 'the browser signer is accepted');

  // Claiming hardware this build does not have is refused, not quietly believed.
  for (const claimed of [ISOLATION.SECURE_ELEMENT, ISOLATION.TEE, ISOLATION.HSM, ISOLATION.HARDWARE_WALLET, ISOLATION.OS_KEYSTORE]) {
    assert.throws(() => assertSigner({ ...base, isolation: claimed }), SignerError, claimed);
    assert.ok(!IMPLEMENTED_ISOLATION.includes(claimed), `${claimed} is not implemented`);
  }
  assert.throws(() => assertSigner({ ...base, isolation: 'something-strong-sounding' }), SignerError);
  assert.throws(() => assertSigner({ ...base, getPrivateKey: () => 'key' }), /must not expose key material/);
  assert.throws(() => assertSigner({ isolation: ISOLATION.BROWSER_JAVASCRIPT }), /missing/);

  // And it says so in words, without implying hardware.
  const said = describeIsolation(ISOLATION.BROWSER_JAVASCRIPT);
  assert.match(said, /browser JavaScript/);
  assert.match(said, /not a secure element, a TEE, an HSM or a hardware wallet/);
});

test('a signer result carries signatures and transactions, and drops anything else', () => {
  const leaked = sealResult({
    hex: 'aa', txid: 'bb', psbt: 'cc', authorization: { record: {} },
    privateKey: 'SHOULD NOT PASS', mnemonic: PHRASE, seed: 'SHOULD NOT PASS', secretKey: 'SHOULD NOT PASS',
  });
  assert.deepEqual(Object.keys(leaked).sort(), ['authorization', 'hex', 'psbt', 'txid']);
  for (const name of ['privateKey', 'mnemonic', 'seed', 'secretKey']) assert.equal(leaked[name], undefined, name);
});

/* ============================================= nothing leaks through the API */

test('no API response carries a private key or a recovery phrase', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const wallet = await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, operation.id);
  const sent = await signAndSend(env, alex, operation.id);

  // Every route a signed-in person can reach with a vault in this state.
  const bodies = [];
  for (const path of ['/api/config', '/api/wallet', '/api/random', '/api/scanner', '/api/invites',
    `/api/operations/${operation.id}/receipt`]) {
    const response = await alex.get(path);
    bodies.push([path, JSON.stringify(response.body ?? {})]);
  }
  bodies.push(['withdrawal', JSON.stringify(sent)]);
  bodies.push(['unlock', JSON.stringify((await alex.post(`/api/operations/${operation.id}/unlock`, {})).body ?? {})]);

  /*
   * The strongest available check: this test knows the actual private key the vault signs
   * with, so it looks for that exact material rather than for a shape. A shape test over
   * these bodies is close to useless — an ML-DSA-65 public key is 1952 bytes of base64 and
   * contains long runs that match almost any key-like pattern.
   */
  const secrets = [
    alex.key.toString('hex'),
    alex.key.toString('base64'),
    Buffer.from(alex.attestation.secretKey).toString('base64'),
    PHRASE,
  ];
  for (const [where, body] of bodies) {
    for (const secret of secrets) {
      assert.ok(!body.includes(secret), `${where} carries no key material`);
    }
    assert.ok(!/"(privateKey|private_key|mnemonic|seed|secretKey|sealedKey|sealed_key)"\s*:/.test(body), `${where} names no key field`);
    // A WIF is a standalone JSON string of exactly this shape, not a run inside base64.
    assert.ok(!/"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}"/.test(body), `${where} carries no WIF key`);
  }

  // The wallet view is public values only.
  const view = ok(await alex.get('/api/wallet')).wallet;
  assert.equal(view.address, wallet.address);
  assert.ok(!('sealed_key' in view) && !('sealedKey' in view) && !('unlock_sealed' in view));
});

test('the unlock releases an unlock secret, and never the wallet key', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 900_000 }];

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));

  // What comes back opens the blob in the browser. It is not, and cannot become, the key:
  // without the encrypted record on that device it opens nothing.
  assert.ok(unlocked.unlock, 'an unlock secret comes back');
  assert.equal(Buffer.from(unlocked.unlock, 'base64').length, 32);
  assert.ok(!('privateKey' in unlocked) && !('mnemonic' in unlocked) && !('sealedKey' in unlocked));
  assert.ok(unlocked.plan && unlocked.transactionHash, 'and the transaction to sign');
});

/* ================================================== the security log keeps quiet */

test('a security event cannot carry a secret, whatever it is handed', () => {
  const kept = redact({
    operationId: 'op-1', vaultId: 'tb1qvault', reason: 'authorisation did not verify',
    // None of these are on the allowlist.
    mnemonic: PHRASE, privateKey: 'ff'.repeat(32), seed: 'aa'.repeat(64), unlock: 'secret',
  });
  assert.deepEqual(Object.keys(kept).sort(), ['operationId', 'reason', 'vaultId']);
  for (const name of ['mnemonic', 'privateKey', 'seed', 'unlock']) assert.equal(kept[name], undefined, name);

  // Even on an allowed field, phrase-shaped and key-shaped values are replaced.
  assert.equal(redact({ reason: PHRASE }).reason, '[redacted: phrase-shaped]');
  assert.equal(redact({ reason: 'ab'.repeat(80) }).reason, '[redacted: key-shaped]');
  assert.equal(redact({ reason: { nested: 'object' } }).reason, '[object]');
  assert.ok(redact({ reason: 'x'.repeat(400) }).reason.length <= 121, 'long values are cut');

  // The allowlist itself names nothing secret.
  for (const field of ALLOWED_EVENT_FIELDS) {
    assert.ok(!/mnemonic|privateKey|secret|seed|unlock|password/i.test(field), field);
  }
});

test('the events a refusal produces say what happened and nothing about the money', async t => {
  const seen = [];
  const env = await start(t, { securitySink: record => seen.push(record) });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 900_000 }];

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, operation.id);

  // A broadcast carrying no authorisation at all: refused, and recorded as refused.
  const refused = await alex.post(`/api/operations/${operation.id}/broadcast`, { hex: '00' });
  assert.equal(refused.status, 409);

  const kinds = seen.map(e => e.event);
  assert.ok(kinds.includes(EVENT.SIGNING_ATTEMPT), 'the attempt was recorded');
  assert.ok(kinds.includes(EVENT.AUTHORIZATION_FAILURE), 'the authorisation failure was recorded');
  assert.ok(kinds.includes(EVENT.SIGNING_REJECTED), 'and the rejection');
  assert.ok(!kinds.includes(EVENT.SIGNING_SUCCESS), 'nothing was signed');

  // And the same operation, properly authorised, records a success.
  const sent = await signAndSend(env, alex, operation.id);
  assert.ok(sent.txid);
  const success = seen.find(e => e.event === EVENT.SIGNING_SUCCESS);
  assert.ok(success, 'the success was recorded');
  assert.equal(success.txid, sent.txid);
  assert.equal(success.isolation, 'none:browser-javascript', 'the log says where it was signed');

  for (const record of seen) {
    const line = JSON.stringify(record);
    assert.ok(!line.includes(PHRASE), 'no phrase in an event');
    assert.ok(!/"(mnemonic|privateKey|seed|secretKey|unlock)"/.test(line), 'no secret field in an event');
  }
});

test('a legacy migration is recorded, and a legacy spend attempt is recorded as refused', async t => {
  const seen = [];
  const env = await start(t, { securitySink: record => seen.push(record) });
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'd'.repeat(64), vout: 0, value: 400_000 }];

  const refused = await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 });
  assert.equal(refused.status, 409);
  const rejection = seen.find(e => e.event === EVENT.SIGNING_REJECTED);
  assert.ok(rejection, 'the refusal was recorded');
  assert.equal(rejection.custody, 'server');
  assert.match(rejection.reason, /legacy server custody/);
});

/* =============================================== the wallet is not bound to a scanner */

test('the wallet a phrase opens does not depend on any scanner', async () => {
  const first = await restored();
  const second = await restored();

  // Different device record, different unlock secret, different salt, different moment — and
  // the same wallet. A scanner cannot change which wallet a phrase opens, because no scanner
  // is an input to any of it: the two calls above differ in everything that is allowed to
  // vary, and the address does not move.
  assert.equal(first.made.address, ADDRESS_OF_PHRASE);
  assert.equal(second.made.address, ADDRESS_OF_PHRASE, 'the same phrase is the same wallet');
  assert.equal(first.made.publicKey, second.made.publicKey);
  assert.notEqual(first.record.blob, second.record.blob, 'and the stored blob differs, as it must');

  // The phrase that comes back out of each device is the same phrase, so the two records are
  // two encryptions of one secret rather than two different wallets.
  assert.equal(await revealPhrase(second.record, { unlock: second.unlock }), PHRASE);
});

test('the wallet module does not import the scanner, so it cannot depend on one', () => {
  const source = fs.readFileSync(new URL('../client/wallet.js', import.meta.url), 'utf8');
  assert.ok(!/from '\.\.\/src\/scanner\.js'/.test(source), 'no scanner import in the wallet module');
  assert.ok(!/scanner/i.test(source.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')), 'no scanner reference in wallet code');

  // And a provider that could touch keys or raw biometrics is refused outright.
  const scanner = assertProvider(createNullScanner());
  assert.equal(scanner.getCapabilities().available, false);
  for (const forbidden of ['deriveKey', 'unwrapKey', 'getKey', 'getTemplate', 'getImage', 'getRawCapture']) {
    assert.throws(() => assertProvider({ ...scanner, [forbidden]: () => {} }), /must not touch key or biometric material/, forbidden);
  }
  assert.deepEqual(scanner.discover instanceof Function, true, 'discovery is part of the interface');
});

test('the scanner route reports that there is no scanner', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const said = ok(await alex.get('/api/scanner'));
  assert.equal(said.available, false);
  assert.equal(said.provider, 'null');
  assert.equal(said.presentationAttackDetection, false);
  assert.equal(said.deviceAttestation, false);
  assert.equal(said.authorizationVersion, 1, 'records stay at V1 until a provider exists');
  assert.notEqual(said.padResult, SCANNER.PASSED);
});
