/*
 * The security boundary, tested at its edges.
 *
 * Three things are asserted here and nothing else:
 *
 *   1. The narrow wallet interface the page is allowed to call still refuses every
 *      substitution the old primitives refused — destination, amount, fee, network and
 *      structure — and gives back nothing that could be used to sign anything else.
 *   2. A vault whose key is held on the server cannot spend, and can still get out.
 *   3. Nothing in this repository can report a biometric or liveness pass, because there is
 *      no scanner. A version 2 authorisation cannot be produced, and a forged one is refused.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { base64 } from '@scure/base';
import { planSpend } from '../src/bitcoin.js';
import { canonicalJson } from '../src/canonical.js';
import { SCANNER, createNullScanner, evidenceIsUsable, assertProvider, ScannerUnavailable } from '../src/scanner.js';
import {
  deriveAttestationKeys, signAuthorization, signAuthorizationV2, verifyAuthorization,
  AuthorizationUnavailable, AUTHORIZATION_VERSIONS, AUTHORIZATION_CONTEXT,
} from '../src/authorization.js';
import {
  createVaultKey, signApprovedSpend, cosignerPublicKeyFor, revealPhrase, restoreVaultKey,
  loadRecord, clearRecord, planDigest,
} from '../client/wallet.js';
import { DEST, start, ok, signedIn, palmApprove, legacyWallet , startWithMigration } from './harness.js';

/* ------------------------------------------------------------ a browser, in Node */

/**
 * The smallest IndexedDB that satisfies the wallet module's four calls.
 *
 * The module stores an encrypted blob and reads it back; that is the whole contract, and
 * standing it up here is what lets the interface be tested at all rather than only in a
 * browser nobody runs in CI.
 */
function installStorage() {
  const rows = new Map();
  const settle = (result, upgrade) => {
    const request = { result, onsuccess: null, onerror: null, onupgradeneeded: null };
    // Queued now, delivered after the caller has attached its handlers.
    queueMicrotask(() => {
      if (upgrade) request.onupgradeneeded?.();
      request.onsuccess?.();
    });
    return request;
  };
  const store = {
    get: key => settle(rows.get(key)),
    put: (value, key) => { rows.set(key, value); return settle(undefined); },
    delete: key => { rows.delete(key); return settle(undefined); },
  };
  globalThis.indexedDB = {
    open: () => settle({
      createObjectStore() {},
      transaction: () => ({ objectStore: () => store }),
      close() {},
    }, true),
  };
  return rows;
}

const b64 = n => Buffer.from(crypto.randomBytes(n)).toString('base64');
const coins = [{ txid: 'a'.repeat(64), vout: 0, value: 500_000 }];
/** A second valid testnet address, so a substitution test cannot pass by being malformed. */
const ELSEWHERE = 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7';

/** Everything a version 2 record has to name about what is being authorised. */
const V2_PARTS = {
  vaultId: 'tb1qvault', accountId: 'bitcoin', subject: 'user-alex',
  transactionHash: 'digest-1', statementDigest: 'statement-1',
  chain: 'bitcoin', network: 'testnet4', policyVersion: 'policy-v1', nonce: 'nonce-1',
  approvalMethod: 'veyns:palm', approvals: '1 of 1',
  approvedBy: ['alex'], decisionIds: ['d1'], approvedAt: 1_800_000_000,
};

/** Evidence shaped the way a real provider would return it, for testing refusals against. */
const PASS = { result: SCANNER.PASSED, performed: true };
const completeEvidence = (bindingNonce = 'digest-1') => ({
  provider: 'test', pad: PASS, biometric: PASS, attestation: { ...PASS, signature: 'sig' },
  scannerClass: 'class-1', captureReference: 'capture-1', sessionId: 'session-1', bindingNonce,
});

/**
 * Signs whatever record it is handed, rather than building one.
 *
 * `signAuthorization` constructs its own V1 record from parts, so it cannot be used to sign a
 * tampered V2 record — a test that tried would only prove the signature did not match.
 */
const rawSign = (record, keys) => base64.encode(ml_dsa65.sign(
  new TextEncoder().encode(canonicalJson(record)),
  keys.secretKey,
  { context: new TextEncoder().encode(AUTHORIZATION_CONTEXT) },
));

/** A vault made the way the page makes one, and an unlock the way the palm gate returns one. */
async function browserVault() {
  installStorage();
  const unlock = b64(32);
  const salt = b64(16);
  const made = await createVaultKey({
    serverRandom: new Uint8Array(crypto.randomBytes(32)),
    jitterSeed: ['test', 1, 2],
    unlock,
    salt,
  });
  const record = await loadRecord();
  const plan = planSpend({
    publicKey: Buffer.from(made.publicKey, 'hex'),
    utxos: coins,
    toAddress: DEST,
    amountSats: 120_000,
    feeRate: 2,
  });
  const transactionHash = planDigest({ network: 'testnet4', from: made.address, plan });
  const unlocked = {
    unlock,
    salt,
    plan,
    transactionHash,
    statementDigest: 'statement-digest',
    approvals: '1 of 1',
    approvedBy: ['alex'],
    decisionIds: ['decision-1'],
    attestationEpoch: 1,
  };
  return { made, record, plan, unlocked };
}

/* ============================================ the interface keeps the binding */

test('the narrow interface signs the approved transaction and nothing else', async () => {
  const { made, record, plan, unlocked } = await browserVault();

  const signed = await signApprovedSpend(record, unlocked, { network: 'testnet4' });
  assert.ok(signed.hex, 'the approved plan signs');
  assert.equal(signed.authorization.record.transactionHash, unlocked.transactionHash);
  assert.equal(signed.authorization.record.vaultId, made.address);

  // Every substitution the brief names, against the digest the palm actually approved.
  const swaps = {
    // A valid address, so the refusal can only be about the digest and not about parsing.
    'destination moved': { ...plan, outputs: plan.outputs.map(o => (o.address === DEST ? { ...o, address: ELSEWHERE } : o)) },
    'amount raised': { ...plan, outputs: plan.outputs.map(o => (o.address === DEST ? { ...o, sats: o.sats * 3 } : o)) },
    'fee raised': { ...plan, feeSats: plan.feeSats + 20_000 },
    'another coin spent': { ...plan, inputs: [{ ...plan.inputs[0], txid: 'b'.repeat(64) }] },
    'an output added': { ...plan, outputs: [...plan.outputs, { address: DEST, sats: 1 }] },
  };
  for (const [what, altered] of Object.entries(swaps)) {
    await assert.rejects(
      () => signApprovedSpend(record, { ...unlocked, plan: altered }, { network: 'testnet4' }),
      /not the transaction that was approved/,
      what,
    );
  }

  // The network is part of the digest, so signing on another one is signing another thing.
  await assert.rejects(
    () => signApprovedSpend(record, unlocked, { network: 'mainnet' }),
    /not the transaction that was approved/,
    'network swapped',
  );
});

test('the interface gives back nothing that could sign anything else', async () => {
  const { record, unlocked } = await browserVault();
  const phrase = await revealPhrase(record, unlocked);

  const signed = await signApprovedSpend(record, unlocked, { network: 'testnet4' });
  assert.deepEqual(Object.keys(signed).sort(), ['authorization', 'hex', 'txid']);

  // Nothing the page receives contains the phrase, or any word of it.
  const returned = JSON.stringify(signed);
  assert.ok(!returned.includes(phrase), 'the phrase is not in the result');
  for (const word of phrase.split(' ')) {
    assert.ok(!returned.includes(`"${word}"`), `the result does not carry "${word}"`);
  }

  // The co-signer call hands back a public key and keeps the private half.
  const publicKey = await cosignerPublicKeyFor(record, unlocked, 0);
  assert.match(publicKey, /^0[23][0-9a-f]{64}$/, 'a compressed public key and nothing more');
});

test('a phrase that belongs to another wallet is refused before it is stored', async () => {
  const { record } = await browserVault();
  const other = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  await assert.rejects(
    () => restoreVaultKey(other, { unlock: b64(32), salt: b64(16) }, record.address),
    /belong to a different wallet/,
  );
  // And the record that was already here is untouched.
  assert.equal((await loadRecord()).address, record.address);
  await clearRecord();
});

/* ==================================== a legacy vault cannot spend, and can leave */

test('a vault whose key is on the server cannot be spent from', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 400_000 }];

  const refused = await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 });
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /Move the vault into your browser/);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing was signed by the server');
});

test('the way out of legacy custody still works, and retires the key', async t => {
  const env = await startWithMigration(t);
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  env.world.chain.utxos = [{ txid: 'd'.repeat(64), vout: 0, value: 400_000 }];

  assert.equal(ok(await alex.get('/api/wallet')).wallet.custody, 'server');
  const { operation } = ok(await alex.post('/api/wallet/upgrade/approval', {}));
  await palmApprove(env, alex, operation.id);

  const { browserKey } = await import('./harness.js');
  const made = browserKey();
  const moved = ok(await alex.post('/api/wallet/upgrade', {
    operationId: operation.id,
    address: made.address,
    publicKey: made.publicKey,
    attestationRegistration: made.attestationRegistration,
  }));
  assert.equal(moved.wallet.custody, 'client');
  assert.ok(moved.txid, 'the coins came with it');

  // And now it can be spent from, which it could not be a moment ago.
  const planned = await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 });
  assert.notEqual(planned.status, 409, 'a browser-held vault plans a withdrawal');
});

test('a legacy vault says what it is, rather than how strong its envelope is', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-legacy');
  await legacyWallet(env, alex);
  const { wallet } = ok(await alex.get('/api/wallet'));
  assert.match(wallet.protection, /Legacy/);
  assert.match(wallet.protection, /can no longer spend/);
});

/* ================================================ there is no scanner, and it says so */

test('the only scanner provider reports nothing and can never report a pass', () => {
  const scanner = assertProvider(createNullScanner());
  assert.equal(scanner.getCapabilities().available, false);
  assert.equal(scanner.getCapabilities().presentationAttackDetection, false);
  assert.equal(scanner.getCapabilities().deviceAttestation, false);

  for (const ask of ['getPADResult', 'getBiometricResult', 'getAttestation']) {
    const said = scanner[ask]();
    assert.equal(said.result, SCANNER.NOT_AVAILABLE, ask);
    assert.equal(said.performed, false, ask);
    assert.notEqual(said.result, SCANNER.PASSED, ask);
  }
  assert.throws(() => scanner.connect(), ScannerUnavailable);
  assert.throws(() => scanner.capture(), ScannerUnavailable);

  // A provider missing any part of the interface is caught where it is installed.
  assert.throws(() => assertProvider({ getCapabilities: () => ({}) }), /missing/);
});

test('evidence is only usable when every check was performed and passed', () => {
  assert.equal(evidenceIsUsable(undefined).ok, false);
  assert.equal(evidenceIsUsable({}).ok, false);

  const pass = { result: SCANNER.PASSED, performed: true };
  const whole = {
    provider: 'test', pad: pass, biometric: pass, attestation: { ...pass, signature: 'sig' },
    scannerClass: 'class-1', captureReference: 'capture-1', bindingNonce: 'digest-1',
  };
  assert.equal(evidenceIsUsable(whole).ok, true, 'complete evidence is usable');

  // A truthy value that is not a performed pass is not a pass.
  for (const [part, bad] of [
    ['pad', { result: true, performed: true }],
    ['biometric', { result: SCANNER.PASSED, performed: false }],
    ['attestation', { result: SCANNER.NOT_AVAILABLE, performed: true }],
  ]) {
    assert.equal(evidenceIsUsable({ ...whole, [part]: bad }).ok, false, part);
  }
  for (const missing of ['scannerClass', 'captureReference', 'bindingNonce']) {
    assert.equal(evidenceIsUsable({ ...whole, [missing]: null }).ok, false, missing);
  }
});

test('a version 2 authorisation cannot be made, because nothing can measure one', () => {
  const keys = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const parts = { ...V2_PARTS };
  const scanner = createNullScanner();

  // What the only provider in this build can actually offer.
  const fromTheNullScanner = {
    provider: scanner.name,
    pad: scanner.getPADResult(),
    biometric: scanner.getBiometricResult(),
    attestation: scanner.getAttestation(),
    scannerClass: null,
    captureReference: null,
    bindingNonce: parts.transactionHash,
  };
  assert.throws(() => signAuthorizationV2(parts, keys, fromTheNullScanner), AuthorizationUnavailable);
  assert.throws(() => signAuthorizationV2(parts, keys, undefined), AuthorizationUnavailable);

  // Evidence for a different transaction is refused even when every check passed.
  assert.throws(() => signAuthorizationV2(parts, keys, completeEvidence('another-digest')), /bound to a different transaction/);

  // A record that does not say what it is about is refused before the evidence is looked at.
  for (const name of ['vaultId', 'subject', 'chain', 'network', 'policyVersion', 'nonce', 'accountId']) {
    assert.throws(
      () => signAuthorizationV2({ ...parts, [name]: undefined }, keys, completeEvidence()),
      new RegExp(`must name: .*${name}`),
      name,
    );
  }

  // With complete, correctly bound evidence it signs — which is what makes the refusals above
  // a statement about the evidence rather than about the function being unfinished.
  const signed = signAuthorizationV2(parts, keys, completeEvidence());
  assert.equal(signed.record.v, AUTHORIZATION_VERSIONS.V2);
  assert.equal(signed.record.padResult, SCANNER.PASSED);
  assert.equal(signed.record.subject, 'user-alex');
  assert.equal(signed.record.policyVersion, 'policy-v1');
  assert.equal(signed.record.chain, 'bitcoin');
  assert.equal(signed.record.network, 'testnet4');
  assert.ok(!('biometricVerified' in signed.record), 'V2 does not assert what it did not measure');
  assert.equal(verifyAuthorization(signed, keys.publicKeyBase64, { transactionHash: 'digest-1' }).ok, true);

  // And it cannot be moved onto another wallet, account, chain, network, person or ruleset.
  for (const [field, value] of [
    ['vaultId', 'tb1qsomeoneelse'], ['accountId', 'ethereum'], ['chain', 'ethereum'],
    ['network', 'mainnet'], ['policyVersion', 'policy-v2'], ['subject', 'user-sam'], ['nonce', 'nonce-2'],
  ]) {
    const moved = verifyAuthorization(signed, keys.publicKeyBase64, { [field]: value });
    assert.equal(moved.ok, false, field);
  }
});

test('a version 2 record with placeholders instead of measurements is refused', () => {
  const keys = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const good = signAuthorizationV2({ ...V2_PARTS }, keys, completeEvidence());

  // The whole point of this test is that the record is refused on its CONTENTS, so each
  // forgery is signed properly with the real key over the tampered record. A signature that
  // did not verify would make every assertion below pass for the wrong reason, so the control
  // at the end re-signs the untouched record the same way and requires it to verify.
  const forge = change => {
    const record = { ...good.record, ...change };
    return { ...good, record, signature: rawSign(record, keys) };
  };
  assert.equal(
    verifyAuthorization(forge({}), keys.publicKeyBase64).ok, true,
    'control: re-signing an untouched record still verifies, so the refusals below are about contents',
  );

  const attacks = {
    'pad asserted rather than measured': { padResult: true },
    'match asserted rather than measured': { biometricVerification: true },
    'no attestation': { scannerAttestation: '' },
    'no scanner class': { scannerClass: null },
    'evidence from another transaction': { bindingNonce: 'another-digest' },
    'the version 1 assertion smuggled in': { biometricVerified: true },
    'no policy version': { policyVersion: null },
    'no subject': { subject: null },
    'no chain': { chain: null },
    'no network': { network: null },
    'no nonce': { nonce: null },
  };
  for (const [what, change] of Object.entries(attacks)) {
    assert.equal(verifyAuthorization(forge(change), keys.publicKeyBase64).ok, false, what);
  }
});

test('version 1 still verifies, and a caller can require version 2 without changing that', () => {
  const keys = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const v1 = signAuthorization({
    vaultId: 'tb1qvault', accountId: 'bitcoin', transactionHash: 'digest-1',
    statementDigest: 'statement-1', approvalMethod: 'veyns:palm', approvals: '1 of 1',
    approvedBy: ['alex'], decisionIds: ['d1'], approvedAt: 1_800_000_000,
  }, keys);

  assert.equal(verifyAuthorization(v1, keys.publicKeyBase64).ok, true, 'V1 is unchanged');
  assert.equal(v1.record.v, AUTHORIZATION_VERSIONS.V1);
  assert.equal(v1.record.biometricVerified, true, 'V1 still says what it always said');

  const required = verifyAuthorization(v1, keys.publicKeyBase64, { minVersion: AUTHORIZATION_VERSIONS.V2 });
  assert.equal(required.ok, false);
  assert.match(required.reason, /requires a version 2/);
});
