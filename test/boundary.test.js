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
  vaultId: 'tb1qvault', accountId: 'bitcoin', subject: 'user-alex', proposalId: 'proposal-1',
  transactionHash: 'digest-1', statementDigest: 'statement-1',
  chain: 'bitcoin', network: 'testnet4', policyVersion: 'policy-v1', nonce: 'nonce-1',
  // An integer a verifier can check, not the display string version 1 carried.
  threshold: 1,
  approvalMethod: 'veyns:palm',
  approvedBy: ['alex'], decisionIds: ['d1'], approvedAt: 1_800_000_000,
  expiresAt: 1_800_001_800,
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
    // The institutional fields the server sends, so the receipt can establish its own policy.
    // `withdrawalUnlock` in src/app.js is where these come from in the real flow.
    authorizationId: 'op-fixture',
    proposalId: 'op-fixture',
    accountId: 'bitcoin',
    subject: 'subject-fixture',
    chain: 'bitcoin',
    network: 'testnet4',
    policyVersion: 'policy-fixture',
    threshold: 1,
    expiresAt: 1_800_001_800,
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

test('a version 2 authorisation can be made without a scanner, and records that plainly', () => {
  /*
   * This test replaces one asserting that V2 could NOT be made. That property was deliberately
   * removed: gating the institutional fields on scanner evidence meant V1 could not prove the
   * policy, V2 could but nothing could emit it, and therefore no receipt could prove the
   * policy at all. Phase A finding F1. The property that survives — and is tested below and in
   * the forgery test that follows — is that a record may never CLAIM a measurement it does not
   * have.
   */
  const keys = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const parts = { ...V2_PARTS };

  // No scanner at all: it signs, and the absence is a recorded value rather than a gap.
  const plain = signAuthorizationV2(parts, keys, null);
  assert.equal(plain.record.v, AUTHORIZATION_VERSIONS.V2);
  assert.equal(plain.record.verification.sensorEvidence, 'none');
  assert.equal(plain.record.verification.padResult, SCANNER.NOT_AVAILABLE);
  assert.equal(plain.record.verification.biometricVerification, SCANNER.NOT_AVAILABLE);
  assert.notEqual(plain.record.verification.padResult, SCANNER.PASSED);
  assert.equal(plain.record.verification.scannerAttestation, null);
  assert.ok(!('biometricVerified' in plain.record), 'and never V1s unconditional assertion');

  // What it is for is in the record, which is the whole point of the version.
  assert.equal(plain.record.policyVersion, 'policy-v1');
  assert.equal(plain.record.threshold, 1);
  assert.equal(plain.record.approvalCount, 1);
  assert.equal(plain.record.proposalId, 'proposal-1');
  assert.equal(plain.record.chain, 'bitcoin');
  assert.equal(plain.record.network, 'testnet4');
  assert.equal(verifyAuthorization(plain, keys.publicKeyBase64, { transactionHash: 'digest-1' }).ok, true);

  // What the only provider in this build can offer produces the same honest 'none'.
  const scanner = createNullScanner();
  const fromNull = signAuthorizationV2(parts, keys, {
    provider: scanner.name,
    pad: scanner.getPADResult(),
    biometric: scanner.getBiometricResult(),
    attestation: scanner.getAttestation(),
    scannerClass: null, captureReference: null, bindingNonce: parts.transactionHash,
  });
  assert.equal(fromNull.record.verification.sensorEvidence, 'none');

  // A record that does not say what it is about is refused before anything is signed.
  for (const name of ['vaultId', 'subject', 'proposalId', 'chain', 'network', 'policyVersion', 'nonce', 'accountId']) {
    assert.throws(
      () => signAuthorizationV2({ ...parts, [name]: undefined }, keys, null),
      new RegExp(`must name: .*${name}`),
      name,
    );
  }
  // The threshold has to be a number a verifier can check, not a label.
  for (const bad of [undefined, 0, -1, '2', 1.5]) {
    assert.throws(() => signAuthorizationV2({ ...parts, threshold: bad }, keys, null), /integer threshold/, String(bad));
  }
  // And it may never claim a requirement it did not reach.
  assert.throws(
    () => signAuthorizationV2({ ...parts, threshold: 3, approvedBy: ['alex', 'sam'] }, keys, null),
    /cannot claim a threshold of 3 with 2 distinct approvers/,
  );
  // Counting one approver twice does not reach a threshold either.
  assert.throws(
    () => signAuthorizationV2({ ...parts, threshold: 2, approvedBy: ['alex', 'alex'] }, keys, null),
    /with 1 distinct approvers/,
  );

  // With real evidence it says so, and evidence about another transaction is refused.
  const measured = signAuthorizationV2(parts, keys, completeEvidence());
  assert.equal(measured.record.verification.sensorEvidence, 'measured');
  assert.equal(measured.record.verification.padResult, SCANNER.PASSED);
  assert.throws(
    () => signAuthorizationV2(parts, keys, completeEvidence('another-digest')),
    /bound to a different transaction/,
  );

  // And a finished record cannot be moved onto another wallet, proposal, ruleset or threshold.
  for (const [field, value] of [
    ['vaultId', 'tb1qsomeoneelse'], ['accountId', 'ethereum'], ['chain', 'ethereum'],
    ['network', 'mainnet'], ['policyVersion', 'policy-v2'], ['subject', 'user-sam'],
    ['nonce', 'nonce-2'], ['proposalId', 'proposal-2'], ['threshold', 2],
  ]) {
    assert.equal(verifyAuthorization(plain, keys.publicKeyBase64, { [field]: value }).ok, false, field);
  }
});

test('a version 2 record that claims more than it measured is refused', () => {
  const keys = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const good = signAuthorizationV2({ ...V2_PARTS }, keys, completeEvidence());

  /*
   * Every forgery is signed properly with the real key over the tampered record, so each
   * refusal below is about the record's CONTENTS and not about a signature that failed. The
   * control re-signs the untouched record the same way and requires it to verify — without it,
   * every assertion here could pass for the wrong reason.
   */
  const forge = change => {
    const record = { ...good.record, ...change };
    return { ...good, record, signature: rawSign(record, keys) };
  };
  const forgeVerification = change => forge({ verification: { ...good.record.verification, ...change } });

  assert.equal(
    verifyAuthorization(forge({}), keys.publicKeyBase64).ok, true,
    'control: re-signing an untouched record still verifies, so the refusals below are about contents',
  );

  // Claiming a measurement it does not have. This is the Phase 1 property, preserved.
  const claims = {
    'pad asserted rather than measured': { padResult: true },
    'match asserted rather than measured': { biometricVerification: true },
    'no attestation': { scannerAttestation: '' },
    'no scanner class': { scannerClass: null },
    'no capture': { captureReference: null },
    'evidence from another transaction': { bindingNonce: 'another-digest' },
    'no biometric policy version': { biometricPolicyVersion: null },
    'an unknown evidence state': { sensorEvidence: 'probably' },
  };
  for (const [what, change] of Object.entries(claims)) {
    assert.equal(verifyAuthorization(forgeVerification(change), keys.publicKeyBase64).ok, false, what);
  }

  // The opposite direction: saying nothing was measured while carrying evidence of one.
  // A complete 'none': the verdicts have to come back to NOT_AVAILABLE too. Leaving PASSED in
  // place while claiming nothing was measured is itself one of the refusals, tested below.
  const nothing = {
    sensorEvidence: 'none',
    padResult: SCANNER.NOT_AVAILABLE,
    biometricVerification: SCANNER.NOT_AVAILABLE,
    scannerAttestation: null, scannerClass: null, captureReference: null, bindingNonce: null,
  };
  assert.equal(verifyAuthorization(forgeVerification(nothing), keys.publicKeyBase64).ok, true, 'an honest none verifies');
  for (const [what, change] of Object.entries({
    'none, but carrying an attestation': { ...nothing, scannerAttestation: 'sig' },
    'none, but naming a scanner': { ...nothing, scannerClass: 'class-1' },
    'none, but reporting a pass': { ...nothing, padResult: SCANNER.PASSED },
  })) {
    assert.equal(verifyAuthorization(forgeVerification(change), keys.publicKeyBase64).ok, false, what);
  }

  // And claims about the payment itself.
  for (const [what, change] of Object.entries({
    'a threshold it did not reach': { threshold: 5 },
    'an approver counted twice': { approvedBy: ['alex', 'alex'], approvalCount: 2 },
    'a miscounted approver list': { approvalCount: 9 },
    'the version 1 assertion smuggled in': { biometricVerified: true },
    'no policy version': { policyVersion: null },
    'no proposal': { proposalId: null },
  })) {
    assert.equal(verifyAuthorization(forge(change), keys.publicKeyBase64).ok, false, what);
  }
});

test('a verdict says what the record it verified can and cannot establish', () => {
  const keys = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);

  // Version 1 is the receipt this product produced until now. It proves a key approved a
  // digest, and genuinely nothing about the rules that governed the payment.
  const v1 = signAuthorization({
    vaultId: 'tb1qvault', accountId: 'bitcoin', transactionHash: 'digest-1',
    statementDigest: 'statement-1', approvalMethod: 'veyns:palm', approvals: '1 of 1',
    approvedBy: ['alex'], decisionIds: ['d1'], approvedAt: 1_800_000_000,
  }, keys);
  const onV1 = verifyAuthorization(v1, keys.publicKeyBase64);
  assert.equal(onV1.ok, true, 'it still verifies');
  assert.equal(onV1.proves.transaction, true);
  assert.equal(onV1.proves.policy, false, 'and establishes no policy');
  assert.equal(onV1.proves.threshold, false);
  assert.equal(onV1.proves.chain, false);
  assert.equal(onV1.proves.proposal, false);
  assert.equal(onV1.proves.sensorMeasurement, false);
  assert.match(onV1.proves.notes, /does NOT establish the policy/);

  // Version 2 establishes the policy and threshold, and still claims no measurement.
  const onV2 = verifyAuthorization(signAuthorizationV2({ ...V2_PARTS }, keys, null), keys.publicKeyBase64);
  assert.equal(onV2.ok, true);
  assert.equal(onV2.proves.policy, true);
  assert.equal(onV2.proves.threshold, true);
  assert.equal(onV2.proves.chain, true);
  assert.equal(onV2.proves.proposal, true);
  assert.equal(onV2.proves.sensorMeasurement, false, 'because there is no scanner in this build');
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
