/*
 * The human authorisation record, and its post-quantum signature.
 *
 * The key that signs these records belongs to the vault's owner, not to this server. It is
 * derived in the browser from the same recovery phrase as the wallet key, under its own HKDF
 * label and epoch, and the server is told only the public half. There is deliberately no
 * function here that derives a signing key from anything the server holds: a QuVault
 * deployment cannot manufacture an authorisation record, because it has nothing to sign with.
 *
 * The record is small and dull on purpose: which vault, which transaction digest, when, by
 * what method, and the identifiers of the palm decisions that settled it. No biometric data
 * of any kind — not an image, not a template, not a score.
 *
 * This module holds no Node or browser APIs, so the page signs and the server verifies with
 * the same code rather than with two implementations that might disagree.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { canonicalJson } from './canonical.js';
import { SCANNER, evidenceIsUsable } from './scanner.js';

const VERSION = 1;
const VERSION_2 = 2;
const KNOWN_VERSIONS = new Set([VERSION, VERSION_2]);
const CONTEXT = 'QUVAULT-HUMAN-AUTHORIZATION-V1'; // FIPS 204 context: nothing else signs under it
const utf8 = text => new TextEncoder().encode(text);
const context = utf8(CONTEXT);

/** The bytes signed are the canonical record; the purpose is carried by the context. */
const signedBytes = record => utf8(canonicalJson(record));

/**
 * The vault's attestation key, from the owner's own seed bytes and an epoch.
 *
 * Deriving it from the recovery phrase rather than storing a second independent secret is a
 * deliberate choice: the same twelve words restore both capabilities, the same palm-gated
 * unlock releases both, and there is no new secret to lose. The trade-off is that the two
 * keys share a root — anyone holding the phrase can both spend and attest — which is no loss,
 * because holding the phrase already means holding the money.
 *
 * `epoch` exists so a key can be replaced: a new epoch is a new key from the same phrase.
 */
export function deriveAttestationKeys(seedBytes, epoch = 1) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length < 32) {
    throw new Error('An attestation key needs at least 32 bytes of seed material.');
  }
  if (!Number.isInteger(epoch) || epoch < 1) throw new Error('The attestation epoch starts at 1.');
  const material = hkdf(sha256, seedBytes, utf8('quvault attestation'), utf8(`quvault ml-dsa attestation v1 epoch ${epoch}`), 32);
  const { publicKey, secretKey } = ml_dsa65.keygen(material);
  material.fill(0);
  return { publicKey, secretKey, epoch, keyId: keyIdOf(publicKey), publicKeyBase64: base64.encode(publicKey) };
}

/** A short, stable name for a key, so a receipt says which key to check it with. */
export const keyIdOf = publicKey => base64.encode(sha256(publicKey)).replace(/[+/=]/g, '').slice(0, 22);

/* ------------------------------------------- version 2, the institutional record */

/*
 * V2 answers the two questions V1 cannot: under what rules was this payment authorised, and
 * what — if anything — did a sensor actually measure.
 *
 * WHY THIS REPLACED THE EARLIER V2. The first version of this record required scanner evidence
 * in which every check was an explicit PASS, and the only scanner provider in this build
 * returns NOT_AVAILABLE to everything. The effect was that V1 could not prove the policy, V2
 * could but nothing could emit it, and so no receipt could prove the policy at all. That
 * conflated two orthogonal things: which rules governed a payment, and what a palm sensor saw.
 * Institutional policy binding does not need a scanner. They are now separate.
 *
 * So a V2 record always carries the institutional fields, and always carries an explicit
 * statement of what was measured — where "nothing was measured" is a legitimate, recorded
 * value rather than a gap. That is the opposite of manufacturing evidence: the record says
 * NOT_AVAILABLE, in writing, signed, and a reader who needs more can demand it.
 *
 * No V2 record was ever produced under the earlier shape, so nothing historical is reinterpreted.
 */
export class AuthorizationUnavailable extends Error {}

/** The ruleset under which the human-verification fields were judged. */
const BIOMETRIC_POLICY_VERSION = 'quvault-biometric-policy-1';

/**
 * What a V2 record must name about the payment itself.
 *
 * `threshold` and `approvalCount` are integers, not the display string V1 used — an independent
 * verifier has to be able to check that the requirement was met without parsing English.
 */
const V2_REQUIRED_PARTS = [
  'vaultId', 'accountId', 'subject', 'proposalId',
  'transactionHash', 'statementDigest', 'chain', 'network',
  'policyVersion', 'nonce',
];

/** The shape of the human-verification statement. Absent evidence is still a statement. */
function verificationFrom(evidence, transactionHash) {
  const result = part => evidence?.[part]?.result ?? SCANNER.NOT_AVAILABLE;
  const measured = evidenceIsUsable(evidence).ok;
  if (measured && evidence.bindingNonce !== transactionHash) {
    // Evidence that passed but describes another transaction is a replayed token, not evidence.
    throw new AuthorizationUnavailable('The scanner evidence is bound to a different transaction.');
  }
  return {
    // Who said a human approved. Today this is the Veyns palm decision the operation collected.
    approvalProvider: evidence?.provider ?? 'veyns',
    // What a sensor in this deployment measured. Nothing, in this build, and it says so.
    padResult: result('pad'),
    biometricVerification: result('biometric'),
    scannerAttestation: measured ? evidence.attestation.signature : null,
    scannerClass: evidence?.scannerClass ?? null,
    captureReference: evidence?.captureReference ?? null,
    bindingNonce: measured ? evidence.bindingNonce : null,
    biometricPolicyVersion: BIOMETRIC_POLICY_VERSION,
    // One field a reader can branch on without interpreting the five above.
    sensorEvidence: measured ? 'measured' : 'none',
  };
}

export function signAuthorizationV2(parts, keys, evidence = null) {
  const absent = V2_REQUIRED_PARTS.filter(name => !parts?.[name]);
  if (absent.length) {
    throw new AuthorizationUnavailable(`A version 2 authorisation must name: ${absent.join(', ')}.`);
  }
  if (!Number.isInteger(parts.threshold) || parts.threshold < 1) {
    throw new AuthorizationUnavailable('A version 2 authorisation must name an integer threshold of at least 1.');
  }
  const approvedBy = [...new Set(parts.approvedBy)].sort();
  if (approvedBy.length < parts.threshold) {
    // A record claiming a threshold it did not reach would be evidence of the wrong thing.
    throw new AuthorizationUnavailable(
      `A version 2 authorisation cannot claim a threshold of ${parts.threshold} with ${approvedBy.length} distinct approvers.`);
  }
  const record = {
    v: VERSION_2,
    // Which vault, which account, whose, and which proposal. `subject` is the opaque
    // per-application identity — never a name, an email, or anything from a palm.
    vaultId: parts.vaultId,
    accountId: parts.accountId,
    subject: parts.subject,
    proposalId: parts.proposalId,
    // What was authorised, and where. The digest already covers chain and network; they are
    // named again so a record can be read without recomputing it.
    transactionHash: parts.transactionHash,
    statementDigest: parts.statementDigest,
    chain: parts.chain,
    network: parts.network,
    // Under what rules. Without these a record outlives the policy it was made under, and a
    // verifier cannot tell whether the requirement was met.
    policyVersion: parts.policyVersion,
    threshold: parts.threshold,
    approvalCount: approvedBy.length,
    approvalMethod: parts.approvalMethod,
    // One authorisation, once.
    nonce: parts.nonce,
    // What a human did, and what a sensor measured — stated separately and explicitly.
    verification: verificationFrom(evidence, parts.transactionHash),
    approvedBy,
    decisionIds: [...new Set(parts.decisionIds)].sort(),
    approvedAt: parts.approvedAt,
    expiresAt: parts.expiresAt ?? null,
    keyEpoch: keys.epoch ?? 1,
  };
  return {
    record,
    algorithm: 'ML-DSA-65',
    context: CONTEXT,
    keyId: keys.keyId ?? keyIdOf(keys.publicKey),
    signature: base64.encode(ml_dsa65.sign(signedBytes(record), keys.secretKey, { context })),
  };
}

/**
 * The structural checks a V2 record must pass beyond its signature.
 *
 * A signature proves the owner's key wrote the record; it does not prove the record says
 * anything coherent. These checks are what stop a record from claiming a threshold it did not
 * reach, or presenting an assertion where a measurement belongs.
 */
function checkV2(record) {
  for (const name of V2_REQUIRED_PARTS) {
    if (!record[name]) return `the record names no ${name}`;
  }
  if (!Number.isInteger(record.threshold) || record.threshold < 1) return 'the record names no integer threshold';
  if (!Array.isArray(record.approvedBy)) return 'the record names no approvers';
  const distinct = new Set(record.approvedBy);
  if (distinct.size !== record.approvedBy.length) return 'the record lists an approver twice';
  if (distinct.size < record.threshold) return 'the record claims a threshold it did not reach';
  if (record.approvalCount !== record.approvedBy.length) return 'the record miscounts its own approvers';

  const said = record.verification;
  if (!said || typeof said !== 'object') return 'the record says nothing about how the human was verified';
  if (!said.biometricPolicyVersion) return 'the record names no biometric policy version';
  if (!['measured', 'none'].includes(said.sensorEvidence)) return 'the record does not say whether a sensor measured anything';
  if (said.sensorEvidence === 'measured') {
    // Claiming a measurement means every part of it has to be a performed pass about this
    // transaction. An assertion is not a measurement, and `true` is not a result.
    if (said.padResult !== SCANNER.PASSED) return 'the record claims a measurement without a passed liveness check';
    if (said.biometricVerification !== SCANNER.PASSED) return 'the record claims a measurement without a passed match';
    if (typeof said.scannerAttestation !== 'string' || !said.scannerAttestation) return 'the record claims a measurement with no scanner attestation';
    if (!said.scannerClass) return 'the record claims a measurement but names no scanner class';
    if (!said.captureReference) return 'the record claims a measurement but names no capture';
    if (said.bindingNonce !== record.transactionHash) return 'the scanner evidence is bound to a different transaction';
  } else {
    // Saying nothing was measured means saying it consistently: no attestation, no capture.
    if (said.scannerAttestation || said.scannerClass || said.captureReference || said.bindingNonce) {
      return 'the record says nothing was measured but carries scanner evidence';
    }
    if (said.padResult === SCANNER.PASSED || said.biometricVerification === SCANNER.PASSED) {
      return 'the record says nothing was measured but reports a pass';
    }
  }
  // V1's unconditional assertion must not reappear in a V2 record and be read as evidence.
  if ('biometricVerified' in record) return 'a version 2 record cannot assert biometricVerified';
  return null;
}

/**
 * What a record actually establishes, for a reader deciding how much to rely on it.
 *
 * Returned alongside a verification so nobody has to infer it from the version number. A V1
 * record is not retroactively stronger for being verified by newer code.
 */
export function whatItProves(record) {
  const v2 = record?.v === VERSION_2;
  return Object.freeze({
    version: record?.v ?? null,
    transaction: Boolean(record?.transactionHash),
    // V1 carries `approvals` as a display string, so the requirement is not checkable.
    policy: v2 ? Boolean(record.policyVersion) : false,
    threshold: v2 ? Number.isInteger(record.threshold) : false,
    approvers: Array.isArray(record?.approvedBy) && record.approvedBy.length > 0,
    chain: v2 ? Boolean(record.chain && record.network) : false,
    proposal: v2 ? Boolean(record.proposalId) : false,
    // No build in this repository can measure a palm. See src/scanner.js.
    sensorMeasurement: v2 ? record.verification?.sensorEvidence === 'measured' : false,
    notes: v2
      ? 'A human approval was collected through the named provider. No sensor measurement is claimed unless sensorMeasurement is true.'
      : 'Version 1: proves the signing key approved this transaction digest. It does NOT establish the policy, the required threshold, the chain, or the proposal.',
  });
}

export const AUTHORIZATION_VERSIONS = Object.freeze({ V1: VERSION, V2: VERSION_2 });

/* ------------------------------------------------- which key is authoritative */

const REGISTRATION_CONTEXT = 'QUVAULT-ATTESTATION-KEY-REGISTRATION-V1';
const registrationContext = utf8(REGISTRATION_CONTEXT);

/**
 * A key says who it is, and who let it in.
 *
 * Epoch 1 signs its own registration, so the root is self-authenticating. Every later epoch
 * is signed by the key it replaces, naming that key by id. The chain of those records — not
 * a column in a table — decides which key is authoritative, so a database that is rewritten
 * cannot promote a key that no previous key ever signed for.
 */
export function signRegistration({ vaultId, publicKey, epoch, previousKeyId = null, registeredAt }, signingKeys) {
  const record = {
    v: VERSION,
    context: REGISTRATION_CONTEXT,
    vaultId,
    publicKey: typeof publicKey === 'string' ? publicKey : base64.encode(publicKey),
    epoch,
    previousKeyId,
    registeredAt,
  };
  return {
    record,
    algorithm: 'ML-DSA-65',
    signedBy: signingKeys.keyId ?? keyIdOf(signingKeys.publicKey),
    signature: base64.encode(ml_dsa65.sign(utf8(canonicalJson(record)), signingKeys.secretKey, { context: registrationContext })),
  };
}

/**
 * Walks a chain of registrations and returns the key it ends at, or why it does not.
 *
 * Epoch 1 must verify against itself; each later link must verify against the key before it,
 * name that key, and step the epoch by exactly one. A gap, a repeat, a wrong vault or a
 * signature by anything other than the previous key ends the walk with a refusal.
 */
export function verifyChain(chain, { vaultId, maxLength = 64 } = {}) {
  if (!Array.isArray(chain) || chain.length === 0) return { ok: false, reason: 'this vault has no attestation key' };
  if (chain.length > maxLength) return { ok: false, reason: 'attestation chain is too long' };
  let previous = null;
  for (const [index, link] of chain.entries()) {
    const record = link?.record;
    if (!record || link.algorithm !== 'ML-DSA-65') return { ok: false, reason: `link ${index} is not an ML-DSA-65 registration` };
    if (record.v !== VERSION || record.context !== REGISTRATION_CONTEXT) return { ok: false, reason: `link ${index} is not a key registration` };
    if (vaultId && record.vaultId !== vaultId) return { ok: false, reason: `link ${index} registers a key for another vault` };
    if (record.epoch !== index + 1) return { ok: false, reason: `link ${index} claims epoch ${record.epoch}` };

    let publicKey;
    try {
      publicKey = base64.decode(record.publicKey);
    } catch {
      return { ok: false, reason: `link ${index} has no readable public key` };
    }
    if (publicKey.length !== 1952) return { ok: false, reason: `link ${index} is not an ML-DSA-65 public key` };

    // Epoch 1 vouches for itself; every later epoch is vouched for by the one before it.
    const signer = previous ? previous.publicKey : publicKey;
    const expectedPrevious = previous ? keyIdOf(previous.publicKey) : null;
    if ((record.previousKeyId ?? null) !== expectedPrevious) {
      return { ok: false, reason: `link ${index} names the wrong previous key` };
    }
    if (link.signedBy && link.signedBy !== keyIdOf(signer)) {
      return { ok: false, reason: `link ${index} was signed by a key that could not authorise it` };
    }
    let verified = false;
    try {
      verified = ml_dsa65.verify(base64.decode(link.signature), utf8(canonicalJson(record)), signer, { context: registrationContext });
    } catch {
      verified = false;
    }
    if (!verified) return { ok: false, reason: `link ${index} was not signed by the key that could authorise it` };
    previous = { publicKey, epoch: record.epoch, keyId: keyIdOf(publicKey), registeredAt: record.registeredAt };
  }
  return {
    ok: true,
    publicKey: base64.encode(previous.publicKey),
    keyId: previous.keyId,
    epoch: previous.epoch,
    rootKeyId: keyIdOf(base64.decode(chain[0].record.publicKey)),
    length: chain.length,
  };
}

/**
 * Builds and signs a V1 record. `biometricVerified` is all it says about the palm itself.
 *
 * That field is written unconditionally, and it is a statement about the Veyns palm decisions
 * this operation collected — not about any scanner this code spoke to, because there is no
 * scanner. V2 below replaces it with fields that can only be filled in by measurement. V1 is
 * left exactly as it was: records already signed under it have to keep verifying.
 */
export function signAuthorization(parts, keys) {
  const record = {
    v: VERSION,
    vaultId: parts.vaultId,
    accountId: parts.accountId,
    transactionHash: parts.transactionHash,
    statementDigest: parts.statementDigest,
    approvalMethod: parts.approvalMethod,
    biometricVerified: true,
    approvals: parts.approvals,
    approvedBy: [...parts.approvedBy].sort(),
    decisionIds: [...parts.decisionIds].sort(),
    approvedAt: parts.approvedAt,
    keyEpoch: keys.epoch ?? 1,
  };
  return {
    record,
    algorithm: 'ML-DSA-65',
    context: CONTEXT,
    keyId: keys.keyId ?? keyIdOf(keys.publicKey),
    signature: base64.encode(ml_dsa65.sign(signedBytes(record), keys.secretKey, { context })),
  };
}

/**
 * Checks a record against a public key and, when given, that it is the record for that exact
 * transaction, vault, statement and epoch. Never throws: it answers, with the reason when the
 * answer is no.
 */
export function verifyAuthorization(authorization, publicKeyBase64, expected = {}) {
  try {
    if (!authorization?.record || authorization.algorithm !== 'ML-DSA-65') {
      return { ok: false, reason: 'not an ML-DSA-65 authorisation' };
    }
    if (authorization.context !== CONTEXT) return { ok: false, reason: 'signed for a different purpose' };
    if (!KNOWN_VERSIONS.has(authorization.record.v)) return { ok: false, reason: 'unknown record version' };
    // A caller that has moved to V2 can refuse V1 without this function's default changing:
    // every existing caller asks for no minimum and keeps exactly the behaviour it had.
    if (expected.minVersion !== undefined && authorization.record.v < expected.minVersion) {
      return { ok: false, reason: `this vault requires a version ${expected.minVersion} authorisation` };
    }
    if (!publicKeyBase64) return { ok: false, reason: 'this vault has no registered attestation key' };
    const publicKey = base64.decode(publicKeyBase64);
    if (authorization.keyId && authorization.keyId !== keyIdOf(publicKey)) {
      return { ok: false, reason: 'signed by a key this vault has not registered' };
    }
    if (!ml_dsa65.verify(base64.decode(authorization.signature), signedBytes(authorization.record), publicKey, { context })) {
      return { ok: false, reason: 'signature does not verify' };
    }
    const record = authorization.record;
    // A V2 record has to carry measurements, not assertions. Checked after the signature, so
    // a malformed record is never distinguishable from a forged one by timing alone.
    if (record.v === VERSION_2) {
      const wrong = checkV2(record);
      if (wrong) return { ok: false, reason: wrong };
    }
    if (expected.transactionHash && record.transactionHash !== expected.transactionHash) {
      return { ok: false, reason: 'authorisation is for a different transaction' };
    }
    if (expected.vaultId && record.vaultId !== expected.vaultId) {
      return { ok: false, reason: 'authorisation is for a different vault' };
    }
    if (expected.statementDigest && record.statementDigest !== expected.statementDigest) {
      return { ok: false, reason: 'authorisation is for a different statement' };
    }
    /*
     * The rest of what a record can be moved between.
     *
     * A field is checked when the caller names it AND the record carries it. A version 1
     * record carries none of these, so a caller may pass them freely and V1 keeps exactly the
     * behaviour it always had — which is also, precisely, V1's weakness: it cannot answer
     * these questions, so it cannot be held to them. A caller that needs the answers sets
     * `minVersion: 2`, and `whatItProves` reports which questions a given record can answer.
     *
     * For a version 2 record every one of these is present — `checkV2` has already refused a
     * record missing any of them — so naming one here is always a real check.
     */
    for (const [field, reason] of [
      ['accountId', 'authorisation is for a different account'],
      ['chain', 'authorisation is for a different chain'],
      ['network', 'authorisation is for a different network'],
      ['policyVersion', 'authorisation was made under different spending rules'],
      ['subject', 'authorisation is for a different person'],
      ['nonce', 'authorisation carries a different nonce'],
      ['proposalId', 'authorisation is for a different proposal'],
      ['threshold', 'authorisation claims a different approval threshold'],
    ]) {
      if (expected[field] === undefined || record[field] === undefined) continue;
      if (record[field] !== expected[field]) return { ok: false, reason };
    }
    if (expected.keyEpoch !== undefined && (record.keyEpoch ?? 1) !== expected.keyEpoch) {
      return { ok: false, reason: 'authorisation was made with a retired key' };
    }
    if (expected.approvedBy && !sameSet(record.approvedBy, expected.approvedBy)) {
      return { ok: false, reason: 'authorisation names different approvers' };
    }
    if (expected.decisionIds && !sameSet(record.decisionIds, expected.decisionIds)) {
      return { ok: false, reason: 'authorisation names different palm decisions' };
    }
    if (expected.notBefore !== undefined && !(record.approvedAt >= expected.notBefore)) {
      return { ok: false, reason: 'authorisation predates these approvals' };
    }
    if (expected.notAfter !== undefined && !(record.approvedAt <= expected.notAfter)) {
      return { ok: false, reason: 'authorisation is dated in the future' };
    }
    // `proves` travels with the verdict so no caller has to infer strength from a version
    // number. A verified V1 record is not a stronger record for having been verified.
    return { ok: true, record, proves: whatItProves(record) };
  } catch {
    return { ok: false, reason: 'malformed authorisation' };
  }
}

const sameSet = (a, b) => Array.isArray(a) && a.length === b.length && [...a].sort().join('\u0000') === [...b].sort().join('\u0000');

export const AUTHORIZATION_CONTEXT = CONTEXT;

/* ------------------------------------------------- evidence checkpoints */

/*
 * A signed commitment to the evidence log, made by a key the server has never held.
 *
 * The problem this solves: a hash chain detects a partial edit, but an operator who can write
 * the whole database can rewrite every entry and recompute the chain from the genesis. Nothing
 * inside the database stops that.
 *
 * A checkpoint is signed in the owner's browser with the same ML-DSA-65 attestation key that
 * signs authorisation receipts — derived from the recovery phrase, and never sent anywhere. So
 * an operator who rewrites the log cannot produce a checkpoint that matches the new head: they
 * would have to forge a post-quantum signature under a key they do not have. Rewriting history
 * becomes detectable by anyone holding an older checkpoint, including the server itself.
 *
 * NO CIRCULARITY. A checkpoint commits to an evidence head that already exists. It is not
 * itself an evidence entry, and no evidence entry commits to a checkpoint — so there is no
 * cycle between the two structures. Signing a checkpoint does append an entry recording that
 * it happened, and that entry is covered by the NEXT checkpoint, never by the one being made.
 *
 * It says nothing about a palm. A checkpoint is a statement about a log, and keeping it
 * separate from the authorisation receipt is what stops anyone reading it as biometric
 * evidence.
 */
const CHECKPOINT_CONTEXT = 'QUVAULT-EVIDENCE-CHECKPOINT-V1';
const checkpointContext = utf8(CHECKPOINT_CONTEXT);
const CHECKPOINT_VERSION = 1;

export function signCheckpoint({ vaultId, head, count, at, nonce }, keys) {
  if (!vaultId || !head || !nonce) throw new Error('A checkpoint must name a vault, a head and a nonce.');
  if (!Number.isInteger(count) || count < 0) throw new Error('A checkpoint must count the entries it covers.');
  const record = { v: CHECKPOINT_VERSION, context: CHECKPOINT_CONTEXT, vaultId, head, count, at, nonce };
  return {
    record,
    algorithm: 'ML-DSA-65',
    context: CHECKPOINT_CONTEXT,
    keyId: keys.keyId ?? keyIdOf(keys.publicKey),
    signature: base64.encode(ml_dsa65.sign(utf8(canonicalJson(record)), keys.secretKey, { context: checkpointContext })),
  };
}

/**
 * Checks a checkpoint against a public key and, when given, the head it should be about.
 *
 * Never throws. `expected.head` is how a verifier asks the question that matters: does this
 * checkpoint describe the log I am holding, or a different one?
 */
export function verifyCheckpoint(checkpoint, publicKeyBase64, expected = {}) {
  try {
    const record = checkpoint?.record;
    if (!record || checkpoint.algorithm !== 'ML-DSA-65') return { ok: false, reason: 'not an ML-DSA-65 checkpoint' };
    if (checkpoint.context !== CHECKPOINT_CONTEXT) return { ok: false, reason: 'signed for a different purpose' };
    if (record.v !== CHECKPOINT_VERSION || record.context !== CHECKPOINT_CONTEXT) {
      return { ok: false, reason: 'not a checkpoint record' };
    }
    if (!publicKeyBase64) return { ok: false, reason: 'this vault has no registered attestation key' };
    const publicKey = base64.decode(publicKeyBase64);
    if (checkpoint.keyId && checkpoint.keyId !== keyIdOf(publicKey)) {
      return { ok: false, reason: 'signed by a key this vault has not registered' };
    }
    if (!ml_dsa65.verify(base64.decode(checkpoint.signature), utf8(canonicalJson(record)), publicKey, { context: checkpointContext })) {
      return { ok: false, reason: 'signature does not verify' };
    }
    if (expected.vaultId && record.vaultId !== expected.vaultId) return { ok: false, reason: 'checkpoint is for a different vault' };
    if (expected.head && record.head !== expected.head) {
      return { ok: false, reason: 'the log does not match this checkpoint: it has been rewritten, or this is a different log' };
    }
    if (expected.count !== undefined && record.count !== expected.count) {
      return { ok: false, reason: 'the log does not have the number of entries this checkpoint covers' };
    }
    return { ok: true, record };
  } catch {
    return { ok: false, reason: 'malformed checkpoint' };
  }
}

export const CHECKPOINT = Object.freeze({ CONTEXT: CHECKPOINT_CONTEXT, VERSION: CHECKPOINT_VERSION });
