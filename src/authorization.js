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

/* --------------------------------------------------------- version 2, dormant */

/*
 * V2 says what a scanner measured, instead of asserting that a palm was verified.
 *
 * Nothing produces a V2 record today, and nothing can: `signAuthorizationV2` refuses unless a
 * provider supplies evidence that passed, and the only provider in this repository is the
 * null one, which cannot return a pass. That is what "dormant" means here — the shape is
 * fixed and tested, the door is shut, and it opens when there is hardware behind it.
 *
 * The rule that makes the evidence worth carrying is `bindingNonce`: the scanner attests to
 * the transaction digest being authorised, so an attestation captured for one spend cannot be
 * replayed onto another. A PAD pass on its own authorises nothing, a match on its own
 * authorises nothing, and neither of them is a substitute for the signature that the owner's
 * key — derived from the phrase, not from the palm — puts on the record.
 */
export class AuthorizationUnavailable extends Error {}

/** The policy version the evidence was judged against, so a later reading knows the rules. */
const BIOMETRIC_POLICY_VERSION = 'quvault-biometric-policy-1';

/** Everything a V2 record must name about the thing being authorised, beyond the evidence. */
const V2_REQUIRED_PARTS = ['vaultId', 'accountId', 'subject', 'transactionHash', 'statementDigest', 'chain', 'network', 'policyVersion', 'nonce'];

export function signAuthorizationV2(parts, keys, evidence) {
  const absent = V2_REQUIRED_PARTS.filter(name => !parts?.[name]);
  if (absent.length) {
    throw new AuthorizationUnavailable(`A version 2 authorisation must name: ${absent.join(', ')}.`);
  }
  const usable = evidenceIsUsable(evidence);
  if (!usable.ok) {
    throw new AuthorizationUnavailable(
      `A version 2 authorisation needs scanner evidence, and there is none: ${usable.reasons.join('; ')}.`);
  }
  // The evidence has to be about this transaction. Without this, a captured attestation is a
  // reusable token rather than a statement about a spend.
  if (evidence.bindingNonce !== parts.transactionHash) {
    throw new AuthorizationUnavailable('The scanner evidence is bound to a different transaction.');
  }
  const record = {
    v: VERSION_2,
    // Which vault, which account, and whose. `subject` is the opaque per-application identity
    // the vault belongs to — never a name, an email or anything from the palm.
    vaultId: parts.vaultId,
    accountId: parts.accountId,
    subject: parts.subject,
    // What was authorised, and on which chain. The digest already covers chain and network,
    // and they are named again so a record can be read without recomputing it.
    transactionHash: parts.transactionHash,
    statementDigest: parts.statementDigest,
    chain: parts.chain,
    network: parts.network,
    // Which rules were in force. Without this a record survives the rules it was made under.
    policyVersion: parts.policyVersion,
    approvalMethod: parts.approvalMethod,
    // One authorisation, once. Distinct from bindingNonce, which is the scanner's tie to the
    // transaction: this one makes two authorisations of the same spend distinguishable.
    nonce: parts.nonce,
    // What was measured, by what, and about which capture — no scores, no templates, no images.
    biometricProvider: evidence.provider,
    biometricVerification: evidence.biometric.result,
    padResult: evidence.pad.result,
    captureReference: evidence.captureReference,
    scannerClass: evidence.scannerClass,
    scannerAttestation: evidence.attestation.signature,
    biometricPolicyVersion: BIOMETRIC_POLICY_VERSION,
    bindingNonce: evidence.bindingNonce,
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
 * The structural checks a V2 record must pass beyond its signature.
 *
 * A signature proves the owner's key wrote the record; it does not prove the record says
 * anything. These checks are what stop a V2 record that was signed with `padResult` set to a
 * placeholder from being read as a measurement.
 */
function checkV2(record) {
  for (const name of V2_REQUIRED_PARTS) {
    if (!record[name]) return `the record names no ${name}`;
  }
  if (record.padResult !== SCANNER.PASSED) return 'the record does not report a passed liveness check';
  if (record.biometricVerification !== SCANNER.PASSED) return 'the record does not report a passed match';
  if (typeof record.scannerAttestation !== 'string' || !record.scannerAttestation) return 'the record carries no scanner attestation';
  if (!record.scannerClass) return 'the record names no scanner class';
  if (!record.captureReference) return 'the record names no capture';
  if (record.bindingNonce !== record.transactionHash) return 'the scanner evidence is bound to a different transaction';
  if (!record.biometricPolicyVersion) return 'the record names no biometric policy version';
  // V1's unconditional assertion must not reappear inside a V2 record and be read as evidence.
  if ('biometricVerified' in record) return 'a version 2 record cannot assert biometricVerified';
  return null;
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
     * The rest of what a record can be moved between. Each is checked only when the caller
     * names it, so every existing V1 caller keeps exactly the behaviour it had; a caller that
     * does name one is asking a question a V1 record cannot answer, and will be told so.
     */
    for (const [field, reason] of [
      ['accountId', 'authorisation is for a different account'],
      ['chain', 'authorisation is for a different chain'],
      ['network', 'authorisation is for a different network'],
      ['policyVersion', 'authorisation was made under different spending rules'],
      ['subject', 'authorisation is for a different person'],
      ['nonce', 'authorisation carries a different nonce'],
    ]) {
      if (expected[field] !== undefined && record[field] !== expected[field]) return { ok: false, reason };
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
    return { ok: true, record };
  } catch {
    return { ok: false, reason: 'malformed authorisation' };
  }
}

const sameSet = (a, b) => Array.isArray(a) && a.length === b.length && [...a].sort().join('\u0000') === [...b].sort().join('\u0000');

export const AUTHORIZATION_CONTEXT = CONTEXT;
