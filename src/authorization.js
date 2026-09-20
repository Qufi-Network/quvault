/*
 * The human authorisation record, and its post-quantum signature.
 *
 * When a palm approval settles, QuVault writes down what it verified and signs that record
 * with ML-DSA-65 (FIPS 204). The record is small and deliberately dull: which vault, which
 * transaction digest, when, by what method, and the identifiers of the palm decisions that
 * settled it. No biometric data of any kind — not an image, not a template, not a score.
 *
 * What a valid signature proves: this QuVault instance verified a palm decision from the
 * identity provider whose action digest covered this exact transaction, before the
 * transaction was signed. What it does not prove: who that person is in law, that their
 * device was sound, or that a live hand was present rather than a decision replayed at the
 * provider. Saying more than this would be dishonest.
 *
 * This module holds no Node or browser APIs, so the page verifies a receipt with the same
 * code that signed it rather than with a second implementation that might disagree.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { canonicalJson } from './canonical.js';

const VERSION = 1;
const CONTEXT = 'QUVAULT-HUMAN-AUTHORIZATION-V1'; // FIPS 204 context: nothing else signs under it
const utf8 = text => new TextEncoder().encode(text);
const context = utf8(CONTEXT);

/** The bytes signed are the canonical record; the purpose is carried by the context. */
const signedBytes = record => utf8(canonicalJson(record));

/**
 * The signing key for authorisation records, from the same 64-byte vault seed as the rest of
 * the vault, through HKDF with its own label. One secret to deploy, separate keys in use.
 */
export function attestationKeys(seedBase64) {
  let seed;
  try {
    seed = base64.decode(seedBase64 ?? '');
  } catch {
    seed = new Uint8Array(0);
  }
  if (seed.length !== 64) throw new Error('WALLET_SEED must be 64 random bytes, base64 encoded. Run: npm run keygen');
  const material = hkdf(sha256, seed, utf8('quvault ml-dsa'), utf8('quvault ml-dsa authorization v1'), 32);
  const { publicKey, secretKey } = ml_dsa65.keygen(material);
  material.fill(0);
  return { publicKey, secretKey, keyId: keyIdOf(publicKey) };
}

/** A short, stable name for the signing key, so a receipt says which key to check it with. */
export const keyIdOf = publicKey => base64.encode(sha256(publicKey)).replace(/[+/=]/g, '').slice(0, 22);

/** Builds and signs the record. `biometricVerified` is all it says about the palm itself. */
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
 * transaction and vault. Never throws: it answers, with the reason when the answer is no.
 */
export function verifyAuthorization(authorization, publicKeyBase64, expected = {}) {
  try {
    if (!authorization?.record || authorization.algorithm !== 'ML-DSA-65') {
      return { ok: false, reason: 'not an ML-DSA-65 authorisation' };
    }
    if (authorization.context !== CONTEXT) return { ok: false, reason: 'signed for a different purpose' };
    if (authorization.record.v !== VERSION) return { ok: false, reason: 'unknown record version' };
    const publicKey = base64.decode(publicKeyBase64);
    if (authorization.keyId && authorization.keyId !== keyIdOf(publicKey)) {
      return { ok: false, reason: 'signed by a different key' };
    }
    if (!ml_dsa65.verify(base64.decode(authorization.signature), signedBytes(authorization.record), publicKey, { context })) {
      return { ok: false, reason: 'signature does not verify' };
    }
    if (expected.transactionHash && authorization.record.transactionHash !== expected.transactionHash) {
      return { ok: false, reason: 'authorisation is for a different transaction' };
    }
    if (expected.vaultId && authorization.record.vaultId !== expected.vaultId) {
      return { ok: false, reason: 'authorisation is for a different vault' };
    }
    return { ok: true, record: authorization.record };
  } catch {
    return { ok: false, reason: 'malformed authorisation' };
  }
}

export const AUTHORIZATION_CONTEXT = CONTEXT;
