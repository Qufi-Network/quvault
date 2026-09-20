/*
 * Post-quantum protection for the stored Bitcoin key.
 *
 * Each wallet key is sealed with a hybrid envelope: ML-KEM-768 (FIPS 203) and X25519 each
 * produce a shared secret, both are mixed through HKDF-SHA256, and the result is the
 * AES-256-GCM key. Opening a sealed key needs the server seed and a break of BOTH
 * ML-KEM-768 and X25519, so a quantum computer alone is not enough.
 *
 * What this does not do: Bitcoin itself signs with secp256k1, which a quantum computer
 * would break on-chain no matter how the key is stored. This protects the key at rest.
 */
import crypto from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';

const VERSION = 1;
const KEM_CIPHERTEXT = 1088;
const X25519_PUBLIC = 32;
const NONCE = 12;
const TAG = 16;
const INFO = Buffer.from('palmsafe wallet key v1');

/** Derives the server's long-term key pairs from one 64-byte seed. */
export function serverKeys(seedBase64) {
  const seed = Buffer.from(seedBase64 ?? '', 'base64');
  if (seed.length !== 64) throw new Error('WALLET_SEED must be 64 random bytes, base64 encoded. Run: npm run keygen');
  const kem = ml_kem768.keygen(seed);
  const x25519Secret = crypto.hkdfSync('sha256', seed, Buffer.from('palmsafe x25519'), INFO, 32);
  return {
    kemPublicKey: kem.publicKey,
    kemSecretKey: kem.secretKey,
    x25519Secret: new Uint8Array(x25519Secret),
    x25519Public: x25519.getPublicKey(new Uint8Array(x25519Secret)),
  };
}

/*
 * A vault's key lineage is anchored to this server's seed, which lives in the environment and
 * not in the database. Walking a registration chain proves internal consistency, but a chain
 * is self-rooted: anyone able to rewrite the row could store a chain rooted at their own key.
 * The root seal is what that rewrite cannot produce, because the seed is not there to be read.
 *
 * It is not a defence against someone who has the seed itself. That is stated plainly in
 * HUMAN-VERIFIED.md rather than implied away.
 */
export const sealRoot = (seedBase64, { vaultId, rootKeyId }) =>
  crypto.createHmac('sha256', Buffer.from(seedBase64 ?? '', 'base64'))
    .update(`quvault attestation root v1|${vaultId}|${rootKeyId}`, 'utf8')
    .digest('base64');

/** Constant-time comparison, so a wrong seal reveals nothing about the right one. */
export function rootSealMatches(seedBase64, parts, seal) {
  const expected = Buffer.from(sealRoot(seedBase64, parts), 'base64');
  let given;
  try {
    given = Buffer.from(String(seal ?? ''), 'base64');
  } catch {
    return false;
  }
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

const aesKey = (kemShared, x25519Shared) =>
  Buffer.from(crypto.hkdfSync('sha256', Buffer.concat([Buffer.from(kemShared), Buffer.from(x25519Shared)]),
    Buffer.alloc(0), INFO, 32));

/** Seals bytes for this server. Returns base64: version | ML-KEM ciphertext | X25519 public | nonce | ciphertext+tag. */
export function seal(plaintext, keys) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(keys.kemPublicKey);
  const ephemeral = x25519.utils.randomSecretKey();
  const classical = x25519.getSharedSecret(ephemeral, keys.x25519Public);
  const nonce = crypto.randomBytes(NONCE);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey(sharedSecret, classical), nonce);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return Buffer.concat([
    Buffer.from([VERSION]), Buffer.from(cipherText), Buffer.from(x25519.getPublicKey(ephemeral)), nonce, body,
  ]).toString('base64');
}

/** Opens a sealed key. Throws if the envelope was altered in any way. */
export function open(envelopeBase64, keys) {
  const envelope = Buffer.from(envelopeBase64, 'base64');
  if (envelope[0] !== VERSION) throw new Error('Unknown sealed key version.');
  let at = 1;
  const take = length => envelope.subarray(at, (at += length));
  const kemCiphertext = take(KEM_CIPHERTEXT);
  const ephemeralPublic = take(X25519_PUBLIC);
  const nonce = take(NONCE);
  const body = envelope.subarray(at);
  if (body.length <= TAG) throw new Error('Sealed key is truncated.');

  const kemShared = ml_kem768.decapsulate(new Uint8Array(kemCiphertext), keys.kemSecretKey);
  const classical = x25519.getSharedSecret(keys.x25519Secret, new Uint8Array(ephemeralPublic));
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey(kemShared, classical), nonce);
  decipher.setAuthTag(body.subarray(body.length - TAG));
  return Buffer.concat([decipher.update(body.subarray(0, body.length - TAG)), decipher.final()]);
}
