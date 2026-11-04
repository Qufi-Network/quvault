/*
 * Proof that whoever registers a signing key holds it.
 *
 * Without this, anyone on a vault's roster could register someone else's public key as their own
 * (public keys are on the roster and on the chain), and the app would then count their palm as
 * that person's. The proof is a signature by the key itself over the vault, the person and the
 * key, so it cannot be made without the private key and cannot be carried to another vault or
 * person. Shared by the browser, which makes it, and the server, which checks it.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '@scure/base';

const utf8 = text => new TextEncoder().encode(text);
const word = value => hex.decode(BigInt(value).toString(16).padStart(64, '0'));

export const keyProofHash = ({ vaultOwnerId, memberId, publicKey }) => sha256(utf8(
  `Palm signing key v1\nvault ${vaultOwnerId}\nsigner ${memberId}\nkey ${String(publicKey).toLowerCase()}`,
));

/** A 64-byte r || s signature, hex, by `privateKey` over the binding. */
export function signKeyProof(privateKey, binding) {
  const signature = secp256k1.sign(keyProofHash(binding), privateKey, { lowS: true });
  const out = new Uint8Array(64);
  out.set(word(signature.r), 0);
  out.set(word(signature.s), 32);
  return hex.encode(out);
}

/** True only for a proof made by the private half of `binding.publicKey` over this binding. */
export function verifyKeyProof(proof, binding) {
  try {
    const signature = hex.decode(String(proof).toLowerCase());
    if (signature.length !== 64) return false;
    return secp256k1.verify(signature, keyProofHash(binding), hex.decode(String(binding.publicKey).toLowerCase()), { lowS: true });
  } catch {
    return false;
  }
}
