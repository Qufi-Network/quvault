/*
 * The browser's own check of a palm approval, before it signs anything.
 *
 * Everything a signer's browser is handed comes from this server, and so from its database: the
 * transaction, its hash, the approval record. Someone able to write to that database could put a
 * different transaction there after a person approved, and the browser would sign it. So before
 * signing, the browser checks Veyns' own signed decision itself, with Veyns' own published keys:
 * that it is genuine, that it is this person's palm, and that the action it approved, word for
 * word, names exactly the transaction about to be signed. A database can be rewritten; a Veyns
 * signature cannot be made without Veyns.
 *
 * No node:crypto here, so the same code runs in the browser bundle and in the tests.
 */
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';
import { canonicalJson } from './canonical.js';

const utf8 = text => new TextEncoder().encode(text);
const fromB64 = text => base64urlnopad.decode(String(text).replace(/=+$/, ''));
const json = part => JSON.parse(new TextDecoder().decode(fromB64(part)));

/** The digest Veyns signs for an action: base64url SHA-256 of the canonical {statement, details}. */
export const actionDigestOf = (statement, details) =>
  base64urlnopad.encode(sha256(utf8(canonicalJson({ statement, details: details ?? null }))));

/**
 * Why `token` is not a genuine Veyns palm decision for `expected`, made by one of `subjects`; or
 * null when it is. `keys` are Veyns' published JWKs.
 */
export function decisionProblem(token, { issuer, audience, keys, subjects = null, expected, now = Math.floor(Date.now() / 1000), maxAge = 6 * 3600 }) {
  const parts = String(token ?? '').split('.');
  if (parts.length !== 3) return 'it is not a signed decision';
  let header;
  let claims;
  try {
    header = json(parts[0]);
    claims = json(parts[1]);
  } catch {
    return 'it cannot be read';
  }
  if (header.alg !== 'ES256') return 'it is not signed the way Veyns signs';
  const jwk = (keys ?? []).find(k => k.kid === header.kid && k.kty === 'EC' && k.crv === 'P-256');
  if (!jwk) return 'it is signed by a key Veyns does not publish';
  let valid = false;
  try {
    const publicKey = new Uint8Array([4, ...fromB64(jwk.x), ...fromB64(jwk.y)]);
    const signature = fromB64(parts[2]);
    valid = signature.length === 64 && p256.verify(signature, sha256(utf8(`${parts[0]}.${parts[1]}`)), publicKey, { lowS: false });
  } catch {
    valid = false;
  }
  if (!valid) return 'its signature does not verify';
  if (claims.iss !== issuer) return 'it is from a different issuer';
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(audience)) return 'it is for a different application';
  if (claims.veyns_intent !== 'action') return 'it is not an approval';
  if (!(Array.isArray(claims.amr) && claims.amr.includes('veyns:palm'))) return 'it was not made with a palm';
  if (claims.veyns_action?.digest !== expected) return 'it approves a different action';
  if (typeof claims.auth_time !== 'number' || claims.auth_time < now - maxAge || claims.auth_time > now + 300) return 'the palm scan is too old';
  if (subjects && !subjects.includes(String(claims.sub))) return 'it was made by someone else';
  return null;
}

/**
 * Throws unless this request carries this person's own Veyns palm decision for exactly the
 * action shown, and that action names exactly the transaction about to be signed.
 */
export function checkPalmProof({ palmProof, transactionHash }, trust, { transaction = true } = {}) {
  if (!palmProof?.decisions?.length) throw new Error('No palm approval came with this request, so nothing has been signed.');
  // Without knowing who this person is, anyone's palm would do: so it is required, not optional.
  if (!trust?.subjects?.length) {
    throw new Error('This device does not yet know which palm is yours. Sign out of Palm and sign in again here, then try again.');
  }
  if (transaction && (!transactionHash || palmProof.details?.transaction_hash !== transactionHash)) {
    throw new Error('The approval names a different transaction from the one handed to this device. Nothing has been signed.');
  }
  const expected = actionDigestOf(palmProof.statement, palmProof.details);
  const problems = palmProof.decisions.map(token => decisionProblem(token, { ...trust, expected }));
  if (!problems.includes(null)) {
    throw new Error(`Veyns did not approve this exact request with your palm (${[...new Set(problems)].join('; ')}). Nothing has been signed.`);
  }
}
