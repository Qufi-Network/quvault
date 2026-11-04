/*
 * The palm signer: the only holder of a vault's palm key, and so the reason Bitcoin needs a palm.
 *
 * It trusts nothing it is told about what is being spent. Before it signs it reads the plan out
 * of the transaction itself, recomputes the digest the palms were asked to approve, and checks
 * every palm decision with Veyns' key pinned here, not fetched at signing time. A server that
 * lies about the transaction, the action or the signers gets a refusal, not a signature.
 *
 * PHASE 1: this runs as an ordinary process and holds its seed in memory. That proves the
 * mechanism on chain, but a compromise of the machine it runs on still yields the seed.
 * Phase 2 moves exactly this code into an attested enclave, where the seed is sealed to the
 * code's measurement and the vault policy (signers, threshold, delay, palm identities) is
 * recorded inside the enclave when a vault is made, not taken from the server at signing time.
 *
 * Expiry: Veyns decision tokens last five minutes, and a quorum's palms arrive over minutes or
 * hours, so a strict `exp` would refuse every slow quorum. What `exp` guards against — a token
 * replayed later — is covered here instead: a decision is bound to one transaction digest and
 * counts towards no other, and the palm scan itself (`auth_time`) must be recent.
 */
import crypto from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import { canonicalTransaction } from './canonical.js';
import { transactionDigest, actionDigest } from './veyns.js';
import { palmVaultOf, planOfPalmPsbt, palmPathOf, signPalmPsbt } from './palm-vault.js';
import { NETWORK } from './bitcoin.js';

export class PalmRefused extends Error {}

const refuse = reason => {
  throw new PalmRefused(reason);
};

export function createPalmSigner({
  seed,
  issuer,
  audience,
  pinnedKeys,
  networkName = 'testnet4',
  network = NETWORK,
  maxAgeSeconds = 7200,
  leeway = 30,
  now = () => Math.floor(Date.now() / 1000),
}) {
  if (!seed || seed.length < 32) throw new Error('The palm signer needs a seed of at least 32 bytes.');
  if (!issuer || !audience) throw new Error('The palm signer needs the issuer and audience it accepts decisions from.');
  const keys = new Map((pinnedKeys ?? [])
    .filter(jwk => jwk?.kty === 'EC' && jwk.crv === 'P-256' && jwk.kid)
    .map(jwk => [jwk.kid, crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' })]));
  if (!keys.size) throw new Error('The palm signer needs at least one pinned Veyns ES256 key.');

  // request_id -> the one transaction digest it has been counted towards.
  const counted = new Map();

  /** A palm key per vault, derived from the seed, so each vault's key is its own. */
  const privateKeyFor = vaultId => {
    for (let counter = 0; ; counter++) {
      const key = crypto.createHmac('sha256', seed).update(`quvault/palm-key/v1/${vaultId}/${counter}`).digest();
      try {
        schnorr.getPublicKey(key);
        return key;
      } catch {
        key.fill(0); // 1 in ~2^128: not a valid scalar, take the next one
      }
    }
  };

  const publicKeyFor = vaultId => {
    const key = privateKeyFor(String(vaultId));
    try {
      return hex.encode(schnorr.getPublicKey(key));
    } finally {
      key.fill(0);
    }
  };

  function verifyDecision(token) {
    const parts = String(token ?? '').split('.');
    if (parts.length !== 3) refuse('a decision is not a signed token');
    const [h, p, s] = parts;
    let header;
    let claims;
    try {
      header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
      claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    } catch {
      refuse('a decision is unreadable');
    }
    if (header.alg !== 'ES256') refuse('a decision is not signed with the pinned algorithm');
    const key = keys.get(header.kid);
    if (!key) refuse('a decision is signed by a key this signer does not trust');
    const ok = crypto.verify('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'));
    if (!ok) refuse('a decision signature does not verify');
    if (claims.iss !== issuer) refuse('a decision comes from a different issuer');
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(audience)) refuse('a decision was issued to a different application');
    return claims;
  }

  /**
   * Signs the palm key's part of a spend, or throws PalmRefused saying why not.
   *
   * `policy` = { signerKeys, required, delay, signerSubs }: the vault as it was made, and the
   * Veyns subjects of the people who sign for it. `action` = { statement, details } as the palms
   * approved it. `decisions` = the raw signed Veyns decision tokens.
   */
  function sign({ vaultId, policy, psbt, action, decisions }) {
    const palmKey = publicKeyFor(vaultId);
    const vault = palmVaultOf({
      palmKey, signerKeys: policy?.signerKeys, required: policy?.required, delay: policy?.delay, network,
    });

    // 1. The transaction, read from the transaction itself.
    if (palmPathOf(vault, psbt) !== 'normal') refuse('the palm key signs only the normal spending path of this vault');
    let plan;
    try {
      plan = planOfPalmPsbt(vault, psbt);
    } catch (error) {
      refuse(error.message.replace(/\.$/, '').toLowerCase());
    }
    const digest = transactionDigest(canonicalTransaction({ chain: 'bitcoin', network: networkName, from: vault.address, plan }));
    if (action?.details?.transaction_hash !== digest) refuse('the approved action names a different transaction');
    const expected = actionDigest(action.statement, action.details);

    // 2. The palms: enough different signers, each bound to exactly this action.
    const subjects = new Set((policy?.signerSubs ?? []).map(String));
    const approvedBy = new Set();
    const requestIds = [];
    const reasons = [];
    const time = now();
    for (const token of decisions ?? []) {
      let claims;
      try {
        claims = verifyDecision(token);
      } catch (error) {
        if (!(error instanceof PalmRefused)) throw error;
        reasons.push(error.message);
        continue;
      }
      const why = claims.veyns_intent !== 'action' ? 'a decision is not an action approval'
        : claims.veyns_presence !== true ? 'a decision does not record a person present'
          : !(Array.isArray(claims.amr) && claims.amr.includes('veyns:palm')) ? 'a decision was not made with a palm'
            : claims.veyns_action?.digest !== expected ? 'a decision approves a different action'
              : typeof claims.request_id !== 'string' || !claims.request_id ? 'a decision names no request'
                : typeof claims.request_nonce !== 'string' || !claims.request_nonce ? 'a decision carries no request nonce'
                  : typeof claims.auth_time !== 'number' || claims.auth_time > time + leeway || claims.auth_time < time - maxAgeSeconds
                    ? 'a palm scan is too old, or dated in the future'
                    : !subjects.has(String(claims.sub)) ? 'a decision is from someone who does not sign for this vault'
                      : counted.has(claims.request_id) && counted.get(claims.request_id) !== digest
                        ? 'a decision has already been counted towards a different transaction'
                        : null;
      if (why) {
        reasons.push(why);
        continue;
      }
      approvedBy.add(String(claims.sub));
      requestIds.push(claims.request_id);
    }
    if (approvedBy.size < vault.required) {
      const detail = reasons.length ? ` (${[...new Set(reasons)].join('; ')})` : '';
      refuse(`needs ${vault.required} palm approval${vault.required === 1 ? '' : 's'} from different signers and has ${approvedBy.size}${detail}`);
    }

    // 3. Sign. Only now is the key made, and it is wiped as soon as it has been used.
    const key = privateKeyFor(String(vaultId));
    try {
      const signed = signPalmPsbt(psbt, key);
      for (const id of requestIds) counted.set(id, digest);
      return { psbt: signed, approvedBy: [...approvedBy].sort(), transactionHash: digest, palmKey };
    } finally {
      key.fill(0);
    }
  }

  return { publicKeyFor, sign };
}
