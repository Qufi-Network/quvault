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
import { bitcoinWordsProblem, evmWordsProblem, evmTokenWordsProblem } from './approval-words.js';
import {
  NATIVE, normalTransfer, normalRefresh, evmTransferDigest, evmRefreshDigest, eip712TransferDigest, eip712RefreshDigest,
  addressOfKey, signDigest,
} from './palm-wallet.js';

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
    // And the words the palm approved describe this transaction: its payees, amounts and fee.
    const words = bitcoinWordsProblem({ statement: action.statement, details: action.details, plan, vaultAddress: vault.address });
    if (words) refuse(words);
    const expected = actionDigest(action.statement, action.details);

    // 2. The palms: enough different signers, each bound to exactly this action.
    const { approvedBy, requestIds } = checkPalms({
      decisions, expected, subjects: policy?.signerSubs, transactionKey: digest, required: vault.required,
    });

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

  /**
   * Enough palm approvals from different people who sign for this vault, each a Veyns decision
   * verified here with a pinned key, each approving exactly `expected`, each counted towards
   * `transactionKey` only. Returns who approved and the request ids, or refuses.
   */
  function checkPalms({ decisions, expected, subjects: subjectList, transactionKey, required }) {
    // Each entry is one person: a subject, or a list of the forms Veyns may name them by. Two
    // forms of one person are still one person, so they can never count as two signers.
    const personOf = new Map();
    for (const entry of subjectList ?? []) {
      const aliases = (Array.isArray(entry) ? entry : [entry]).map(String);
      for (const alias of aliases) personOf.set(alias, aliases[0]);
    }
    const digest = transactionKey;
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
                    : !personOf.has(String(claims.sub)) ? 'a decision is from someone who does not sign for this vault'
                      : counted.has(claims.request_id) && counted.get(claims.request_id) !== digest
                        ? 'a decision has already been counted towards a different transaction'
                        : null;
      if (why) {
        reasons.push(why);
        continue;
      }
      approvedBy.add(personOf.get(String(claims.sub)));
      requestIds.push(claims.request_id);
    }
    if (approvedBy.size < required) {
      const detail = reasons.length ? ` (${[...new Set(reasons)].join('; ')})` : '';
      refuse(`needs ${required} palm approval${required === 1 ? '' : 's'} from different signers and has ${approvedBy.size}${detail}`);
    }
    return { approvedBy, requestIds };
  }

  /* ------------------------------------------------------- Ethereum and BSC */

  // A Palm Wallet's palm key: its own derivation, so no Bitcoin vault and no wallet share a key.
  const evmKeyFor = vaultId => privateKeyFor(`evm:${vaultId}`);

  /** The address a Palm Wallet names as its palm signer. */
  const palmAddressFor = vaultId => {
    const key = evmKeyFor(String(vaultId));
    try {
      return addressOfKey(key);
    } finally {
      key.fill(0);
    }
  };

  /**
   * Signs the palm key's part of a Palm Wallet payment, or throws PalmRefused saying why not.
   *
   * The approval's transaction hash must be this exact payment, and every line a person read on
   * their phone must be this payment's: the payee, the amount, the asset, Palm's fee and where it
   * goes, the network fee, the wallet and the chain. A server that showed one thing and asked for
   * another is refused here, however the hash was arranged.
   */
  function signEvmTransfer({ vaultId, wallet, transfer, action, decisions }) {
    let t;
    let digest;
    try {
      t = normalTransfer(transfer);
      digest = evmTransferDigest({ chainId: wallet?.chainId, wallet: wallet?.address, transfer: t });
    } catch (error) {
      refuse(String(error.message).replace(/\.$/, '').toLowerCase());
    }
    const details = action?.details ?? {};
    if (details.transaction_hash !== digest) refuse('the approved action names a different transfer');
    const approvedToken = details.token === undefined || details.token === 'native' ? NATIVE : lower(details.token);
    if (lower(details.to) !== t.to) refuse('the approved payee is not this transfer\'s');
    if (String(details.amount_units ?? '') !== t.amount) refuse('the approved amount is not this transfer\'s');
    if (approvedToken !== t.token) refuse('the approved asset is not this transfer\'s');
    if (String(details.palm_fee_units ?? '0') !== t.fee) refuse('the approved Palm fee is not this transfer\'s');
    if (t.fee !== '0' && lower(details.palm_fee_to) !== t.feeTo) refuse('the approved Palm fee goes somewhere else');
    if (String(details.network_fee_units ?? '0') !== t.gasRefund) refuse('the approved network fee is not this transfer\'s');
    if (t.gasRefund !== '0' && lower(details.network_fee_to) !== t.refundTo) refuse('the approved network fee goes somewhere else');
    if (lower(details.wallet) !== lower(wallet.address)) refuse('the approval is for a different wallet');
    if (String(details.chain_id ?? '') !== String(wallet.chainId)) refuse('the approval is for a different chain');
    // The sentence itself names the payee, the amount and the fees together.
    const words = t.token === NATIVE
      ? evmWordsProblem({ statement: action.statement, to: t.to, amount: t.amount, fees: (BigInt(t.fee) + BigInt(t.gasRefund)).toString() })
      : evmTokenWordsProblem({ statement: action.statement, to: t.to, token: t.token, amount: t.amount, fee: t.fee, gasRefund: t.gasRefund });
    if (words) refuse(words);

    const required = Number(wallet.threshold);
    if (!Number.isInteger(required) || required < 1) refuse('the wallet names no threshold');
    const { approvedBy, requestIds } = checkPalms({
      decisions, expected: actionDigest(action.statement, details), subjects: wallet.signerSubs, transactionKey: digest, required,
    });

    const key = evmKeyFor(String(vaultId));
    try {
      const signature = signDigest(eip712TransferDigest({ chainId: wallet.chainId, wallet: wallet.address, transfer: t }), key);
      for (const id of requestIds) counted.set(id, digest);
      return { signature, palmAddress: addressOfKey(key), approvedBy: [...approvedBy].sort(), transactionHash: digest };
    } finally {
      key.fill(0);
    }
  }

  /**
   * Signs the palm key's part of a refresh: the signers and the palm saying they are still here,
   * which closes the recovery path again. It needs the same palms as a payment, so neither the
   * palm key alone nor the signers alone can keep the recovery path shut.
   */
  function signEvmRefresh({ vaultId, wallet, refresh, action, decisions }) {
    let r;
    let digest;
    try {
      r = normalRefresh(refresh);
      digest = evmRefreshDigest({ chainId: wallet?.chainId, wallet: wallet?.address, refresh: r });
    } catch (error) {
      refuse(String(error.message).replace(/\.$/, '').toLowerCase());
    }
    const details = action?.details ?? {};
    if (details.transaction_hash !== digest) refuse('the approved action names a different refresh');
    if (String(details.network_fee_units ?? '0') !== r.gasRefund) refuse('the approved network fee is not this refresh\'s');
    if (r.gasRefund !== '0' && lower(details.network_fee_to) !== r.refundTo) refuse('the approved network fee goes somewhere else');
    if (lower(details.wallet) !== lower(wallet.address)) refuse('the approval is for a different wallet');
    if (String(details.chain_id ?? '') !== String(wallet.chainId)) refuse('the approval is for a different chain');
    const refreshWords = evmWordsProblem({ statement: action.statement, fees: r.gasRefund });
    if (refreshWords) refuse(refreshWords);
    const required = Number(wallet.threshold);
    if (!Number.isInteger(required) || required < 1) refuse('the wallet names no threshold');
    const { approvedBy, requestIds } = checkPalms({
      decisions, expected: actionDigest(action.statement, details), subjects: wallet.signerSubs, transactionKey: digest, required,
    });
    const key = evmKeyFor(String(vaultId));
    try {
      const signature = signDigest(eip712RefreshDigest({ chainId: wallet.chainId, wallet: wallet.address, refresh: r }), key);
      for (const id of requestIds) counted.set(id, digest);
      return { signature, palmAddress: addressOfKey(key), approvedBy: [...approvedBy].sort(), transactionHash: digest };
    } finally {
      key.fill(0);
    }
  }
  const lower = value => String(value ?? '').toLowerCase();

  return { publicKeyFor, sign, palmAddressFor, signEvmTransfer, signEvmRefresh };
}
