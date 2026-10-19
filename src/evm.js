/*
 * EIP-1559 transaction encoding for Ethereum and other EVM chains (BSC among them).
 *
 * This module is pure: RLP, the signing payload, the assembled signed transaction, and the
 * reverse — reconstructing a raw transaction back into its fields. No key material passes
 * through it. The browser signs (client/wallet.js) using `signingHash` and `assembleSigned`;
 * the server reconstructs a broadcast with `decodeSigned` and checks it reconciles to the
 * canonical transfer the palm approved, exactly as the Bitcoin path re-derives its plan.
 *
 * Only type-2 (EIP-1559) transactions are produced and accepted. Legacy and type-1 are not:
 * one transaction shape is one thing to get right and one thing to verify.
 *
 * It imports @noble's keccak the same way the other src modules import @noble primitives, so it
 * works unchanged in Node and in the browser bundle.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { canonicalTransfer, transferBytes } from './canonical-transfer.js';

export class EvmError extends Error {}

const TYPE = 0x02; // EIP-1559

/* ------------------------------------------------------------------------------- bytes */

const hexToBytes = h => {
  const body = h.startsWith('0x') ? h.slice(2) : h;
  if (body.length % 2) throw new EvmError('odd-length hex');
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const bytesToHex = b => `0x${[...b].map(x => x.toString(16).padStart(2, '0')).join('')}`;
const concat = arrays => {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) { out.set(a, o); o += a.length; }
  return out;
};

/** A non-negative integer (decimal string or bigint) as its minimal big-endian bytes. Zero is empty. */
const uintBytes = value => {
  let n = typeof value === 'bigint' ? value : BigInt(value);
  if (n < 0n) throw new EvmError('negative quantity');
  if (n === 0n) return new Uint8Array(0);
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  return Uint8Array.from(bytes);
};
const bytesToBig = b => (b.length ? BigInt(bytesToHex(b)) : 0n);

/* --------------------------------------------------------------------------------- RLP */

function rlpLength(len, offset) {
  if (len < 56) return Uint8Array.of(offset + len);
  const lenBytes = uintBytes(BigInt(len));
  return concat([Uint8Array.of(offset + 55 + lenBytes.length), lenBytes]);
}

/** RLP-encode a byte string or a (recursively) list of them. */
export function rlp(item) {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return concat([rlpLength(item.length, 0x80), item]);
  }
  if (Array.isArray(item)) {
    const body = concat(item.map(rlp));
    return concat([rlpLength(body.length, 0xc0), body]);
  }
  throw new EvmError('rlp: not bytes or a list');
}

/** Decode one RLP item at `pos`, returning { value, next } where value is bytes or an array. */
function rlpDecodeAt(data, pos) {
  const b = data[pos];
  if (b < 0x80) return { value: Uint8Array.of(b), next: pos + 1 };
  if (b < 0xb8) { const n = b - 0x80; return { value: data.slice(pos + 1, pos + 1 + n), next: pos + 1 + n }; }
  if (b < 0xc0) {
    const ll = b - 0xb7;
    const n = Number(bytesToBig(data.slice(pos + 1, pos + 1 + ll)));
    return { value: data.slice(pos + 1 + ll, pos + 1 + ll + n), next: pos + 1 + ll + n };
  }
  let payloadStart;
  let payloadEnd;
  if (b < 0xf8) { payloadStart = pos + 1; payloadEnd = payloadStart + (b - 0xc0); }
  else {
    const ll = b - 0xf7;
    const n = Number(bytesToBig(data.slice(pos + 1, pos + 1 + ll)));
    payloadStart = pos + 1 + ll; payloadEnd = payloadStart + n;
  }
  const items = [];
  let p = payloadStart;
  while (p < payloadEnd) { const d = rlpDecodeAt(data, p); items.push(d.value); p = d.next; }
  return { value: items, next: payloadEnd };
}

/* ------------------------------------------------------------------- the transaction */

/** The nine fields of an EIP-1559 transaction, in signing order, as RLP items. */
function txFields(transfer) {
  return [
    uintBytes(transfer.chainId),
    uintBytes(transfer.nonce),
    uintBytes(transfer.maxPriorityFeePerGas),
    uintBytes(transfer.maxFeePerGas),
    uintBytes(transfer.gasLimit),
    hexToBytes(transfer.to),
    uintBytes(transfer.value),
    hexToBytes(transfer.data ?? '0x'),
    [], // accessList: always empty here
  ];
}

/** keccak256 over `0x02 || rlp(fields)`: the hash the owner's key signs. */
export function signingHash(transfer) {
  return keccak_256(concat([Uint8Array.of(TYPE), rlp(txFields(transfer))]));
}

/**
 * Assemble the broadcastable raw transaction from the fields plus a signature.
 * `signature` is { yParity: 0|1, r: bigint|hex|decimal, s: ... }.
 */
export function assembleSigned(transfer, signature) {
  const y = Number(signature.yParity);
  if (y !== 0 && y !== 1) throw new EvmError('yParity must be 0 or 1');
  const toBytes = v => (typeof v === 'string' && v.startsWith('0x') ? uintBytes(BigInt(v)) : uintBytes(v));
  const signed = [...txFields(transfer), uintBytes(BigInt(y)), toBytes(signature.r), toBytes(signature.s)];
  return bytesToHex(concat([Uint8Array.of(TYPE), rlp(signed)]));
}

/** keccak256 of the raw signed transaction: its on-chain hash (txid). */
export const transactionHash = rawHex => bytesToHex(keccak_256(hexToBytes(rawHex)));

/**
 * Reconstruct a raw EIP-1559 transaction into the same field shape `canonicalTransfer` uses, so
 * the server can rebuild the canonical form from what is about to be broadcast and confirm it
 * equals the one the palm approved. Refuses anything that is not a well-formed type-2 tx.
 */
export function decodeSigned(rawHex) {
  const data = hexToBytes(rawHex);
  if (data[0] !== TYPE) throw new EvmError('not an EIP-1559 (type 2) transaction');
  const { value: items } = rlpDecodeAt(data, 1);
  if (!Array.isArray(items) || items.length !== 12) {
    throw new EvmError(`a signed type-2 tx has 12 fields, got ${Array.isArray(items) ? items.length : 'non-list'}`);
  }
  const [chainId, nonce, maxPriority, maxFee, gasLimit, to, value, callData, accessList, , ,] = items;
  if (!Array.isArray(accessList) || accessList.length !== 0) throw new EvmError('a non-empty access list is not accepted');
  if (to.length !== 20) throw new EvmError('the recipient is not a 20-byte address');
  return {
    chainId: bytesToBig(chainId).toString(10),
    nonce: bytesToBig(nonce).toString(10),
    maxPriorityFeePerGas: bytesToBig(maxPriority).toString(10),
    maxFeePerGas: bytesToBig(maxFee).toString(10),
    gasLimit: bytesToBig(gasLimit).toString(10),
    to: bytesToHex(to),
    value: bytesToBig(value).toString(10),
    data: bytesToHex(callData),
  };
}

/**
 * Recover the sender's address from a signed raw transaction — the account that actually
 * signed it, which is not one of the transaction's own fields but is implied by the signature.
 * The server uses this to confirm the approved sender is who signed.
 */
export function recoverSigner(rawHex) {
  const data = hexToBytes(rawHex);
  if (data[0] !== TYPE) throw new EvmError('not an EIP-1559 (type 2) transaction');
  const { value: items } = rlpDecodeAt(data, 1);
  if (!Array.isArray(items) || items.length !== 12) throw new EvmError('not a signed type-2 transaction');
  const [chainId, nonce, maxPriority, maxFee, gasLimit, to, value, callData, accessList, yParity, r, s] = items;
  if (!Array.isArray(accessList) || accessList.length !== 0) throw new EvmError('a non-empty access list is not accepted');

  const unsigned = [chainId, nonce, maxPriority, maxFee, gasLimit, to, value, callData, []];
  const hash = keccak_256(concat([Uint8Array.of(TYPE), rlp(unsigned)]));
  const recovery = yParity.length ? yParity[yParity.length - 1] : 0;
  const sig = new secp256k1.Signature(bytesToBig(r), bytesToBig(s)).addRecoveryBit(recovery);
  const pub = sig.recoverPublicKey(hash).toRawBytes(false).subarray(1);
  return bytesToHex(keccak_256(pub).subarray(-20));
}

/**
 * The server-side reconciliation gate — the EVM twin of the Bitcoin path's `verifyAgainstPlan`.
 *
 * Given the transfer the palm approved and the raw transaction a browser is asking to broadcast,
 * it confirms two things that together mean "this is exactly what was approved, signed by the
 * approved account":
 *
 *   1. Rebuilding the canonical transfer from the raw transaction's own fields (plus the
 *      network, sender and asset the approval fixed) reproduces the approved bytes exactly. A
 *      single changed byte — recipient, amount, fee, nonce, gas — makes the bytes differ.
 *   2. The address recovered from the signature is the approved sender. A valid transaction
 *      signed by some other key is refused.
 *
 * Returns { ok, reason, signer }. Never throws on a bad transaction — a refusal is an answer.
 */
export function reconcileSignedTransfer(approved, rawHex) {
  let decoded;
  let signer;
  try {
    decoded = decodeSigned(rawHex);
    signer = recoverSigner(rawHex);
  } catch (error) {
    return { ok: false, reason: `the signed transaction is malformed: ${error.message}`, signer: null };
  }
  if (signer.toLowerCase() !== approved.from.toLowerCase()) {
    return { ok: false, reason: 'signed by a different account than the one approved', signer };
  }
  let rebuilt;
  let approvedCanonical;
  try {
    rebuilt = canonicalTransfer({
      chain: approved.chain, network: approved.network, from: approved.from, asset: approved.asset,
      plan: {
        chainId: decoded.chainId, nonce: decoded.nonce, to: decoded.to, value: decoded.value,
        data: decoded.data, gasLimit: decoded.gasLimit,
        maxFeePerGas: decoded.maxFeePerGas, maxPriorityFeePerGas: decoded.maxPriorityFeePerGas,
      },
    });
    // `approved` is the stored payload, which carries an extra transactionHash field the
    // canonical form does not; re-canonicalise it so both sides are compared on equal terms.
    approvedCanonical = canonicalTransfer({
      chain: approved.chain, network: approved.network, from: approved.from, asset: approved.asset,
      plan: approved,
    });
  } catch (error) {
    return { ok: false, reason: `the signed transaction is not a valid transfer: ${error.message}`, signer };
  }
  if (transferBytes(rebuilt) !== transferBytes(approvedCanonical)) {
    return { ok: false, reason: 'the signed transaction does not match the approved transfer', signer };
  }
  return { ok: true, reason: null, signer };
}

export const utils = { hexToBytes, bytesToHex, uintBytes, bytesToBig };
