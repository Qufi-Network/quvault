/*
 * The Palm Wallet on Ethereum and BSC: the off-chain half of contracts/contracts/PalmWallet.sol.
 *
 * A transfer from a Palm Wallet needs signatures from enough signers and from the palm key, over
 * an EIP-712 digest the contract recomputes. This module builds that digest exactly as the
 * contract does, and the canonical description of a transfer whose hash the palms approve, so
 * the human-readable approval, the palm signer's check and the on-chain signature all name the
 * same transfer.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import { canonicalJson } from './canonical.js';
import { sha256Base64Url } from './veyns.js';

export const NATIVE = '0x0000000000000000000000000000000000000000';

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;

export class PalmWalletError extends Error {}

const utf8 = text => new TextEncoder().encode(text);
const keccak = (...parts) => keccak_256(concat(...parts));
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}
const word = value => {
  const out = new Uint8Array(32);
  let v = BigInt(value);
  for (let i = 31; v > 0n; i--, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
};
const addressWord = address => {
  const out = new Uint8Array(32);
  out.set(hex.decode(address.slice(2).toLowerCase()), 12);
  return out;
};

/** A transfer in the one form everything agrees on: lower-case addresses, decimal strings. */
export function normalTransfer({ token, to, amount, nonce }) {
  const tokenAddress = token ? String(token) : NATIVE;
  if (!ADDRESS.test(tokenAddress) || !ADDRESS.test(String(to))) throw new PalmWalletError('That is not an address.');
  if (!DECIMAL.test(String(amount)) || !DECIMAL.test(String(nonce))) throw new PalmWalletError('Amounts and nonces are whole numbers.');
  if (String(amount) === '0') throw new PalmWalletError('Send more than nothing.');
  return { token: tokenAddress.toLowerCase(), to: String(to).toLowerCase(), amount: String(amount), nonce: String(nonce) };
}

/** What the palms approve the hash of: this wallet, this chain, this transfer, this nonce. */
export function canonicalEvmTransfer({ chainId, wallet, transfer }) {
  if (!ADDRESS.test(String(wallet))) throw new PalmWalletError('That is not a wallet address.');
  return { v: 1, kind: 'palm-wallet-transfer', chainId: String(chainId), wallet: String(wallet).toLowerCase(), ...normalTransfer(transfer) };
}

/** The transaction hash in the palm approval's details: base64url SHA-256 of the canonical JSON. */
export const evmTransferDigest = args => sha256Base64Url(canonicalJson(canonicalEvmTransfer(args)));

const DOMAIN_TYPEHASH = keccak(utf8('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));
const TRANSFER_TYPEHASH = keccak(utf8('Transfer(address token,address to,uint256 amount,uint256 nonce)'));
const RECOVERY_TYPEHASH = keccak(utf8('Recovery(address token,address to,uint256 amount,uint256 nonce)'));
const CANCEL_TYPEHASH = keccak(utf8('Cancel(bytes32 id,uint256 nonce)'));

/** The wallet's EIP-712 domain separator, as `_domainSeparatorV4()` computes it. */
export const domainSeparator = ({ chainId, wallet }) => keccak(
  DOMAIN_TYPEHASH, keccak(utf8('PalmWallet')), keccak(utf8('1')), word(chainId), addressWord(String(wallet)),
);

const typed = (domain, structHash) => keccak(Uint8Array.from([0x19, 0x01]), domain, structHash);

/** The digest a normal-path transfer is signed over, as `transferDigest()` computes it. */
export function eip712TransferDigest({ chainId, wallet, transfer }) {
  const t = normalTransfer(transfer);
  return typed(domainSeparator({ chainId, wallet }),
    keccak(TRANSFER_TYPEHASH, addressWord(t.token), addressWord(t.to), word(t.amount), word(t.nonce)));
}

/** The digest the signers sign to schedule a recovery transfer, as `recoveryDigest()` computes it. */
export function eip712RecoveryDigest({ chainId, wallet, transfer }) {
  const t = normalTransfer(transfer);
  return typed(domainSeparator({ chainId, wallet }),
    keccak(RECOVERY_TYPEHASH, addressWord(t.token), addressWord(t.to), word(t.amount), word(t.nonce)));
}

/** The digest the palm key signs to cancel a scheduled recovery, as `cancelDigest()` computes it. */
export function eip712CancelDigest({ chainId, wallet, id, nonce }) {
  return typed(domainSeparator({ chainId, wallet }), keccak(CANCEL_TYPEHASH, hex.decode(String(id).replace(/^0x/, '')), word(nonce)));
}

/** The Ethereum address of a secp256k1 private key. */
export function addressOfKey(privateKey) {
  const uncompressed = secp256k1.getPublicKey(privateKey, false);
  return `0x${hex.encode(keccak_256(uncompressed.subarray(1)).subarray(12))}`;
}

/** A 65-byte r || s || v signature over a 32-byte digest, low-s, v 27 or 28, as `ECDSA.recover` wants. */
export function signDigest(digest, privateKey) {
  const signature = secp256k1.sign(digest, privateKey, { lowS: true });
  return `0x${hex.encode(concat(word(signature.r), word(signature.s), Uint8Array.of(27 + signature.recovery)))}`;
}
