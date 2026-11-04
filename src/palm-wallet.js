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
import { sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex, base64urlnopad } from '@scure/base';
import { canonicalJson } from './canonical.js';
import { PALM_WALLET_CREATION_CODE } from './palm-wallet-code.js';

// The same base64url SHA-256 the server uses everywhere, written here without node:crypto so the
// browser can check a transfer against its palm approval with this very module.
const sha256Base64Url = text => base64urlnopad.encode(sha256(new TextEncoder().encode(text)));

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

/* ------------------------------------------------------------- the wallet on the chain */

/**
 * The deterministic deployment proxy (Arachnid's CREATE2 deployer), at this address on Ethereum,
 * Sepolia, BSC and its testnet, and almost every other EVM chain. Sending it salt || init code
 * deploys that code at an address anyone can work out beforehand, so a Palm Wallet has its
 * address, and can receive, before it exists, and no factory of ours has to be deployed first.
 */
export const DEPLOYER = '0x4e59b44847b379578588920ca78fbf26c0b4956c';
const SECONDS_PER_DAY = 86400;
export const MAX_SIGNERS = 20;

const selector = signature => keccak_256(utf8(signature)).subarray(0, 4);
const pad32 = bytes => {
  const out = new Uint8Array(Math.ceil(bytes.length / 32) * 32);
  out.set(bytes);
  return out;
};
const hexBytes = value => hex.decode(String(value).replace(/^0x/, '').toLowerCase());
const toHex = bytes => `0x${hex.encode(bytes)}`;

/** The Ethereum address a secp256k1 public key (compressed or not, hex) signs for. */
export function evmAddressOfPublicKey(publicKey) {
  let point;
  try {
    point = secp256k1.Point.fromHex(String(publicKey).replace(/^0x/, ''));
  } catch {
    throw new PalmWalletError('That is not a public key.');
  }
  return `0x${hex.encode(keccak_256(point.toBytes(false).subarray(1)).subarray(12))}`;
}

/**
 * One wallet's settings, checked and put in the one order the contract accepts: signer
 * addresses ascending and distinct, the palm signer not among them, a threshold the contract
 * will take, and a delay in whole days within its bounds.
 */
export function walletParams({ signers, threshold, palmSigner, recoveryDays }) {
  const list = [...new Set((signers ?? []).map(a => String(a).toLowerCase()))].sort();
  if (!list.length || list.length > MAX_SIGNERS) throw new PalmWalletError(`A Palm Wallet takes between 1 and ${MAX_SIGNERS} signers.`);
  if (list.length !== (signers ?? []).length) throw new PalmWalletError('The same signer appears twice.');
  if (!list.every(a => ADDRESS.test(a))) throw new PalmWalletError('A signer is not an address.');
  const palm = String(palmSigner ?? '').toLowerCase();
  if (!ADDRESS.test(palm) || palm === NATIVE) throw new PalmWalletError('The palm signer is not an address.');
  if (list.includes(palm)) throw new PalmWalletError('The palm signer cannot also be a signer.');
  const m = Number(threshold);
  if (!Number.isInteger(m) || m < 1 || m > list.length) throw new PalmWalletError('That threshold does not fit those signers.');
  if (list.length > 1 && m < 2) throw new PalmWalletError('A shared wallet needs at least two signatures.');
  const days = Number(recoveryDays);
  if (!Number.isInteger(days) || days < 1 || days > 730) throw new PalmWalletError('The recovery delay must be between 1 and 730 days.');
  return { signers: list, threshold: m, palmSigner: palm, recoveryDelay: days * SECONDS_PER_DAY };
}

/** abi.encode(address[] signers, uint256 threshold, address palmSigner, uint256 recoveryDelay) */
function constructorArgs(params) {
  return concat(
    word(128), word(params.threshold), addressWord(params.palmSigner), word(params.recoveryDelay),
    word(params.signers.length), ...params.signers.map(addressWord),
  );
}

/** The exact bytes that deploy this wallet: its creation code, then its constructor arguments. */
export const initCodeOf = params => concat(hexBytes(PALM_WALLET_CREATION_CODE), constructorArgs(params));

/** The salt a wallet is deployed with: fixed by the vault it belongs to, so its address is too. */
export const walletSalt = walletId => keccak_256(utf8(`palm-wallet:${walletId}`));

/** Where this wallet lives, or will: CREATE2 from the deployment proxy. */
export function walletAddressOf(params, salt) {
  const digest = keccak_256(concat(Uint8Array.of(0xff), hexBytes(DEPLOYER), salt, keccak_256(initCodeOf(params))));
  return `0x${hex.encode(digest.subarray(12))}`;
}

/** The call to the deployment proxy that builds the wallet: salt || init code. */
export const deployCallOf = (params, salt) => toHex(concat(salt, initCodeOf(params)));

/** nonce(): the wallet's next transfer number. */
export const NONCE_CALL = toHex(selector('nonce()'));

/**
 * transfer(address token, address to, uint256 amount, bytes[] signerSignatures, bytes palmSignature),
 * with the signer signatures ordered by the address that made them, as the contract requires.
 */
export function transferCallOf(transfer, signerSignatures, palmSignature) {
  const t = normalTransfer(transfer);
  const sigs = signerSignatures.map(hexBytes);
  const palm = hexBytes(palmSignature);
  const element = bytes => concat(word(bytes.length), pad32(bytes));
  const elements = sigs.map(element);
  const offsets = [];
  let at = 32 * sigs.length;
  for (const e of elements) {
    offsets.push(word(at));
    at += e.length;
  }
  const array = concat(word(sigs.length), ...offsets, ...elements);
  const head = 5 * 32;
  return toHex(concat(
    selector('transfer(address,address,uint256,bytes[],bytes)'),
    addressWord(t.token), addressWord(t.to), word(t.amount), word(head), word(head + array.length),
    array, element(palm),
  ));
}

/** The address a 65-byte r || s || v signature over `digest` was made by. */
export function recoverAddress(digest, signature) {
  const bytes = hexBytes(signature);
  if (bytes.length !== 65) throw new PalmWalletError('A signature is 65 bytes.');
  const v = bytes[64] >= 27 ? bytes[64] - 27 : bytes[64];
  if (v !== 0 && v !== 1) throw new PalmWalletError('That signature has no recovery bit.');
  const sig = secp256k1.Signature.fromBytes(bytes.subarray(0, 64), 'compact').addRecoveryBit(v);
  if (sig.hasHighS()) throw new PalmWalletError('That signature is not in low-s form.');
  return `0x${hex.encode(keccak_256(sig.recoverPublicKey(digest).toBytes(false).subarray(1)).subarray(12))}`;
}
