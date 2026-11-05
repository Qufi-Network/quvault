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
const WORD_LIMIT = 1n << 256n;
/** Palm's fee is at most this fraction of the amount: the contract's FEE_DIVISOR. */
export const FEE_DIVISOR = 1000n;

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
/** One 32-byte word. A value that does not fit is refused, never reduced modulo 2^256. */
const word = value => {
  const v = BigInt(value);
  if (v < 0n || v >= WORD_LIMIT) throw new PalmWalletError('That number does not fit in 256 bits.');
  const out = new Uint8Array(32);
  let rest = v;
  for (let i = 31; rest > 0n; i--, rest >>= 8n) out[i] = Number(rest & 0xffn);
  return out;
};
const addressWord = address => {
  const out = new Uint8Array(32);
  out.set(hex.decode(address.slice(2).toLowerCase()), 12);
  return out;
};
const whole = (value, what) => {
  const text = String(value ?? '');
  if (!DECIMAL.test(text) || BigInt(text) >= WORD_LIMIT) throw new PalmWalletError(`${what} must be a whole number below 2^256.`);
  return text;
};
const address = (value, what) => {
  const text = String(value ?? '');
  if (!ADDRESS.test(text)) throw new PalmWalletError(`${what} is not an address.`);
  return text.toLowerCase();
};

/**
 * A payment in the one form everything agrees on: lower-case addresses, decimal strings. It pays
 * `amount` of `token` to `to`, Palm's `fee` in the same asset to `feeTo` (at most 0.1% of the
 * amount, which the contract enforces too), and `gasRefund` of the native coin to whoever
 * submits it, and is worthless after `deadline` (seconds since 1970).
 */
export function normalTransfer({ token, to, amount, fee = '0', feeTo = NATIVE, gasRefund = '0', refundTo = NATIVE, deadline, nonce }) {
  const t = {
    token: address(token || NATIVE, 'The asset'),
    to: address(to, 'The payee'),
    amount: whole(amount, 'The amount'),
    fee: whole(fee, 'The fee'),
    feeTo: address(feeTo || NATIVE, 'The fee recipient'),
    gasRefund: whole(gasRefund, 'The network fee'),
    refundTo: address(refundTo || NATIVE, 'The network fee recipient'),
    deadline: whole(deadline, 'The deadline'),
    nonce: whole(nonce, 'The nonce'),
  };
  if (t.amount === '0') throw new PalmWalletError('Send more than nothing.');
  if (BigInt(t.fee) > BigInt(t.amount) / FEE_DIVISOR) throw new PalmWalletError('Palm’s fee can be at most 0.1% of the amount.');
  if (t.fee !== '0' && t.feeTo === NATIVE) throw new PalmWalletError('A fee needs somewhere to go.');
  if (t.gasRefund !== '0' && t.refundTo === NATIVE) throw new PalmWalletError('A network fee refund needs somewhere to go.');
  return t;
}

/** A refresh: moves nothing, refunds the network fee to `refundTo`, and closes the recovery path again. */
export function normalRefresh({ gasRefund = '0', refundTo = NATIVE, deadline, nonce }) {
  const r = {
    gasRefund: whole(gasRefund, 'The network fee'), refundTo: address(refundTo || NATIVE, 'The network fee recipient'),
    deadline: whole(deadline, 'The deadline'), nonce: whole(nonce, 'The nonce'),
  };
  if (r.gasRefund !== '0' && r.refundTo === NATIVE) throw new PalmWalletError('A network fee refund needs somewhere to go.');
  return r;
}

/** What the palms approve the hash of: this wallet, this chain, this payment, this nonce. */
export function canonicalEvmTransfer({ chainId, wallet, transfer }) {
  return { v: 3, kind: 'palm-wallet-transfer', chainId: whole(chainId, 'The chain'), wallet: address(wallet, 'The wallet'), ...normalTransfer(transfer) };
}

export function canonicalEvmRefresh({ chainId, wallet, refresh }) {
  return { v: 3, kind: 'palm-wallet-refresh', chainId: whole(chainId, 'The chain'), wallet: address(wallet, 'The wallet'), ...normalRefresh(refresh) };
}

/** The transaction hash in the palm approval's details: base64url SHA-256 of the canonical JSON. */
export const evmTransferDigest = args => sha256Base64Url(canonicalJson(canonicalEvmTransfer(args)));
export const evmRefreshDigest = args => sha256Base64Url(canonicalJson(canonicalEvmRefresh(args)));

const DOMAIN_TYPEHASH = keccak(utf8('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));
const TRANSFER_TYPEHASH = keccak(utf8(
  'Transfer(address token,address to,uint256 amount,uint256 fee,address feeTo,uint256 gasRefund,address refundTo,uint256 deadline,uint256 nonce)',
));
const REFRESH_TYPEHASH = keccak(utf8('Refresh(uint256 gasRefund,address refundTo,uint256 deadline,uint256 nonce)'));
const RECOVERY_TYPEHASH = keccak(utf8('Recovery(address token,address to,uint256 amount,uint256 deadline,uint256 nonce)'));

/** The wallet's EIP-712 domain separator, as `_domainSeparatorV4()` computes it: version 3. */
export const domainSeparator = ({ chainId, wallet }) => keccak(
  DOMAIN_TYPEHASH, keccak(utf8('PalmWallet')), keccak(utf8('3')), word(chainId), addressWord(address(wallet, 'The wallet')),
);

const typed = (domain, structHash) => keccak(Uint8Array.from([0x19, 0x01]), domain, structHash);

/** The digest a palm path payment is signed over, as `transferDigest()` computes it. */
export function eip712TransferDigest({ chainId, wallet, transfer }) {
  const t = normalTransfer(transfer);
  return typed(domainSeparator({ chainId, wallet }), keccak(
    TRANSFER_TYPEHASH, addressWord(t.token), addressWord(t.to), word(t.amount), word(t.fee),
    addressWord(t.feeTo), word(t.gasRefund), addressWord(t.refundTo), word(t.deadline), word(t.nonce),
  ));
}

/** The digest a refresh is signed over, as `refreshDigest()` computes it. */
export function eip712RefreshDigest({ chainId, wallet, refresh }) {
  const r = normalRefresh(refresh);
  return typed(domainSeparator({ chainId, wallet }), keccak(REFRESH_TYPEHASH, word(r.gasRefund), addressWord(r.refundTo), word(r.deadline), word(r.nonce)));
}

/** The digest the signers alone sign on the recovery path, as `recoveryDigest()` computes it. */
export function eip712RecoveryDigest({ chainId, wallet, recovery }) {
  const token = address(recovery.token || NATIVE, 'The asset');
  return typed(domainSeparator({ chainId, wallet }), keccak(
    RECOVERY_TYPEHASH, addressWord(token), addressWord(address(recovery.to, 'The payee')),
    word(whole(recovery.amount, 'The amount')), word(whole(recovery.deadline, 'The deadline')), word(whole(recovery.nonce, 'The nonce')),
  ));
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

/** abi.encode of a bytes[] (and a bytes after it, unless null), as the tail of a call whose head is `headWords` long. */
function signaturesTail(headWords, signerSignatures, palmSignature) {
  const element = bytes => concat(word(bytes.length), pad32(bytes));
  const elements = signerSignatures.map(sig => element(hexBytes(sig)));
  const offsets = [];
  let at = 32 * elements.length;
  for (const e of elements) {
    offsets.push(word(at));
    at += e.length;
  }
  const array = concat(word(elements.length), ...offsets, ...elements);
  const head = 32 * headWords;
  const palm = palmSignature === null ? null : element(hexBytes(palmSignature));
  return {
    offsets: palm ? [word(head), word(head + array.length)] : [word(head)],
    body: palm ? concat(array, palm) : array,
  };
}

/**
 * transfer((address token, address to, uint256 amount, uint256 fee, address feeTo,
 * uint256 gasRefund, address refundTo, uint256 deadline) p, bytes[] signerSignatures,
 * bytes palmSignature), with the signer signatures ordered by the address that made them, as the
 * contract requires.
 */
export function transferCallOf(transfer, signerSignatures, palmSignature) {
  const t = normalTransfer(transfer);
  const tail = signaturesTail(10, signerSignatures, palmSignature);
  return toHex(concat(
    selector('transfer((address,address,uint256,uint256,address,uint256,address,uint256),bytes[],bytes)'),
    addressWord(t.token), addressWord(t.to), word(t.amount), word(t.fee), addressWord(t.feeTo), word(t.gasRefund),
    addressWord(t.refundTo), word(t.deadline),
    ...tail.offsets, tail.body,
  ));
}

/** refresh(uint256 gasRefund, address refundTo, uint256 deadline, bytes[] signerSignatures, bytes palmSignature) */
export function refreshCallOf(refresh, signerSignatures, palmSignature) {
  const r = normalRefresh(refresh);
  const tail = signaturesTail(5, signerSignatures, palmSignature);
  return toHex(concat(
    selector('refresh(uint256,address,uint256,bytes[],bytes)'), word(r.gasRefund), addressWord(r.refundTo), word(r.deadline),
    ...tail.offsets, tail.body,
  ));
}

/** recover(address token, address to, uint256 amount, uint256 deadline, bytes[] signerSignatures) */
export function recoverCallOf(recovery, signerSignatures) {
  const tail = signaturesTail(5, signerSignatures, null);
  return toHex(concat(
    selector('recover(address,address,uint256,uint256,bytes[])'),
    addressWord(address(recovery.token || NATIVE, 'The asset')), addressWord(address(recovery.to, 'The payee')),
    word(whole(recovery.amount, 'The amount')), word(whole(recovery.deadline, 'The deadline')), ...tail.offsets, tail.body,
  ));
}

/** lastActivity(): when the palm last approved something in this wallet. */
export const LAST_ACTIVITY_CALL = toHex(selector('lastActivity()'));

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

/* ------------------------------------------------------------- what an heir reads from the chain */

/** The read-only calls an heir needs: everything else about a wallet is on the chain itself. */
export const SIGNERS_CALL = toHex(selector('signers()'));
export const THRESHOLD_CALL = toHex(selector('threshold()'));
export const RECOVERY_DELAY_CALL = toHex(selector('recoveryDelay()'));

/** An address[] returned by a call: offset, length, then one address per word. */
export function decodeAddressArray(result) {
  const bytes = hexBytes(result);
  const at = n => Number(BigInt(`0x${hex.encode(bytes.subarray(n, n + 32))}`));
  const start = at(0);
  const count = at(start);
  if (count > MAX_SIGNERS || bytes.length < start + 32 + 32 * count) throw new PalmWalletError('That is not a list of addresses.');
  return Array.from({ length: count }, (_, i) => `0x${hex.encode(bytes.subarray(start + 32 + 32 * i + 12, start + 64 + 32 * i))}`);
}

/**
 * What an inheritance sheet prints for a Palm Wallet: its chain and its address. The signers, the
 * threshold, the delay and when the palm last approved anything are all read from the wallet.
 */
export const walletDescription = ({ chainId, address: wallet }) => `palmwallet:${whole(chainId, 'The chain')}:${address(wallet, 'The wallet')}`;

export function parseWalletDescription(text) {
  const m = String(text ?? '').trim().replace(/\s+/g, '').toLowerCase().match(/^palmwallet:(\d{1,12}):(0x[0-9a-f]{40})$/);
  if (!m) throw new PalmWalletError('That is not a Palm Wallet description. It looks like palmwallet:11155111:0x… on the inheritance sheet.');
  return { chainId: Number(m[1]), address: m[2] };
}
