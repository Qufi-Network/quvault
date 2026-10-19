/*
 * The canonical form of an account-based (EVM) transfer: the exact transaction a palm approves
 * and a signature must reconcile to, for Ethereum and any EVM chain such as BSC.
 *
 * WHY THIS IS SEPARATE FROM src/canonical.js
 *
 * `canonicalTransaction` there is UTXO-shaped — inputs, outputs, a fee in satoshis. An EVM
 * transfer has no UTXOs: it is an account nonce, a single recipient, a value, a gas limit and
 * two EIP-1559 fee fields. Collapsing the two into one function would mean a shape that is half
 * empty for whichever chain is being signed, and a verifier could not tell which rules applied.
 * So account chains get their own canonical form, and `whatItProves`-style readers can branch
 * on `chain`.
 *
 * WHY IT IS CAREFUL
 *
 * This is the keystone the whole EVM path hangs off, for the same reason the policy descriptor
 * was: the digest of these bytes is what the palm approves, what the authorisation record binds,
 * and what the browser re-derives before it will sign. Freeze it wrong and every receipt taken
 * against it is unverifiable, with no migration available. So the field set and its serialisation
 * are fixed here, exercised by a locked reference vector, and guarded by `checkTransferStability`
 * which the first signer runs before it signs anything.
 *
 * WHY VALUES ARE STRINGS
 *
 * Wei has 18 decimals. A single ETH is 10^18 wei, far past Number.MAX_SAFE_INTEGER (~9*10^15),
 * so a JS number cannot hold a balance without silently rounding — and a rounded value that
 * hashed one way when signed and another after a JSON round trip is exactly the class of bug
 * that was fixed in canonical.js. Every quantity here is a base-10 string of the integer wei
 * amount, normalised (no leading zeros, no sign, no decimal point), so the bytes are identical
 * on both sides of the wire.
 *
 * It imports only `canonicalJson`, no Node or browser APIs, so the browser can bundle it.
 */
import { canonicalJson } from './canonical.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64urlnopad } from '@scure/base';

export const TRANSFER_VERSION = 1;

export class TransferError extends Error {}

/** A base-10 string of a non-negative integer, normalised. Accepts a string or a bigint. */
function uint(value, field) {
  let text;
  if (typeof value === 'bigint') text = value.toString(10);
  else if (typeof value === 'string') text = value.trim();
  else throw new TransferError(`${field} must be a base-10 string or a bigint, not ${typeof value}.`);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new TransferError(`${field} must be a non-negative integer with no leading zeros: ${text}`);
  }
  return text;
}

/** A 0x-prefixed lower-case hex string of the given byte length, or null to forbid absence. */
function hex(value, { bytes = null, field }) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]*$/.test(value)) {
    throw new TransferError(`${field} must be a 0x hex string.`);
  }
  const body = value.slice(2);
  if (body.length % 2 !== 0) throw new TransferError(`${field} has an odd number of hex digits.`);
  if (bytes !== null && body.length !== bytes * 2) {
    throw new TransferError(`${field} must be ${bytes} bytes, got ${body.length / 2}.`);
  }
  return `0x${body.toLowerCase()}`;
}

/**
 * The exact transaction, in a fixed field set and a fixed order after canonical sorting.
 *
 * `plan` is what the server built and the browser will sign:
 *   chainId, nonce, to, value, data, gasLimit, maxFeePerGas, maxPriorityFeePerGas
 *
 * `asset` describes WHAT is moving so a reader does not have to decode `data`: 'native' for the
 * chain's own coin, or { kind: 'erc20', token, symbol, decimals } for a token. It is a readable
 * restatement, never the authority — the authority is `to`/`value`/`data`, which is what gets
 * signed. For an ERC-20 transfer the real recipient and amount live inside `data`; `asset` and
 * the top-level `to`/`value` (the token contract and 0) must agree with it, which
 * `checkErc20Plan` enforces.
 */
export function canonicalTransfer({ chain, network, from, plan, asset = { kind: 'native' } }) {
  if (chain !== 'evm') throw new TransferError(`canonicalTransfer is for EVM chains, not ${chain}.`);
  if (typeof network !== 'string' || !network) throw new TransferError('A transfer must name its network.');
  const fromAddr = hex(from, { bytes: 20, field: 'from' });

  const record = {
    v: TRANSFER_VERSION,
    chain,
    network,
    chainId: uint(plan.chainId, 'chainId'),
    from: fromAddr,
    nonce: uint(plan.nonce, 'nonce'),
    to: hex(plan.to, { bytes: 20, field: 'to' }),
    value: uint(plan.value, 'value'),
    data: hex(plan.data ?? '0x', { field: 'data' }),
    gasLimit: uint(plan.gasLimit, 'gasLimit'),
    maxFeePerGas: uint(plan.maxFeePerGas, 'maxFeePerGas'),
    maxPriorityFeePerGas: uint(plan.maxPriorityFeePerGas, 'maxPriorityFeePerGas'),
    asset: normaliseAsset(asset),
  };

  // The priority fee cannot exceed the cap; an EVM node rejects such a transaction, and catching
  // it here means a palm is never spent approving one that cannot be mined.
  if (BigInt(record.maxPriorityFeePerGas) > BigInt(record.maxFeePerGas)) {
    throw new TransferError('maxPriorityFeePerGas cannot exceed maxFeePerGas.');
  }
  return record;
}

function normaliseAsset(asset) {
  if (!asset || asset.kind === 'native') return { kind: 'native' };
  if (asset.kind === 'erc20') {
    return {
      kind: 'erc20',
      token: hex(asset.token, { bytes: 20, field: 'asset.token' }),
      symbol: typeof asset.symbol === 'string' ? asset.symbol.slice(0, 16) : '',
      decimals: Number.isInteger(asset.decimals) && asset.decimals >= 0 && asset.decimals <= 36
        ? asset.decimals : (() => { throw new TransferError('asset.decimals must be an integer 0..36.'); })(),
    };
  }
  throw new TransferError(`Unknown asset kind: ${asset.kind}`);
}

/** The exact bytes the digest is taken over. One function, used by signer and verifier alike. */
export const transferBytes = transfer => canonicalJson(transfer);

/**
 * The binding digest of a transfer: base64url (no padding) of SHA-256 over its canonical bytes.
 * This is what the palm approves and what the authorisation record names, so the server and the
 * browser must produce the same string — which they do because both call this one function.
 */
export const transferDigest = transfer =>
  base64urlnopad.encode(sha256(new TextEncoder().encode(transferBytes(transfer))));

/* ------------------------------------------------------------ the ERC-20 consistency check */

const ERC20_TRANSFER_SELECTOR = '0xa9059cbb'; // keccak256('transfer(address,uint256)')[:4]

/**
 * For a token transfer, the readable `asset`, the top-level `to`/`value`, and the ABI-encoded
 * `data` must all agree, so a palm approving "send 100 USDT to X" cannot be realised as a
 * transaction that `data` makes do something else.
 *
 * Returns the decoded { recipient, amount } so a caller can show them; throws on any mismatch.
 */
export function checkErc20Plan(transfer) {
  if (transfer.asset.kind !== 'erc20') throw new TransferError('Not an ERC-20 transfer.');
  if (transfer.value !== '0') throw new TransferError('A token transfer sends no native value.');
  if (transfer.to !== transfer.asset.token) {
    throw new TransferError('A token transfer must be addressed to the token contract.');
  }
  const data = transfer.data;
  if (!data.startsWith(ERC20_TRANSFER_SELECTOR) || data.length !== 2 + 8 + 64 + 64) {
    throw new TransferError('The call data is not a bare ERC-20 transfer(address,uint256).');
  }
  const recipientWord = data.slice(10, 74);
  if (!/^0{24}[0-9a-f]{40}$/.test(recipientWord)) {
    throw new TransferError('The ERC-20 recipient word has dirty high bytes.');
  }
  const recipient = `0x${recipientWord.slice(24)}`;
  const amount = BigInt(`0x${data.slice(74, 138)}`).toString(10);
  return { recipient, amount };
}

/* --------------------------------------------------------------------- the locked vector */

/**
 * A fixed transfer and the bytes and digest it must produce. Deliberately exercises the parts
 * that could move: a big value past Number range, a non-empty data field, and an erc20 asset
 * with its fields out of alphabetical order on input.
 */
export const REFERENCE_INPUT = Object.freeze({
  chain: 'evm',
  network: 'ethereum',
  from: '0x1111111111111111111111111111111111111111',
  plan: {
    chainId: '1',
    nonce: '7',
    to: '0x55d398326f99059fF775485246999027B3197955',
    value: '0',
    data: '0xa9059cbb000000000000000000000000'
      + '2222222222222222222222222222222222222222'
      + '0000000000000000000000000000000000000000000000008ac7230489e80000', // 10 * 10^18
    gasLimit: '60000',
    maxFeePerGas: '30000000000',
    maxPriorityFeePerGas: '1500000000',
  },
  asset: { decimals: 18, symbol: 'USDT', kind: 'erc20', token: '0x55d398326f99059fF775485246999027B3197955' },
});

export const REFERENCE_BYTES =
  '{"asset":{"decimals":18,"kind":"erc20","symbol":"USDT","token":"0x55d398326f99059ff775485246999027b3197955"},'
  + '"chain":"evm","chainId":"1",'
  + '"data":"0xa9059cbb0000000000000000000000002222222222222222222222222222222222222222'
  + '0000000000000000000000000000000000000000000000008ac7230489e80000",'
  + '"from":"0x1111111111111111111111111111111111111111",'
  + '"gasLimit":"60000","maxFeePerGas":"30000000000","maxPriorityFeePerGas":"1500000000",'
  + '"network":"ethereum","nonce":"7","to":"0x55d398326f99059ff775485246999027b3197955",'
  + '"v":1,"value":"0"}';

/** base64url SHA-256 of REFERENCE_BYTES. Locked; recomputed and checked in the test suite. */
export const REFERENCE_DIGEST = 'IoDhiBiUk3iOj6__FY8pw_5bapBvker6jysKZEyL1jY';

/**
 * Refuses to let a caller proceed if the canonical form of a transfer has moved. Called by the
 * first EVM signer before it signs, and by the test suite. Throws, because the correct response
 * to drift is always to stop. `digestOf(text) -> string` is supplied by the caller.
 */
export function checkTransferStability(digestOf) {
  if (typeof digestOf !== 'function') throw new TransferError('checkTransferStability needs a digest function.');
  const transfer = canonicalTransfer(REFERENCE_INPUT);
  const bytes = transferBytes(transfer);

  if (bytes !== REFERENCE_BYTES) {
    throw new TransferError(
      'The canonical form of an EVM transfer has changed. Every digest already taken over the old '
      + 'bytes is now unverifiable, so nothing may be signed until this is understood.\n'
      + `  expected: ${REFERENCE_BYTES}\n  produced: ${bytes}`);
  }
  let parsed;
  try { parsed = JSON.parse(bytes); } catch (error) {
    throw new TransferError(`Transfer bytes are not valid JSON: ${error.message}`);
  }
  if (transferBytes(JSON.parse(JSON.stringify(transfer))) !== bytes) {
    throw new TransferError('A transfer does not survive a JSON round trip.');
  }
  if (transferBytes(parsed) !== bytes) {
    throw new TransferError('Re-canonicalising parsed transfer bytes does not reproduce them.');
  }
  // The ERC-20 check must agree with the fields it is derived from.
  const decoded = checkErc20Plan(transfer);
  if (decoded.recipient !== '0x2222222222222222222222222222222222222222' || decoded.amount !== '10000000000000000000') {
    throw new TransferError(`The ERC-20 decode drifted: ${JSON.stringify(decoded)}`);
  }

  const digest = digestOf(bytes);
  if (REFERENCE_DIGEST !== 'PENDING' && digest !== REFERENCE_DIGEST) {
    throw new TransferError(
      `The EVM transfer digest has changed.\n  expected: ${REFERENCE_DIGEST}\n  produced: ${digest}`);
  }
  if (digestOf(bytes) !== digest) throw new TransferError('The digest function is not deterministic.');
  return { bytes, digest };
}
