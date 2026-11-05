/*
 * A receipt checked against an Ethereum or BSC chain. The receipt's transaction digest is the
 * digest of what the palm approved; this works the same digest out again from what the chain
 * itself recorded, so a receipt that matches describes exactly the transaction that went out.
 *
 * Two kinds of transaction reach the chain from Palm:
 *
 *   - a Palm Wallet payment or refresh: the gas account calls the wallet contract. The payment
 *     sits in the call's input, and the wallet's own nonce for it is in the event it emits.
 *   - a plain account's transfer, signed in the browser: every field of the canonical transfer
 *     is a field of the transaction.
 *
 * It needs nothing but the transaction and its receipt, and no node or browser API, so the page
 * runs the same code as the tests.
 */
import { keccak_256 } from '@noble/hashes/sha3.js';
import { canonicalTransfer, transferDigest } from './canonical-transfer.js';
import { evmTransferDigest, evmRefreshDigest, NATIVE } from './palm-wallet.js';

const hexOf = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const hashOf = text => hexOf(keccak_256(new TextEncoder().encode(text)));
const lower = value => String(value ?? '').toLowerCase();

const TRANSFER = hashOf('transfer((address,address,uint256,uint256,address,uint256,address,uint256),bytes[],bytes)').slice(0, 8);
const REFRESH = hashOf('refresh(uint256,address,uint256,bytes[],bytes)').slice(0, 8);
const TRANSFERRED = `0x${hashOf('Transferred(uint256,address,address,uint256,uint256,uint256)')}`;
const REFRESHED = `0x${hashOf('Refreshed(uint256,uint256)')}`;

/**
 * The digest a receipt for this chain transaction would carry, with what the transaction did.
 * `tx` is the transaction with its receipt's logs, every quantity a decimal string, as
 * /api/chain/evm/:network/tx/:hash returns it.
 */
export function chainDigestOf(tx, { network }) {
  const input = lower(tx.input || '0x').replace(/^0x/, '');
  const selector = input.slice(0, 8);
  const word = i => input.slice(8 + 64 * i, 8 + 64 * (i + 1));
  const uint = i => BigInt(`0x${word(i) || '0'}`).toString(10);
  const addr = i => `0x${word(i).slice(24)}`;
  // The wallet's nonce for this call, from the event the wallet itself emitted.
  const nonceFrom = topic => {
    const log = (tx.logs ?? []).find(item => lower(item.address) === lower(tx.to) && lower(item.topics?.[0]) === topic);
    return log ? BigInt(log.topics[1]).toString(10) : null;
  };

  if (selector === TRANSFER) {
    const nonce = nonceFrom(TRANSFERRED);
    if (nonce === null) return { kind: 'palm wallet payment', digest: null, problem: 'The wallet recorded no payment in this transaction.' };
    const transfer = {
      token: addr(0), to: addr(1), amount: uint(2), fee: uint(3), feeTo: addr(4),
      gasRefund: uint(5), refundTo: addr(6), deadline: uint(7), nonce,
    };
    return {
      kind: 'palm wallet payment',
      digest: evmTransferDigest({ chainId: tx.chainId, wallet: tx.to, transfer }),
      payee: transfer.to, amount: transfer.amount, token: transfer.token === NATIVE ? null : transfer.token,
      fees: (BigInt(transfer.fee) + BigInt(transfer.gasRefund)).toString(10),
    };
  }
  if (selector === REFRESH) {
    const nonce = nonceFrom(REFRESHED);
    if (nonce === null) return { kind: 'palm wallet refresh', digest: null, problem: 'The wallet recorded no refresh in this transaction.' };
    const refresh = { gasRefund: uint(0), refundTo: addr(1), deadline: uint(2), nonce };
    return {
      kind: 'palm wallet refresh',
      digest: evmRefreshDigest({ chainId: tx.chainId, wallet: tx.to, refresh }),
      payee: null, amount: '0', token: null, fees: refresh.gasRefund,
    };
  }
  const transfer = canonicalTransfer({
    chain: 'evm', network, from: tx.from,
    plan: {
      chainId: tx.chainId, nonce: tx.nonce, to: tx.to, value: tx.value, data: tx.input || '0x', gasLimit: tx.gas,
      maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
    },
  });
  return { kind: 'transfer', digest: transferDigest(transfer), payee: transfer.to, amount: transfer.value, token: null, fees: null };
}
