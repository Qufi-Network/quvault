/*
 * The gas account: the one Ethereum and BSC account this server sends transactions from.
 *
 * A Palm Wallet's transfer can be submitted by anyone, because the signatures in it are the
 * authority, so somebody has to pay the network fee, and making every signer keep coins for gas
 * would be one more thing to go wrong. This account pays: it builds a wallet on its first
 * payment and submits each signed transfer. It cannot move anyone's coins. A transaction it
 * sends without the signers' and the palm key's signatures is refused by the wallet, so the most
 * a stolen gas account key can do is spend the gas account's own fees.
 *
 * Its key is derived from WALLET_SEED, so there is nothing new to configure; the same address
 * on every EVM chain. On a test network it is topped up from a faucet.
 */
import crypto from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { signingHash, assembleSigned, transactionHash } from './evm.js';
import { addressOfKey } from './palm-wallet.js';

const ORDER = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');

/** The gas account's private key: never zero, never past the curve order. */
export function relayerKeyFrom(walletSeed) {
  const n = BigInt(`0x${crypto.createHmac('sha256', String(walletSeed)).update('palm gas account v1').digest('hex')}`);
  const scalar = (n % (ORDER - 1n)) + 1n;
  return Uint8Array.from(Buffer.from(scalar.toString(16).padStart(64, '0'), 'hex'));
}

export const relayerAddressOf = key => addressOfKey(key);

/** An EIP-1559 transaction signed by `key`: the raw bytes to broadcast and their hash. */
export function signRelayed(fields, key) {
  const signature = secp256k1.sign(signingHash(fields), key, { lowS: true });
  const raw = assembleSigned(fields, { yParity: signature.recovery, r: signature.r, s: signature.s });
  return { raw, txid: transactionHash(raw) };
}
