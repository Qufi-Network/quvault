/*
 * The two things about Bitcoin that the browser and the server must agree on exactly and that
 * need no node:crypto: which network, and the error a wallet operation throws. src/bitcoin.js
 * re-exports both, so `instanceof WalletError` is the same class wherever it is checked.
 */
import * as btc from '@scure/btc-signer';

export const NETWORK = btc.TEST_NETWORK;

export class WalletError extends Error {}
