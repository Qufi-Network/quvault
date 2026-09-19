/*
 * The wallet, in your browser. This module holds the only copy of the key material,
 * bundled into public/vendor/wallet.js by `npm run build:client`.
 *
 * The server never sees the phrase or the key. It holds one sealed unlock secret, which is
 * useless on its own: without the encrypted blob in this browser there is nothing to open.
 */
import * as btc from '@scure/btc-signer';
import { HDKey } from '@scure/bip32';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hex } from '@scure/base';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const NETWORK = btc.TEST_NETWORK;
const PATH = "m/84'/1'/0'/0/0"; // BIP84 testnet: the phrase restores in any standard wallet
const DB_NAME = 'quvault';
const STORE = 'wallet';
const RECORD = 'current';

/* ------------------------------------------------------------- entropy */

/**
 * Mixes three sources, so no single one has to be perfect: this browser's generator,
 * fresh randomness from the server, and jitter from the creation ceremony itself.
 */
export function makeMnemonic({ serverRandom, jitter }) {
  const browser = crypto.getRandomValues(new Uint8Array(32));
  const mixed = hkdf(sha256, concat(browser, serverRandom, jitter), undefined, 'quvault wallet seed v1', 16);
  return generateMnemonic(wordlist, 128, () => mixed); // 12 words, 128 bits
}

function concat(...parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** A few bytes that depend on how the person actually moved and how long each step took. */
export function jitterFrom(events) {
  const text = events.map(value => String(value)).join('|');
  return sha256(new TextEncoder().encode(`${text}|${performance.now()}|${Date.now()}`));
}

/* ------------------------------------------------------ keys and money */

export function accountFrom(mnemonic) {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error('That is not a valid 12-word recovery phrase.');
  const node = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic)).derive(PATH);
  const publicKey = node.publicKey;
  const payment = btc.p2wpkh(publicKey, NETWORK);
  return { privateKey: node.privateKey, publicKey, address: payment.address, path: PATH };
}

/**
 * Signs exactly the plan the palm approved: same coins, same outputs, same fee.
 * `expectedAddress` guards against signing with the wrong phrase, which would otherwise
 * produce a transaction the network silently rejects.
 */
export function signPlan(mnemonic, plan, expectedAddress) {
  const { privateKey, publicKey, address } = accountFrom(mnemonic);
  if (expectedAddress && address !== expectedAddress) {
    throw new Error('That phrase belongs to a different wallet.');
  }
  const script = btc.p2wpkh(publicKey, NETWORK).script;
  const tx = new btc.Transaction();
  for (const input of plan.inputs) {
    tx.addInput({ txid: hex.decode(input.txid), index: input.index, witnessUtxo: { script, amount: BigInt(input.value) } });
  }
  for (const output of plan.outputs) tx.addOutputAddress(output.address, BigInt(output.sats), NETWORK);
  tx.sign(privateKey);
  tx.finalize();
  const fee = plan.inputs.reduce((sum, i) => sum + i.value, 0) - plan.outputs.reduce((sum, o) => sum + o.sats, 0);
  if (fee !== plan.feeSats) throw new Error('The transaction does not match the approved plan.');
  return { hex: tx.hex, txid: tx.id };
}

/* ------------------------------------------------------------- storage */

const aesKey = async (unlockSecret, salt) => crypto.subtle.importKey(
  'raw',
  hkdf(sha256, unlockSecret, salt, 'quvault device key v1', 32),
  { name: 'AES-GCM' },
  false,
  ['encrypt', 'decrypt'],
);

export async function encryptMnemonic(mnemonic, unlockSecretBase64, saltBase64) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(fromBase64(unlockSecretBase64), fromBase64(saltBase64));
  const body = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, new TextEncoder().encode(mnemonic));
  return toBase64(concat(nonce, new Uint8Array(body)));
}

export async function decryptMnemonic(blobBase64, unlockSecretBase64, saltBase64) {
  const blob = fromBase64(blobBase64);
  const key = await aesKey(fromBase64(unlockSecretBase64), fromBase64(saltBase64));
  const body = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(0, 12) }, key, blob.slice(12));
  return new TextDecoder().decode(body);
}

export const toBase64 = bytes => btoa(String.fromCharCode(...bytes));
export const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('This browser will not let QuVault store your wallet.'));
  });
}

async function withStore(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = fn(tx.objectStore(STORE));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('Could not reach this browser\'s storage.'));
    });
  } finally {
    db.close();
  }
}

/** { blob, salt, address, publicKey, createdAt } — never the phrase itself. */
export const loadRecord = () => withStore('readonly', store => store.get(RECORD));
export const saveRecord = record => withStore('readwrite', store => store.put(record, RECORD));
export const clearRecord = () => withStore('readwrite', store => store.delete(RECORD));
