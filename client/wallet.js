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
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hmac } from '@noble/hashes/hmac.js';
import { base32, base58check } from '@scure/base';
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64urlnopad } from '@scure/base';
import { canonicalTransaction, canonicalBytes } from '../src/canonical.js';
import { verifyAuthorization } from '../src/authorization.js';

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

/* ------------------------------------------------- the other networks */

/**
 * One phrase, one address per network, each on that network's standard path — so the same
 * words restore in Sparrow, MetaMask, Phantom, TronLink or a Stellar wallet.
 */
export const NETWORKS = {
  bitcoin: { label: 'Bitcoin', symbol: 'tBTC', path: "m/84'/1'/0'/0/0", curve: 'secp256k1' },
  ethereum: { label: 'Ethereum', symbol: 'SepoliaETH', path: "m/44'/60'/0'/0/0", curve: 'secp256k1' },
  tron: { label: 'Tron', symbol: 'TRX', path: "m/44'/195'/0'/0/0", curve: 'secp256k1' },
  solana: { label: 'Solana', symbol: 'SOL', path: "m/44'/501'/0'/0'", curve: 'ed25519' },
  stellar: { label: 'Stellar', symbol: 'XLM', path: "m/44'/148'/0'", curve: 'ed25519' },
};

/** SLIP-0010 for ed25519: hardened steps only, which is all Solana and Stellar use. */
function ed25519Node(seed, path) {
  let I = hmac(sha512, new TextEncoder().encode('ed25519 seed'), seed);
  let key = I.slice(0, 32);
  let chain = I.slice(32);
  for (const part of path.split('/').slice(1)) {
    const index = (Number.parseInt(part, 10) >>> 0) + 0x80000000;
    const data = new Uint8Array(37);
    data.set(key, 1);
    new DataView(data.buffer).setUint32(33, index >>> 0);
    I = hmac(sha512, chain, data);
    key = I.slice(0, 32);
    chain = I.slice(32);
  }
  return key;
}

const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

const eip55 = bytes => {
  const plain = toHex(bytes);
  const hash = toHex(keccak_256(new TextEncoder().encode(plain)));
  return `0x${[...plain].map((c, i) => (Number.parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c)).join('')}`;
};

/** Stellar strkey: version byte, payload, CRC16-XModem, base32 without padding. */
function strkey(publicKey) {
  const payload = new Uint8Array(35);
  payload[0] = 6 << 3; // account id, the "G" prefix
  payload.set(publicKey, 1);
  let crc = 0;
  for (const byte of payload.subarray(0, 33)) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  payload[33] = crc & 0xff;
  payload[34] = (crc >> 8) & 0xff;
  return base32.encode(payload).replace(/=+$/, '');
}

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) + BigInt(byte);
  let out = '';
  while (value > 0n) {
    out = BASE58[Number(value % 58n)] + out;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = `1${out}`;
  }
  return out;
}

/** Every network's address for this phrase. */
export function accountsFrom(mnemonic) {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error('That is not a valid 12-word recovery phrase.');
  const seed = mnemonicToSeedSync(mnemonic);
  const master = HDKey.fromMasterSeed(seed);
  const out = {};

  for (const [id, network] of Object.entries(NETWORKS)) {
    if (network.curve === 'secp256k1') {
      const node = master.derive(network.path);
      if (id === 'bitcoin') {
        out[id] = { address: btc.p2wpkh(node.publicKey, NETWORK).address, publicKey: toHex(node.publicKey), path: network.path };
        continue;
      }
      const uncompressed = secp256k1.getPublicKey(node.privateKey, false).subarray(1);
      const hash20 = keccak_256(uncompressed).subarray(-20);
      out[id] = {
        address: id === 'ethereum' ? eip55(hash20) : base58check(sha256).encode(new Uint8Array([0x41, ...hash20])),
        publicKey: toHex(node.publicKey),
        path: network.path,
      };
      continue;
    }
    const priv = ed25519Node(seed, network.path);
    const pub = ed25519.getPublicKey(priv);
    out[id] = {
      address: id === 'solana' ? base58Encode(pub) : strkey(pub),
      publicKey: toHex(pub),
      path: network.path,
    };
    priv.fill(0);
  }
  return out;
}

/**
 * The digest of the exact transaction, computed here from the plan the server handed back.
 * It has to equal the digest that was inside the sentence the palm approved.
 */
export function planDigest({ network, from, plan }) {
  return base64urlnopad.encode(sha256(new TextEncoder().encode(
    canonicalBytes(canonicalTransaction({ chain: 'bitcoin', network, from, plan })),
  )));
}

/** Re-checks an authorisation receipt in the browser, with the same code that signed it. */
export const checkAuthorization = verifyAuthorization;

/**
 * Signs exactly the plan the palm approved: same coins, same outputs, same fee.
 *
 * Three refusals, all before a signature exists: the phrase must belong to this wallet, the
 * plan must hash to the digest the human approved, and the finished transaction's fee must
 * match the plan. Any mismatch and this returns nothing to broadcast.
 */
export function signPlan(mnemonic, plan, expectedAddress, approved = {}) {
  const { privateKey, publicKey, address } = accountFrom(mnemonic);
  if (expectedAddress && address !== expectedAddress) {
    throw new Error('That phrase belongs to a different wallet.');
  }
  if (approved.transactionHash) {
    const here = planDigest({ network: approved.network, from: address, plan });
    if (here !== approved.transactionHash) {
      throw new Error('This is not the transaction that was approved. Nothing has been signed.');
    }
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
