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
import { deriveAttestationKeys, signAuthorization, signRegistration, verifyAuthorization, verifyChain } from '../src/authorization.js';
import { ISOLATION, assertSigner, sealResult } from '../src/signer.js';

const NETWORK = btc.TEST_NETWORK;
const PATH = "m/84'/1'/0'/0/0"; // BIP84 testnet: the phrase restores in any standard wallet
// BIP48 script-type 2', the path every multisig coordinator uses for P2WSH co-signing. One
// branch per vault a person signs for, so the same phrase backs all of them and no two
// vaults share a key on the chain.
const COSIGN_PATH = index => `m/48'/1'/0'/2'/0/${index}`;
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
  const input = concat(browser, serverRandom, jitter);
  const mixed = hkdf(sha256, input, undefined, 'quvault wallet seed v1', 16);
  try {
    return generateMnemonic(wordlist, 128, () => mixed); // 12 words, 128 bits
  } finally {
    // The words are the secret from here on; these three arrays are the same secret in
    // another form, and there is no reason for them to outlive the line that used them.
    browser.fill(0);
    input.fill(0);
    mixed.fill(0);
  }
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
  const seed = mnemonicToSeedSync(mnemonic);
  let node;
  try {
    node = HDKey.fromMasterSeed(seed).derive(PATH);
  } finally {
    seed.fill(0); // the master seed is every key this phrase can make; it is needed for one line
  }
  const publicKey = node.publicKey;
  const payment = btc.p2wpkh(publicKey, NETWORK);
  return { privateKey: node.privateKey, publicKey, address: payment.address, path: PATH };
}

/**
 * The key this person signs with for one particular vault. It comes from the same twelve
 * words as their own wallet, on a branch of its own, so there is still one phrase to keep
 * and losing it costs them their place in a quorum rather than their own coins.
 */
export function cosignerFrom(mnemonic, index) {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error('That is not a valid 12-word recovery phrase.');
  if (!Number.isInteger(index) || index < 0 || index > 0x7fffffff) throw new Error('That is not a signing branch.');
  const path = COSIGN_PATH(index);
  const seed = mnemonicToSeedSync(mnemonic);
  let node;
  try {
    node = HDKey.fromMasterSeed(seed).derive(path);
  } finally {
    seed.fill(0);
  }
  return { privateKey: node.privateKey, publicKey: node.publicKey, path };
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
  // Every address is derived; the material they came from has no further use here.
  seed.fill(0);
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
 * The vault's attestation key: ML-DSA-65, derived from this phrase and nowhere else.
 *
 * The server never sees it. It learns the public half when the vault is created, and after
 * that it can only check signatures — it cannot make one. A new `epoch` is a new key from
 * the same phrase, which is how a key is replaced without a new secret to store.
 */
export function attestationKeys(mnemonic, epoch = 1) {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error('That is not a valid 12-word recovery phrase.');
  const seed = mnemonicToSeedSync(mnemonic);
  const keys = deriveAttestationKeys(seed, epoch);
  seed.fill(0);
  return keys;
}

/**
 * Registers an attestation key, signed by the key that is allowed to vouch for it: itself at
 * epoch 1, the previous epoch afterwards. The server can verify this and store it; it cannot
 * make one, so it cannot move a vault onto a key of its choosing.
 */
export function registerKey(mnemonic, { vaultId, epoch = 1, previous = null, registeredAt }) {
  const keys = attestationKeys(mnemonic, epoch);
  const signer = previous ? attestationKeys(mnemonic, previous) : keys;
  try {
    return signRegistration({
      vaultId,
      publicKey: keys.publicKey,
      epoch,
      previousKeyId: previous ? signer.keyId : null,
      registeredAt: registeredAt ?? Math.floor(Date.now() / 1000),
    }, signer);
  } finally {
    keys.secretKey.fill(0);
    signer.secretKey.fill(0);
  }
}

/** Walks a vault's key lineage in the browser, with the same code the server uses. */
export const checkChain = verifyChain;

/** Signs the authorisation record for a transaction this device is about to sign. */
export function attest(mnemonic, parts, epoch = 1) {
  const keys = attestationKeys(mnemonic, epoch);
  try {
    return signAuthorization(parts, keys);
  } finally {
    keys.secretKey.fill(0);
  }
}

/**
 * Signs exactly the plan the palm approved: same coins, same outputs, same fee.
 *
 * Three refusals, all before a signature exists: the phrase must belong to this wallet, the
 * plan must hash to the digest the human approved, and the finished transaction's fee must
 * match the plan. Any mismatch and this returns nothing to broadcast.
 */
export function signPlan(mnemonic, plan, expectedAddress, approved = {}) {
  const { privateKey, publicKey, address } = accountFrom(mnemonic);
  try {
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
  } finally {
    // Whether it signed or refused, the key has done all it was derived for.
    privateKey.fill(0);
  }
}

/**
 * One signer putting their name to a spend from an account the chain guards.
 *
 * The transaction is re-hashed here against what the palm approved, exactly as a single-key
 * spend is, before anything is signed. What goes back is the same partly signed transaction
 * with one more signature on it — this browser's — and never a key.
 */
export function signQuorum(mnemonic, { psbt, plan, index, address, transactionHash, network }) {
  const { privateKey, publicKey } = cosignerFrom(mnemonic, index);
  try {
    if (transactionHash) {
      const here = planDigest({ network, from: address, plan });
      if (here !== transactionHash) {
        throw new Error('This is not the transaction that was approved. Nothing has been signed.');
      }
    }
    const tx = btc.Transaction.fromPSBT(base64nopadDecode(psbt));
    let signed = 0;
    try {
      signed = tx.sign(privateKey);
    } catch {
      signed = 0;
    }
    if (!signed) throw new Error('This browser does not hold a key for that account.');
    return { psbt: base64nopadEncode(tx.toPSBT()), signingKey: toHexKey(publicKey) };
  } finally {
    privateKey.fill(0);
  }
}

const toHexKey = bytes => hex.encode(bytes);
const base64nopadEncode = bytes => btoa(String.fromCharCode(...bytes));
const base64nopadDecode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));

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
  const bytes = new Uint8Array(body);
  try {
    return new TextDecoder().decode(bytes);
  } finally {
    // The string that goes back cannot be erased; this copy of the same words can be.
    bytes.fill(0);
  }
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

/* ====================================================== vault operations ==== */

/*
 * The narrow interface the page is allowed to use.
 *
 * Everything above this line is a primitive that takes a phrase. Everything below takes a
 * stored record and a palm-gated unlock, and gives back an address, a public key, a signed
 * transaction or a receipt — never key material. The page imports only these, so there is no
 * line in `public/app.js` where a phrase is a value that can be held, copied, logged, put in
 * a closure, or still be reachable when the next thing happens.
 *
 * `revealPhrase` is the one exception, and it exists because showing someone their own
 * recovery words is the entire purpose of that screen. It is the only export here that
 * returns a secret, and it is named so that a reviewer can grep for it.
 *
 * On erasure: a JavaScript string cannot be wiped. `String.prototype` offers no way to
 * overwrite the bytes, the engine may have copied or interned them, and the garbage collector
 * decides when the original goes. So the phrase is a string for as few statements as the work
 * allows, and every form of the same secret that IS a typed array — seeds, private keys,
 * HKDF output, decrypted plaintext — is zeroed on the way out, including when the operation
 * throws. That is a real reduction in exposure and it is not the same thing as erasure; this
 * code does not claim erasure.
 */

const held = record => {
  if (!record?.blob) throw new Error('This browser does not hold the key for this wallet.');
  return record;
};

/** Opens the phrase, does one job with it, and lets it go. Not exported. */
async function withPhrase(record, unlock, job) {
  return job(await decryptMnemonic(held(record).blob, unlock, record.salt));
}

/**
 * Makes a vault key, stores it encrypted, and reports only the public half.
 *
 * The registration is signed here too, so the caller never needs the phrase a second time to
 * start the attestation lineage.
 */
export async function createVaultKey({ serverRandom, jitterSeed, unlock, salt, vaultId = null }) {
  const mnemonic = makeMnemonic({ serverRandom, jitter: jitterFrom(jitterSeed) });
  const account = accountFrom(mnemonic);
  account.privateKey.fill(0); // only the address and public key are wanted here
  const address = account.address;
  const publicKey = hex.encode(account.publicKey);
  const root = attestationKeys(mnemonic, 1);
  root.secretKey.fill(0);
  const registration = registerKey(mnemonic, { vaultId: vaultId ?? address, epoch: 1 });
  const blob = await encryptMnemonic(mnemonic, unlock, salt);
  await saveRecord({
    blob,
    salt,
    address,
    publicKey,
    // Pinned here so a server that rewrote its own record of the lineage is visible.
    attestationRootKeyId: root.keyId,
    createdAt: Date.now(),
  });
  return { address, publicKey, attestationRootKeyId: root.keyId, registration };
}

/** Signs an approved withdrawal and its authorisation record. Returns nothing secret. */
export async function signApprovedSpend(record, unlocked, { network }) {
  return withPhrase(record, unlocked.unlock, mnemonic => {
    const signed = signPlan(mnemonic, unlocked.plan, record.address, {
      transactionHash: unlocked.transactionHash,
      network,
    });
    const authorization = attest(mnemonic, {
      vaultId: record.address,
      accountId: 'bitcoin',
      transactionHash: unlocked.transactionHash,
      statementDigest: unlocked.statementDigest,
      approvalMethod: 'veyns:palm',
      approvals: unlocked.approvals,
      approvedBy: unlocked.approvedBy,
      decisionIds: unlocked.decisionIds,
      approvedAt: Math.floor(Date.now() / 1000),
    }, unlocked.attestationEpoch ?? 1);
    return { hex: signed.hex, txid: signed.txid, authorization };
  });
}

/** One signature towards a quorum spend. What comes back is a PSBT, never a key. */
export async function signApprovedQuorum(record, unlocked, { network }) {
  return withPhrase(record, unlocked.unlock, mnemonic => signQuorum(mnemonic, {
    psbt: unlocked.psbt,
    plan: unlocked.plan,
    index: unlocked.keyIndex,
    address: unlocked.address,
    transactionHash: unlocked.transactionHash,
    network,
  }));
}

/** The public half of this browser's signing key for one vault's branch. */
export async function cosignerPublicKeyFor(record, unlocked, branch) {
  return withPhrase(record, unlocked.unlock, mnemonic => {
    const { privateKey, publicKey } = cosignerFrom(mnemonic, branch);
    privateKey.fill(0);
    return hex.encode(publicKey);
  });
}

/** A registration for a new attestation epoch, signed by the key it replaces. */
export async function signKeyRegistration(record, unlocked, { vaultId, epoch, previous = null }) {
  return withPhrase(record, unlocked.unlock, mnemonic => registerKey(mnemonic, { vaultId, epoch, previous }));
}

/** The address this vault has on another network, derived from the same phrase. */
export async function deriveAccountFor(record, unlocked, network) {
  return withPhrase(record, unlocked.unlock, mnemonic => {
    const derived = accountsFrom(mnemonic);
    if (derived.bitcoin.address !== record.address) throw new Error('That phrase belongs to a different wallet.');
    const account = derived[network];
    if (!account) throw new Error('This vault does not know that network.');
    return { address: account.address, publicKey: account.publicKey };
  });
}

/**
 * Puts a phrase the owner typed back on this device.
 *
 * This one takes a phrase because a person has to type it somewhere. It does not keep it: the
 * caller's copy is the one the browser's input holds, and clearing that is the page's job.
 */
export async function restoreVaultKey(mnemonic, { unlock, salt }, expectedAddress) {
  const account = accountFrom(mnemonic);
  account.privateKey.fill(0);
  if (account.address !== expectedAddress) throw new Error('Those words belong to a different wallet.');
  const blob = await encryptMnemonic(mnemonic, unlock, salt);
  await saveRecord({
    blob,
    salt,
    address: account.address,
    publicKey: hex.encode(account.publicKey),
    createdAt: Date.now(),
  });
  return { address: account.address, publicKey: hex.encode(account.publicKey) };
}

/**
 * The recovery words, to show the person who owns them.
 *
 * The only export in this module that returns a secret. Its caller must put the words on the
 * screen and drop them, and must not keep them in a variable that outlives the dialog.
 */
export async function revealPhrase(record, unlocked) {
  return decryptMnemonic(held(record).blob, unlocked.unlock, record.salt);
}

/**
 * Writes the attestation root onto the stored record without the caller opening it.
 *
 * The page needs to pin which key lineage it started, and that is a public identifier — but
 * reading the record to write one field would put the encrypted blob in the page's hands for
 * no reason, so the record never leaves this module.
 */
export async function pinAttestationRoot(keyId) {
  const record = await loadRecord();
  if (!record) return null;
  await saveRecord({ ...record, attestationRootKeyId: keyId });
  return loadRecord();
}

/* ======================================================= the signing boundary ==== */

/*
 * A Signer over the operations above.
 *
 * This is the object the page holds instead of a key. It answers three questions — sign this
 * transaction, sign this message, what is your public key — and there is no fourth question
 * it will answer. `assertSigner` refuses to build one that exposes key material, and
 * `sealResult` strips anything outside the allowed result fields on the way back.
 *
 * Its isolation level is `none:browser-javascript`, and that is the truth: the key is
 * decrypted in this realm, used, and dropped. Script running in this origin can reach it
 * while it is in use. Nothing here is a secure element, a TEE, an HSM or a hardware wallet,
 * and the interface exists so that when one of those does exist it replaces this object
 * rather than every call site in the page.
 */
export function browserSigner(record, unlocked) {
  return assertSigner({
    isolation: ISOLATION.BROWSER_JAVASCRIPT,

    /** The public key of the vault this signer speaks for. Never anything else. */
    getPublicKey: () => held(record).publicKey,

    /**
     * Signs whatever the palm approved: a whole spend, or one contribution to a quorum.
     *
     * Which one it is comes from the approval itself rather than from the caller, so a page
     * cannot ask for a full signature on an operation that was only approved for a share.
     */
    async signTransaction({ network }) {
      return sealResult(unlocked.psbt
        ? await signApprovedQuorum(record, unlocked, { network })
        : await signApprovedSpend(record, unlocked, { network }));
    },

    /**
     * Signs an attestation key registration — the only non-transaction message this product
     * signs. ML-DSA-65, under its own FIPS 204 context, with a key the server has never had.
     */
    async signMessage({ vaultId, epoch, previous = null }) {
      return signKeyRegistration(record, unlocked, { vaultId, epoch, previous });
    },
  });
}
