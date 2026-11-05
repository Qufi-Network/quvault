/*
 * A vault Bitcoin itself will not let anyone spend without a palm.
 *
 * Bitcoin cannot see a palm. It checks signatures and time, so that is what this vault is made
 * of. The coins sit behind a Taproot output with exactly two ways out:
 *
 *   normal    the palm key AND m of the n signers       at any time
 *   recovery  m of the n signers                        only once the coins have sat unmoved
 *                                                       for `delay` blocks
 *
 * The palm key belongs to the palm signer (src/palm-signer.js), which signs only after it has
 * checked real palm decisions bound to the exact transaction. The key path is closed: the
 * internal key is BIP341's provably unspendable point, so there is no third way out. With the
 * twelve words alone, the normal path is impossible and the recovery path is slow and public.
 *
 * Both scripts are written byte for byte as miniscript compiles them, so the vault is an
 * ordinary output descriptor:
 *
 *   tr(H,{and_v(v:pk(PALM),multi_a(m,K1,…,Kn)),and_v(v:older(delay),multi_a(m,K1,…,Kn))})
 *
 * Bitcoin Core or any descriptor wallet can import it. That is what lets the signers recover
 * without QuVault: the descriptor is everything a wallet needs to rebuild both scripts and
 * spend through the recovery path. It must be handed to every signer when the vault is made.
 */
import * as btc from '@scure/btc-signer';
import { hex, base64 } from '@scure/base';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { NETWORK, WalletError } from './bitcoin-common.js';

/** BIP341's H: a point nobody knows the private key of, so the key path can never be used. */
export const NUMS_KEY = btc.TAPROOT_UNSPENDABLE_KEY;
export const LEAF_VERSION = 0xc0;
export const MAX_SIGNERS = 20;
/** A relative timelock counted in blocks tops out at 65535, about 455 days. */
export const MAX_DELAY = 0xffff;
/** About one year of blocks. */
export const DEFAULT_RECOVERY_DELAY = 52560;
export const PATHS = ['normal', 'recovery'];
/** Bitcoin makes about 144 blocks a day. */
export const BLOCKS_PER_DAY = 144;
/**
 * The recovery delays a vault can be made with, in days. Shorter is a faster inheritance and less
 * time to stop a thief who has the twelve words; longer is the reverse.
 */
export const RECOVERY_CHOICES = [90, 180, 365];
export const delayForDays = days => days * BLOCKS_PER_DAY;
export const daysOfDelay = blocks => Math.round(blocks / BLOCKS_PER_DAY);

const P2TR_DUST = 330;
const SCHNORR_SIG = 64; // SIGHASH_DEFAULT: no sighash byte
const EMPTY = new Uint8Array(0);

const equalBytes = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);
const decodeHex = value => {
  try {
    return hex.decode(String(value).toLowerCase());
  } catch {
    return null;
  }
};

/** A public key in the 32-byte x-only form Taproot uses. Takes compressed or x-only, hex or bytes. */
export function xOnlyKey(value) {
  const bytes = typeof value === 'string' ? decodeHex(value) : value instanceof Uint8Array ? value : null;
  const x = bytes?.length === 33 && (bytes[0] === 2 || bytes[0] === 3) ? bytes.slice(1)
    : bytes?.length === 32 ? Uint8Array.from(bytes)
      : null;
  if (!x) throw new WalletError('That is not a public key.');
  try {
    secp256k1.Point.fromHex(`02${hex.encode(x)}`);
  } catch {
    throw new WalletError('That public key is not a point on the curve.');
  }
  return x;
}

/* ------------------------------------------------------------- the scripts */

const multiA = (required, keys) =>
  [keys[0], 'CHECKSIG', ...keys.slice(1).flatMap(key => [key, 'CHECKSIGADD']), required, 'NUMEQUAL'];

function leafScripts(palmKey, keys, required, delay) {
  return {
    // and_v(v:pk(PALM),multi_a(m,…)): the palm signature is checked first and must be valid.
    normal: btc.Script.encode([palmKey, 'CHECKSIGVERIFY', ...multiA(required, keys)]),
    // and_v(v:older(delay),multi_a(m,…)): Bitcoin refuses it until the coins are old enough.
    recovery: btc.Script.encode([delay, 'CHECKSEQUENCEVERIFY', 'VERIFY', ...multiA(required, keys)]),
  };
}

const taggedHash = (tag, ...parts) => {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, ...parts));
};
// Plain bytes rather than Buffer, so the browser can rebuild a vault with this same module.
const concatBytes = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};
const compactSize = n => (n < 0xfd ? Uint8Array.of(n)
  : n <= 0xffff ? Uint8Array.of(0xfd, n & 0xff, n >> 8)
    : Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff));

/** BIP341 leaf hash: what a script-path signature commits to. */
export const tapLeafHash = script =>
  taggedHash('TapLeaf', Uint8Array.of(LEAF_VERSION), compactSize(script.length), script);

/* ------------------------------------------------------------- the vault */

/**
 * The vault for one palm key and one set of signers. The same people, threshold and delay
 * always make the same address, whatever order the keys arrive in.
 */
export function palmVaultOf({ palmKey, signerKeys, required, delay = DEFAULT_RECOVERY_DELAY, network = NETWORK }) {
  const palm = xOnlyKey(palmKey);
  const keys = (Array.isArray(signerKeys) ? signerKeys : []).map(xOnlyKey);
  if (!keys.length) throw new WalletError('A palm vault needs at least one signer.');
  if (keys.length > MAX_SIGNERS) throw new WalletError(`A palm vault takes at most ${MAX_SIGNERS} signers.`);
  const ordered = keys.map(key => hex.encode(key)).sort();
  if (new Set(ordered).size !== ordered.length) throw new WalletError('The same key appears twice in this vault.');
  if (ordered.includes(hex.encode(palm))) throw new WalletError('The palm key cannot also be a signer key.');
  if (!Number.isInteger(required) || required < 1 || required > keys.length) {
    throw new WalletError(`A vault of ${keys.length} signer${keys.length === 1 ? '' : 's'} needs between one and ${keys.length} signatures.`);
  }
  if (!Number.isInteger(delay) || delay < 1 || delay > MAX_DELAY) {
    throw new WalletError(`The recovery delay must be between 1 and ${MAX_DELAY} blocks.`);
  }

  const sorted = ordered.map(key => hex.decode(key));
  const scripts = leafScripts(palm, sorted, required, delay);
  const out = btc.p2tr(NUMS_KEY, [{ script: scripts.normal }, { script: scripts.recovery }], network, true);
  const leafOf = script => {
    const entry = out.tapLeafScript.find(([, withVersion]) => equalBytes(withVersion.subarray(0, -1), script));
    return { script, controlBlock: entry[0], leafHash: tapLeafHash(script) };
  };
  return {
    palmKey: palm,
    keys: sorted,
    required,
    delay,
    network,
    address: out.address,
    script: out.script,
    tapInternalKey: out.tapInternalKey,
    leaves: { normal: leafOf(scripts.normal), recovery: leafOf(scripts.recovery) },
    descriptor: descriptorOf({ palmKey: palm, keys: sorted, required, delay }),
  };
}

/* ------------------------------------------------------------- the descriptor */

const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
// Bitcoin Core's descriptor.cpp PolyMod. Each is the one before times 2, per 5-bit coefficient,
// in GF(32) mod x^5+x^3+1; the tests check that, and the proof checks against `getdescriptorinfo`.
const GENERATOR = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

function polymod(symbols) {
  let chk = 1n;
  for (const value of symbols) {
    const top = chk >> 35n;
    chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(value);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= GENERATOR[i];
  }
  return chk;
}

/** BIP380 descriptor checksum: the eight characters after `#`. */
export function descriptorChecksum(descriptor) {
  const symbols = [];
  let groups = [];
  for (const char of descriptor) {
    const value = INPUT_CHARSET.indexOf(char);
    if (value < 0) throw new WalletError('That descriptor holds a character no descriptor can hold.');
    symbols.push(value & 31);
    groups.push(value >> 5);
    if (groups.length === 3) {
      symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
      groups = [];
    }
  }
  if (groups.length === 1) symbols.push(groups[0]);
  else if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
  const chk = polymod([...symbols, 0, 0, 0, 0, 0, 0, 0, 0]) ^ 1n;
  return [...Array(8).keys()].map(i => CHECKSUM_CHARSET[Number((chk >> BigInt(5 * (7 - i))) & 31n)]).join('');
}

function descriptorOf({ palmKey, keys, required, delay }) {
  const list = keys.map(key => hex.encode(key)).join(',');
  const body = `tr(${hex.encode(NUMS_KEY)},{and_v(v:pk(${hex.encode(palmKey)}),multi_a(${required},${list})),`
    + `and_v(v:older(${delay}),multi_a(${required},${list}))})`;
  return `${body}#${descriptorChecksum(body)}`;
}

const DESCRIPTOR = /^tr\(([0-9a-f]{64}),\{and_v\(v:pk\(([0-9a-f]{64})\),multi_a\((\d{1,2}),([0-9a-f,]+)\)\),and_v\(v:older\((\d{1,5})\),multi_a\((\d{1,2}),([0-9a-f,]+)\)\)\}\)#([a-z0-9]{8})$/;

/**
 * The vault a descriptor describes, from the descriptor alone: what an heir with the inheritance
 * sheet has. Only a palm vault exactly as this module writes it is read, and it is rebuilt and
 * written out again and must come back character for character, so a descriptor that reads but
 * means something else is refused rather than half understood.
 */
export function palmVaultFromDescriptor(descriptor, network = NETWORK) {
  const text = String(descriptor ?? '').trim().replace(/\s+/g, '').toLowerCase();
  const m = text.match(DESCRIPTOR);
  if (!m) throw new WalletError('That is not a Palm vault description. Copy it exactly as the inheritance sheet shows it.');
  const [, internal, palmKey, requiredA, listA, delay, requiredB, listB, checksum] = m;
  if (descriptorChecksum(text.slice(0, -9)) !== checksum) {
    throw new WalletError('That vault description has a typing mistake in it: its checksum does not match.');
  }
  if (internal !== hex.encode(NUMS_KEY) || requiredA !== requiredB || listA !== listB) {
    throw new WalletError('That is not a Palm vault description.');
  }
  const vault = palmVaultOf({
    palmKey, signerKeys: listA.split(','), required: Number(requiredA), delay: Number(delay), network,
  });
  if (vault.descriptor !== text) throw new WalletError('That vault description is not written the way a Palm vault is.');
  return vault;
}

/**
 * When the recovery path opens for each coin. A coin can be spent through it in the first block
 * whose height is at least the coin's height plus the delay (BIP68), so with the chain at `tip`
 * the next block is tip + 1, and a coin is ready when that block would be late enough.
 */
export function recoveryClock(vault, utxos, tip) {
  const coins = (utxos ?? []).filter(coin => Number.isInteger(coin.height) && coin.height > 0).map(coin => {
    const opensAt = coin.height + vault.delay;
    const blocksLeft = Math.max(0, opensAt - (tip + 1));
    return {
      txid: coin.txid, vout: coin.vout, value: coin.value, height: coin.height,
      opensAt, blocksLeft, daysLeft: Math.ceil(blocksLeft / BLOCKS_PER_DAY), ready: blocksLeft === 0,
    };
  }).sort((a, b) => a.opensAt - b.opensAt);
  const next = coins[0] ?? null;
  return {
    tip,
    delay: vault.delay,
    delayDays: daysOfDelay(vault.delay),
    coins,
    nextOpensAt: next?.opensAt ?? null,
    blocksLeft: next?.blocksLeft ?? null,
    daysLeft: next?.daysLeft ?? null,
    readySats: coins.filter(c => c.ready).reduce((sum, c) => sum + c.value, 0),
  };
}

/* ------------------------------------------------------------- planning a spend */

const witnessItem = length => compactSize(length).length + length;

/**
 * What one input costs, in vbytes, spent through `path`. Counted from the witness the
 * finaliser below really writes: a signature or an empty slot per signer, the palm signature
 * on the normal path, then the script and its control block.
 */
export function palmInputVsize(vault, path = 'normal') {
  const leaf = vault.leaves[path];
  if (!leaf) throw new WalletError('A palm vault is spent through the normal or the recovery path.');
  const n = vault.keys.length;
  const items = n + (path === 'normal' ? 1 : 0) + 2;
  const witness = compactSize(items).length
    + vault.required * witnessItem(SCHNORR_SIG)
    + (n - vault.required) * witnessItem(0)
    + (path === 'normal' ? witnessItem(SCHNORR_SIG) : 0)
    + witnessItem(leaf.script.length)
    + witnessItem(33 + 32 * leaf.controlBlock.merklePath.length);
  return 41 + witness / 4;
}

const outputScriptOf = (address, network) => {
  try {
    return btc.OutScript.encode(btc.Address(network).decode(String(address)));
  } catch {
    throw new WalletError('That is not a valid address on this network.');
  }
};
const addressOfScript = (script, network) => btc.Address(network).encode(btc.OutScript.decode(script));

/**
 * Chooses coins (largest first) and returns the plan: the exact inputs, outputs and fee the
 * palms will approve. `amountSats` may be 'max' to sweep. Change goes back to the vault.
 */
export function planPalmSpend({ vault, utxos, toAddress, amountSats, feeRate, path = 'normal' }) {
  const network = vault.network;
  const toScript = outputScriptOf(toAddress, network);
  if (!utxos?.length) throw new WalletError('No confirmed coins in this vault yet.');
  const rate = Math.max(1, Math.round(feeRate));
  const inputVsize = palmInputVsize(vault, path);
  const outputVsize = script => 8 + witnessItem(script.length);
  const vsizeOf = (inputs, scripts) => Math.ceil(10.5 + inputs * inputVsize + scripts.reduce((sum, s) => sum + outputVsize(s), 0));
  const coins = [...utxos].sort((a, b) => b.value - a.value);
  const sum = list => list.reduce((total, coin) => total + coin.value, 0);
  const planOf = (chosen, outputs, feeSats) => ({
    inputs: chosen.map(coin => ({ txid: coin.txid, index: coin.vout, value: coin.value })),
    outputs,
    feeSats,
    feeRate: rate,
    sentSats: outputs.filter(o => o.address !== vault.address).reduce((total, o) => total + o.sats, 0),
    changeSats: outputs.filter(o => o.address === vault.address).reduce((total, o) => total + o.sats, 0),
  });

  if (amountSats === 'max') {
    const feeSats = vsizeOf(coins.length, [toScript]) * rate;
    const sats = sum(coins) - feeSats;
    if (sats < P2TR_DUST) throw new WalletError('The balance is too small to cover the fee.');
    return planOf(coins, [{ address: toAddress, sats }], feeSats);
  }
  const amount = Number(amountSats);
  if (!Number.isInteger(amount) || amount < P2TR_DUST) throw new WalletError(`Send at least ${P2TR_DUST} satoshis.`);
  for (let i = 1; i <= coins.length; i++) {
    const chosen = coins.slice(0, i);
    const have = sum(chosen);
    const feeWithChange = vsizeOf(i, [toScript, vault.script]) * rate;
    const change = have - amount - feeWithChange;
    if (change >= P2TR_DUST) {
      return planOf(chosen, [{ address: toAddress, sats: amount }, { address: vault.address, sats: change }], feeWithChange);
    }
    // Too little left over for a change output: the remainder is absorbed by the fee.
    if (have - amount - vsizeOf(i, [toScript]) * rate >= 0) return planOf(chosen, [{ address: toAddress, sats: amount }], have - amount);
  }
  throw new WalletError('Not enough coins for that amount plus the fee.');
}

/* ------------------------------------------------------------- the transaction */

const readPsbt = psbt => {
  try {
    return btc.Transaction.fromPSBT(base64.decode(String(psbt)), { allowUnknownInputs: true });
  } catch {
    throw new WalletError('That is not a readable partly signed transaction.');
  }
};

/** The unsigned transaction for an approved plan, every input spending through `path`. */
export function palmVaultPsbt(vault, plan, { path = 'normal' } = {}) {
  const leaf = vault.leaves[path];
  if (!leaf) throw new WalletError('A palm vault is spent through the normal or the recovery path.');
  // Version 2, so the relative timelock on the recovery path is enforced (BIP68).
  const tx = new btc.Transaction({ version: 2, allowUnknownInputs: true });
  for (const input of plan.inputs) {
    tx.addInput({
      txid: hex.decode(input.txid),
      index: input.index,
      witnessUtxo: { script: vault.script, amount: BigInt(input.value) },
      tapInternalKey: vault.tapInternalKey,
      tapLeafScript: [[leaf.controlBlock, Uint8Array.from([...leaf.script, LEAF_VERSION])]],
      ...(path === 'recovery' ? { sequence: vault.delay } : {}),
    });
  }
  for (const output of plan.outputs) tx.addOutputAddress(output.address, BigInt(output.sats), vault.network);
  return base64.encode(tx.toPSBT());
}

/** One key adding its signature, with Taproot's default sighash only: it covers every output. */
export function signPalmPsbt(psbt, privateKey) {
  const tx = readPsbt(psbt);
  let signed = 0;
  try {
    signed = tx.sign(new Uint8Array(privateKey), [btc.SigHash.DEFAULT]);
  } catch {
    signed = 0;
  }
  if (!signed) throw new WalletError('That key does not sign for this vault.');
  return base64.encode(tx.toPSBT());
}

/**
 * Which of `signerKeys` have signed every input through the normal path. The palm key is not a
 * signer and is never counted. Keys come back in the form they were given (the account stores
 * compressed keys), sorted.
 */
export function palmSignersOf(vault, psbt, signerKeys) {
  const tx = readPsbt(psbt);
  const { leafHash, script } = vault.leaves.normal;
  // A signature counts only if it verifies: over this input's sighash, through the palm path,
  // with SIGHASH_DEFAULT. Sixty-four random bytes are not a signature, whoever sent them.
  const scripts = [];
  const amounts = [];
  for (let i = 0; i < tx.inputsLength; i++) {
    const utxo = tx.getInput(i).witnessUtxo;
    scripts.push(utxo?.script ?? vault.script);
    amounts.push(utxo?.amount ?? 0n);
  }
  const perInput = [];
  for (let i = 0; i < tx.inputsLength; i++) {
    let message = null;
    try {
      message = tx.preimageWitnessV1(i, scripts, btc.SigHash.DEFAULT, amounts, undefined, script, LEAF_VERSION);
    } catch {
      message = null;
    }
    perInput.push(new Set((tx.getInput(i).tapScriptSig ?? [])
      .filter(([meta, sig]) => message && equalBytes(meta.leafHash, leafHash) && sig.length === SCHNORR_SIG
        && (() => { try { return schnorr.verify(sig, message, meta.pubKey); } catch { return false; } })())
      .map(([meta]) => hex.encode(meta.pubKey))));
  }
  if (!perInput.length) return [];
  return signerKeys
    .filter(key => perInput.every(set => set.has(hex.encode(xOnlyKey(key)))))
    .sort();
}

/** Puts signers' work on one palm vault spend together. Work for another transaction is refused. */
export function combinePalmPsbts(psbts) {
  const [first, ...rest] = psbts.map(readPsbt);
  if (!first) throw new WalletError('There is nothing to put together.');
  for (const part of rest) {
    try {
      first.combine(part);
    } catch (error) {
      throw new WalletError(`Those signatures are not for this transaction: ${error.message}`);
    }
  }
  return base64.encode(first.toPSBT());
}

/** Which path every input spends through, or null when they disagree or are not this vault's. */
export function palmPathOf(vault, psbt) {
  const tx = readPsbt(psbt);
  const paths = new Set();
  for (let i = 0; i < tx.inputsLength; i++) {
    const leaves = tx.getInput(i).tapLeafScript ?? [];
    if (leaves.length !== 1) return null;
    const script = leaves[0][1].subarray(0, -1);
    const path = PATHS.find(name => equalBytes(script, vault.leaves[name].script));
    if (!path) return null;
    paths.add(path);
  }
  return paths.size === 1 ? [...paths][0] : null;
}

/** The plan a transaction actually carries, read from the transaction itself. */
export function planOfPalmPsbt(vault, psbt) {
  const tx = readPsbt(psbt);
  const inputs = [];
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    if (!input.witnessUtxo || !equalBytes(input.witnessUtxo.script, vault.script)) {
      throw new WalletError('An input of that transaction is not this vault\'s.');
    }
    if (input.sighashType !== undefined && input.sighashType !== btc.SigHash.DEFAULT) {
      throw new WalletError('An input asks for a signature that would not cover every output.');
    }
    inputs.push({ txid: hex.encode(input.txid), index: input.index, value: Number(input.witnessUtxo.amount) });
  }
  const outputs = [...Array(tx.outputsLength).keys()].map(i => {
    const output = tx.getOutput(i);
    return { address: addressOfScript(output.script, vault.network), sats: Number(output.amount) };
  });
  const feeSats = inputs.reduce((total, input) => total + input.value, 0) - outputs.reduce((total, o) => total + o.sats, 0);
  if (feeSats < 0) throw new WalletError('That transaction spends more than it has.');
  return { inputs, outputs, feeSats };
}

/**
 * The finished transaction. Written out slot by slot rather than left to the library,
 * because Taproot multisig needs an empty slot for every signer who did not sign, in key
 * order, and the palm signature on top: the witness is a stack and the script reads the palm
 * first. Exactly m signer signatures go in; NUMEQUAL fails on more or fewer.
 */
export function finalizePalmPsbt(vault, psbt) {
  const tx = readPsbt(psbt);
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    if (input.tapLeafScript?.length !== 1) throw new WalletError('Each input must name exactly one spending path.');
    const [controlBlock, withVersion] = input.tapLeafScript[0];
    const script = withVersion.subarray(0, -1);
    const path = PATHS.find(name => equalBytes(script, vault.leaves[name].script));
    if (!path) throw new WalletError('That input does not spend this vault.');
    const leafHash = vault.leaves[path].leafHash;
    const signatureOf = key => (input.tapScriptSig ?? [])
      .find(([meta]) => equalBytes(meta.pubKey, key) && equalBytes(meta.leafHash, leafHash))?.[1];

    let used = 0;
    const slots = vault.keys.map(key => {
      const signature = used < vault.required ? signatureOf(key) : undefined;
      if (!signature) return EMPTY;
      used++;
      return signature;
    });
    if (used < vault.required) {
      throw new WalletError(`This needs ${vault.required} signer signature${vault.required === 1 ? '' : 's'} and has ${used}.`);
    }
    const stack = [...slots].reverse();
    if (path === 'normal') {
      const palm = signatureOf(vault.palmKey);
      if (!palm) throw new WalletError('The palm key has not signed, so Bitcoin will refuse this spend.');
      stack.push(palm);
    }
    tx.updateInput(i, { finalScriptWitness: [...stack, script, btc.TaprootControlBlock.encode(controlBlock)] }, true);
  }
  return { hex: tx.hex, txid: tx.id, vsize: tx.vsize };
}
