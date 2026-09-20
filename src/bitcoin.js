/*
 * Wallet keys and transactions. One native-segwit (bech32) address per person on testnet4.
 *
 * A spend is planned first: exact inputs, exact outputs, exact fee. The plan is what the
 * person approves with their palm, and the plan alone is what gets signed afterwards —
 * coin selection never runs again, so the signed transaction cannot drift from the approval.
 */
import crypto from 'node:crypto';
import * as btc from '@scure/btc-signer';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex, base64 } from '@scure/base';

// testnet4 shares address formats and version bytes with the older test network.
export const NETWORK = btc.TEST_NETWORK;
const DUST_SATS = 294n;

export class WalletError extends Error {}

export function createKey() {
  for (;;) {
    const key = crypto.randomBytes(32);
    try {
      secp256k1.getPublicKey(key, true);
      return key;
    } catch {
      // 1 in ~2^128: try again.
    }
  }
}

export const publicKeyOf = privateKey => Buffer.from(secp256k1.getPublicKey(privateKey, true));
export const addressOf = publicKey => btc.p2wpkh(new Uint8Array(publicKey), NETWORK).address;
const scriptOf = publicKey => btc.p2wpkh(new Uint8Array(publicKey), NETWORK).script;

export function isValidAddress(address) {
  try {
    btc.Address(NETWORK).decode(String(address));
    return true;
  } catch {
    return false;
  }
}

const addressOfScript = script => btc.Address(NETWORK).encode(btc.OutScript.decode(script));

/*
 * A quorum the chain itself keeps.
 *
 * The coins sit in a P2WSH output holding an ordinary m-of-n script, which every wallet and
 * every explorer understands, and which holds whether or not this server is running. Keys
 * are ordered lexicographically (BIP67) so that the same people always derive the same
 * address, whichever of them derives it, and so that the order nobody agreed on cannot
 * quietly become a different vault.
 */
export const MAX_KEYS = 15; // OP_CHECKMULTISIG counts no higher

const asKey = value => {
  const bytes = typeof value === 'string' ? tryHex(value) : new Uint8Array(value);
  if (bytes?.length !== 33 || (bytes[0] !== 2 && bytes[0] !== 3)) {
    throw new WalletError('That is not a compressed public key.');
  }
  return bytes;
};

const tryHex = value => {
  try {
    return hex.decode(value.toLowerCase());
  } catch {
    return null;
  }
};

export function multisigOf(publicKeys, required) {
  const keys = (Array.isArray(publicKeys) ? publicKeys : []).map(asKey);
  if (keys.length < 2) throw new WalletError('A quorum needs at least two keys.');
  if (keys.length > MAX_KEYS) throw new WalletError(`A quorum takes at most ${MAX_KEYS} keys.`);
  if (!Number.isInteger(required) || required < 1 || required > keys.length) {
    throw new WalletError(`A quorum of ${keys.length} keys needs between one and ${keys.length} signatures.`);
  }
  const ordered = keys.map(k => hex.encode(k)).sort();
  if (new Set(ordered).size !== ordered.length) throw new WalletError('The same key appears twice in this quorum.');
  return btc.p2wsh(btc.p2ms(required, ordered.map(k => hex.decode(k))), NETWORK);
}

export const multisigAddressOf = (publicKeys, required) => multisigOf(publicKeys, required).address;

/** What a vault's coins are locked to: one key, or a quorum of them. */
export function lockOf({ publicKey, publicKeys, required } = {}) {
  if (required === undefined || required === null) {
    return { address: addressOf(publicKey), script: scriptOf(publicKey), required: null };
  }
  const wsh = multisigOf(publicKeys, required);
  return { address: wsh.address, script: wsh.script, witnessScript: wsh.witnessScript, required };
}

/*
 * What one input costs to spend, in vbytes. A single-key input carries a signature and a
 * public key; a quorum carries one signature per required palm and the script itself. The
 * arithmetic is here rather than a constant because the answer moves with the threshold,
 * and a test signs a real transaction to check this has not drifted from the truth.
 */
function inputVsize(lock) {
  if (!lock.required) return 68;
  const script = lock.witnessScript.length;
  const witness = 2 + 73 * lock.required + (script < 253 ? 1 : 3) + script;
  return 41 + Math.ceil(witness / 4);
}

/**
 * Chooses coins and returns the plan. `amountSats` may be 'max' to sweep everything.
 * Throws WalletError with a plain message when the balance or fee does not work out.
 */
export function planSpend({ publicKey, publicKeys, required, utxos, toAddress, amountSats, feeRate }) {
  if (!isValidAddress(toAddress)) throw new WalletError('That is not a valid testnet4 address.');
  if (!utxos.length) throw new WalletError('This wallet has no confirmed coins yet.');
  const lock = lockOf({ publicKey, publicKeys, required });
  const { script, address } = lock;
  const spendable = utxos.map(u => ({
    txid: hex.decode(u.txid),
    index: u.vout,
    witnessUtxo: { script, amount: BigInt(u.value) },
    ...(lock.witnessScript ? { witnessScript: lock.witnessScript } : {}),
  }));
  const rate = Math.max(1, Math.round(feeRate));
  if (amountSats === 'max') {
    // Everything in one output, so the fee comes out of the amount sent.
    const total = utxos.reduce((sum, u) => sum + u.value, 0);
    const vsize = Math.ceil(10.5 + inputVsize(lock) * utxos.length + 31);
    const feeSats = vsize * rate;
    const sats = total - feeSats;
    if (sats < Number(DUST_SATS)) throw new WalletError('The balance is too small to cover the fee.');
    return {
      inputs: utxos.map(u => ({ txid: u.txid, index: u.vout, value: u.value })),
      outputs: [{ address: toAddress, sats }],
      feeSats,
      feeRate: rate,
      sentSats: sats,
      changeSats: 0,
    };
  }
  const outputs = [{ address: toAddress, amount: BigInt(amountSats) }];
  if (BigInt(amountSats) < DUST_SATS) throw new WalletError(`Send at least ${DUST_SATS} satoshis.`);

  let selection;
  try {
    selection = btc.selectUTXO(spendable, outputs, 'default', {
      changeAddress: address,
      feePerByte: BigInt(rate),
      bip69: false, // Keep the order we chose, so the plan and the signed transaction match.
      createTx: true,
      network: NETWORK,
      allowUnknownOutputs: false,
    });
  } catch (error) {
    throw new WalletError(`Could not build this transaction: ${error.message}`);
  }
  if (!selection?.tx) throw new WalletError('Not enough coins for that amount plus the fee.');

  const tx = selection.tx;
  const plan = {
    inputs: [...Array(tx.inputsLength).keys()].map(i => {
      const input = tx.getInput(i);
      const outpoint = { txid: hex.encode(input.txid), index: input.index };
      const match = utxos.find(u => u.txid === outpoint.txid && u.vout === outpoint.index);
      return { ...outpoint, value: match.value };
    }),
    outputs: [...Array(tx.outputsLength).keys()].map(i => {
      const output = tx.getOutput(i);
      return { address: addressOfScript(output.script), sats: Number(output.amount) };
    }),
    feeSats: Number(selection.fee),
    feeRate: rate,
  };
  plan.sentSats = plan.outputs.filter(o => o.address !== address).reduce((sum, o) => sum + o.sats, 0);
  plan.changeSats = plan.outputs.filter(o => o.address === address).reduce((sum, o) => sum + o.sats, 0);
  return plan;
}

/** Signs exactly the approved plan. Nothing here re-selects coins or recomputes a fee. */
export function signPlan({ privateKey, publicKey, plan }) {
  const script = scriptOf(publicKey);
  const tx = new btc.Transaction();
  for (const input of plan.inputs) {
    tx.addInput({ txid: hex.decode(input.txid), index: input.index, witnessUtxo: { script, amount: BigInt(input.value) } });
  }
  for (const output of plan.outputs) tx.addOutputAddress(output.address, BigInt(output.sats), NETWORK);
  tx.sign(new Uint8Array(privateKey));
  tx.finalize();
  const fee = plan.inputs.reduce((sum, i) => sum + i.value, 0) - plan.outputs.reduce((sum, o) => sum + o.sats, 0);
  if (fee !== plan.feeSats) throw new WalletError('The signed transaction does not match the approved plan.');
  return { hex: tx.hex, txid: tx.id, vsize: tx.vsize };
}

/*
 * Collecting a quorum's signatures.
 *
 * The server builds the unsigned transaction for the approved plan and holds it as a PSBT.
 * Each signer's own browser opens it, adds one signature and hands it back; the server can
 * put those together but cannot produce one, because it holds no signer's key. A PSBT that
 * describes a different transaction is refused by the library, so a signature collected for
 * one spend cannot be carried over to another.
 */
export function psbtForPlan(vault, plan) {
  const lock = lockOf(vault);
  const tx = new btc.Transaction();
  for (const input of plan.inputs) {
    tx.addInput({
      txid: hex.decode(input.txid),
      index: input.index,
      witnessUtxo: { script: lock.script, amount: BigInt(input.value) },
      ...(lock.witnessScript ? { witnessScript: lock.witnessScript } : {}),
    });
  }
  for (const output of plan.outputs) tx.addOutputAddress(output.address, BigInt(output.sats), NETWORK);
  return base64.encode(tx.toPSBT());
}

const readPsbt = psbt => {
  try {
    return btc.Transaction.fromPSBT(base64.decode(String(psbt)));
  } catch {
    throw new WalletError('That is not a readable partly signed transaction.');
  }
};

/** One signer adding their own signature. The plan is already fixed; nothing else changes. */
export function signPsbt(psbt, privateKey) {
  const tx = readPsbt(psbt);
  let signed = 0;
  try {
    signed = tx.sign(new Uint8Array(privateKey));
  } catch {
    signed = 0;
  }
  if (!signed) throw new WalletError('That key does not sign for this vault.');
  return base64.encode(tx.toPSBT());
}

/** How many of the quorum have signed, counted per input so a thin one cannot hide. */
export function signatureCount(psbt) {
  const tx = readPsbt(psbt);
  const counts = [...Array(tx.inputsLength).keys()].map(i => tx.getInput(i).partialSig?.length ?? 0);
  return counts.length ? Math.min(...counts) : 0;
}

/** Puts the signers' work together. Work for a different transaction is refused outright. */
export function combinePsbts(psbts) {
  const parts = psbts.map(readPsbt);
  if (!parts.length) throw new WalletError('There is nothing to put together.');
  const [first, ...rest] = parts;
  for (const part of rest) {
    try {
      first.combine(part);
    } catch (error) {
      throw new WalletError(`Those signatures are not for this transaction: ${error.message}`);
    }
  }
  return base64.encode(first.toPSBT());
}

/** The finished transaction, once enough of the quorum has signed. */
export function finalizePsbt(psbt) {
  const tx = readPsbt(psbt);
  try {
    tx.finalize();
  } catch (error) {
    throw new WalletError(`This transaction is not ready to send: ${error.message}`);
  }
  return { hex: tx.hex, txid: tx.id, vsize: tx.vsize };
}

export const toBtc = sats => (sats / 1e8).toFixed(8);

/**
 * Checks a signed transaction from someone's browser against the plan their palms approved,
 * before it is allowed anywhere near the network: same coins, same outputs, same fee.
 */
export function verifyAgainstPlan(rawHex, plan) {
  let tx;
  try {
    tx = btc.Transaction.fromRaw(hex.decode(String(rawHex).trim()));
  } catch {
    throw new WalletError('That is not a readable Bitcoin transaction.');
  }

  const inputs = [...Array(tx.inputsLength).keys()].map(i => {
    const input = tx.getInput(i);
    return `${hex.encode(input.txid)}:${input.index}`;
  });
  const planned = plan.inputs.map(input => `${input.txid}:${input.index}`);
  if (inputs.length !== planned.length || [...inputs].sort().join() !== [...planned].sort().join()) {
    throw new WalletError('The transaction spends different coins from the ones approved.');
  }

  const outputs = [...Array(tx.outputsLength).keys()].map(i => {
    const output = tx.getOutput(i);
    return { address: addressOfScript(output.script), sats: Number(output.amount) };
  });
  if (JSON.stringify(outputs) !== JSON.stringify(plan.outputs.map(o => ({ address: o.address, sats: o.sats })))) {
    throw new WalletError('The transaction pays different amounts from the ones approved.');
  }

  const fee = plan.inputs.reduce((sum, i) => sum + i.value, 0) - plan.outputs.reduce((sum, o) => sum + o.sats, 0);
  if (fee !== plan.feeSats) throw new WalletError('The transaction fee does not match the approved one.');
  for (let i = 0; i < tx.inputsLength; i++) {
    if (!tx.getInput(i).finalScriptWitness?.length) throw new WalletError('The transaction is not fully signed.');
  }
  return { txid: tx.id, vsize: tx.vsize };
}
