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
import { hex } from '@scure/base';

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

/**
 * Chooses coins and returns the plan. `amountSats` may be 'max' to sweep everything.
 * Throws WalletError with a plain message when the balance or fee does not work out.
 */
export function planSpend({ publicKey, utxos, toAddress, amountSats, feeRate }) {
  if (!isValidAddress(toAddress)) throw new WalletError('That is not a valid testnet4 address.');
  if (!utxos.length) throw new WalletError('This wallet has no confirmed coins yet.');
  const script = scriptOf(publicKey);
  const address = addressOf(publicKey);
  const spendable = utxos.map(u => ({
    txid: hex.decode(u.txid),
    index: u.vout,
    witnessUtxo: { script, amount: BigInt(u.value) },
  }));
  const rate = Math.max(1, Math.round(feeRate));
  if (amountSats === 'max') {
    // Everything in one output, so the fee comes out of the amount sent.
    const total = utxos.reduce((sum, u) => sum + u.value, 0);
    const vsize = Math.ceil(10.5 + 68 * utxos.length + 31);
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

export const toBtc = sats => (sats / 1e8).toFixed(8);
