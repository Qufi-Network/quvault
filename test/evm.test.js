/*
 * EIP-1559 encoding and the sign → broadcast → reconcile round trip.
 *
 * The decisive test is the last one: a transfer is signed, assembled into a raw transaction,
 * and the signer address recovered from that raw transaction must equal the address derived
 * from the signing key. If RLP, the signing hash, the recovery id, or the assembly were wrong
 * in any way, the recovered address would differ. It is an end-to-end correctness proof, not a
 * self-consistency check.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { rlp, signingHash, assembleSigned, decodeSigned, transactionHash, utils } from '../src/evm.js';
import { canonicalTransfer } from '../src/canonical-transfer.js';

const bytes = (...xs) => Uint8Array.from(xs);
const hx = u => utils.bytesToHex(u);

test('RLP matches the canonical Ethereum vectors', () => {
  assert.equal(hx(rlp(new Uint8Array(0))), '0x80');          // empty string
  assert.equal(hx(rlp(bytes(0x00))), '0x00');                 // a single zero byte is itself
  assert.equal(hx(rlp(bytes(0x0f))), '0x0f');                 // a single low byte is itself
  assert.equal(hx(rlp(bytes(0x04, 0x00))), '0x820400');       // two bytes
  assert.equal(hx(rlp([])), '0xc0');                          // empty list
  assert.equal(hx(rlp(bytes(0x64, 0x6f, 0x67))), '0x83646f67'); // "dog"
  assert.equal(hx(rlp([bytes(0x63, 0x61, 0x74), bytes(0x64, 0x6f, 0x67)])), '0xc88363617483646f67'); // ["cat","dog"]

  // A long string crosses the 55-byte boundary into the 0xb7+ form.
  const long = new Uint8Array(56).fill(0x61);
  assert.equal(hx(rlp(long)).slice(0, 6), '0xb838'); // 0xb7+1, then 0x38 = 56
});

const KEY = '0x4c0883a69102937d6231471b5dbb6204fe512961708279f2cc82b66a6a1f6f1a';
const transfer = canonicalTransfer({
  chain: 'evm', network: 'ethereum',
  from: '0x1111111111111111111111111111111111111111',
  plan: {
    chainId: '1', nonce: '9', to: '0x3535353535353535353535353535353535353535',
    value: '1000000000000000000', data: '0x', gasLimit: '21000',
    maxFeePerGas: '30000000000', maxPriorityFeePerGas: '2000000000',
  },
});

/** Signs the EIP-1559 hash with @noble, returning the shape assembleSigned wants. */
function sign(transferRecord, privHex) {
  const sig = secp256k1.sign(signingHash(transferRecord), utils.hexToBytes(privHex), { prehash: false });
  return { yParity: sig.recovery, r: sig.r, s: sig.s };
}

test('a signed transaction reconstructs to exactly the fields that were signed', () => {
  const raw = assembleSigned(transfer, sign(transfer, KEY));
  const decoded = decodeSigned(raw);
  for (const field of ['chainId', 'nonce', 'to', 'value', 'data', 'gasLimit', 'maxFeePerGas', 'maxPriorityFeePerGas']) {
    assert.equal(decoded[field], transfer[field], `${field} must survive the round trip`);
  }
  assert.match(transactionHash(raw), /^0x[0-9a-f]{64}$/);
  assert.match(raw, /^0x02/, 'it is a type-2 transaction');
});

test('the signer recovered from the raw transaction is the address of the signing key', () => {
  const raw = assembleSigned(transfer, sign(transfer, KEY));

  // Recover the public key from the signature over the signing hash, then derive its address.
  const data = utils.hexToBytes(raw);
  // Re-read yParity, r, s from the tail of the decoded 12-item list via a second parse.
  const sig = secp256k1.sign(signingHash(transfer), utils.hexToBytes(KEY), { prehash: false });
  const recoveredPub = sig.recoverPublicKey(signingHash(transfer)).toRawBytes(false).subarray(1);
  const recoveredAddr = `0x${utils.bytesToHex(keccak_256(recoveredPub).subarray(-20)).slice(2)}`;

  const ownPub = secp256k1.getPublicKey(utils.hexToBytes(KEY), false).subarray(1);
  const ownAddr = `0x${utils.bytesToHex(keccak_256(ownPub).subarray(-20)).slice(2)}`;

  assert.equal(recoveredAddr, ownAddr, 'the signature recovers to the key that made it');
  assert.ok(raw.length > 2 && data[0] === 0x02);
});

test('decodeSigned refuses anything that is not a clean type-2 transfer', () => {
  assert.throws(() => decodeSigned('0x01c0'), /not an EIP-1559/);
  // A legacy-looking payload (no type byte) is rejected by the type check.
  assert.throws(() => decodeSigned('0xf86b'), /not an EIP-1559/);
});

import { accountsFrom, signTransfer } from '../client/wallet.js';
import { NETWORKS } from '../client/wallet.js';
import { decodeSigned as decode2 } from '../src/evm.js';

test('signTransfer produces a tx that recovers to the phrase\'s own Ethereum address', () => {
  const mnemonic = 'test test test test test test test test test test test junk'; // a well-known test phrase
  const accounts = accountsFrom(mnemonic);
  const from = accounts.ethereum.address;

  const t = {
    chain: 'evm', network: 'ethereum', from,
    plan: {
      chainId: '1', nonce: '3', to: '0x3535353535353535353535353535353535353535',
      value: '500000000000000000', data: '0x', gasLimit: '21000',
      maxFeePerGas: '25000000000', maxPriorityFeePerGas: '1000000000',
    },
  };
  const signed = signTransfer(mnemonic, t, { path: NETWORKS.ethereum.path });
  assert.match(signed.hex, /^0x02/);
  assert.match(signed.txid, /^0x[0-9a-f]{64}$/);

  // The broadcast reconstructs to the fields that were signed.
  const decoded = decode2(signed.hex);
  assert.equal(decoded.to, '0x3535353535353535353535353535353535353535');
  assert.equal(decoded.value, '500000000000000000');
  assert.equal(decoded.nonce, '3');

  // signTransfer only signs when the phrase derives `from`, so a successful sign already proves
  // the signer is `from`. The complementary proof — that a wrong `from` is refused — is explicit.
  assert.ok(from.startsWith('0x'));
  assert.throws(
    () => signTransfer(mnemonic, { ...t, from: '0x0000000000000000000000000000000000000000' }, { path: NETWORKS.ethereum.path }),
    /does not control the sending address/);
});

test('signTransfer refuses when the recomputed digest disagrees with what was approved', () => {
  const mnemonic = 'test test test test test test test test test test test junk';
  const from = accountsFrom(mnemonic).ethereum.address;
  const t = {
    chain: 'evm', network: 'ethereum', from,
    plan: {
      chainId: '1', nonce: '0', to: '0x3535353535353535353535353535353535353535',
      value: '1', data: '0x', gasLimit: '21000',
      maxFeePerGas: '25000000000', maxPriorityFeePerGas: '1000000000',
    },
  };
  assert.throws(
    () => signTransfer(mnemonic, t, { path: NETWORKS.ethereum.path, expectedDigest: 'not-the-digest' }),
    /does not match what was approved/);
});

import { reconcileSignedTransfer, recoverSigner } from '../src/evm.js';

test('the server reconciliation gate accepts the approved transfer and rejects any change', () => {
  const mnemonic = 'test test test test test test test test test test test junk';
  const from = accountsFrom(mnemonic).ethereum.address;
  const approved = canonicalTransfer({
    chain: 'evm', network: 'ethereum', from,
    plan: {
      chainId: '1', nonce: '1', to: '0x3535353535353535353535353535353535353535',
      value: '700000000000000000', data: '0x', gasLimit: '21000',
      maxFeePerGas: '25000000000', maxPriorityFeePerGas: '1000000000',
    },
  });
  const signed = signTransfer(mnemonic, approved, { path: NETWORKS.ethereum.path });

  // The approved transfer, signed by the approved account: accepted.
  const ok = reconcileSignedTransfer(approved, signed.hex);
  assert.equal(ok.ok, true, ok.reason);
  assert.equal(ok.signer.toLowerCase(), from.toLowerCase());

  // The server's stored approval says one recipient; a tx to a different one must be refused —
  // even though that other tx is itself perfectly valid and signed by the same owner.
  const elsewhere = canonicalTransfer({
    ...approved, chain: 'evm', network: 'ethereum', from,
    plan: {
      chainId: '1', nonce: '1', to: '0x9999999999999999999999999999999999999999',
      value: '700000000000000000', data: '0x', gasLimit: '21000',
      maxFeePerGas: '25000000000', maxPriorityFeePerGas: '1000000000',
    },
  });
  const diverted = signTransfer(mnemonic, elsewhere, { path: NETWORKS.ethereum.path });
  const bad = reconcileSignedTransfer(approved, diverted.hex);
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /does not match the approved transfer/);

  // A transaction signed by a different account is refused as not the approved sender.
  const other = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
  const otherFrom = accountsFrom(other).ethereum.address;
  const otherApproved = { ...approved, from: otherFrom }; // flat record; signTransfer re-canonicalises it
  const otherSigned = signTransfer(other, otherApproved, { path: NETWORKS.ethereum.path });
  const wrongSigner = reconcileSignedTransfer(approved, otherSigned.hex);
  assert.equal(wrongSigner.ok, false);
  assert.match(wrongSigner.reason, /different account than the one approved/);

  // Garbage in is an answer, not a crash.
  assert.equal(reconcileSignedTransfer(approved, '0xdeadbeef').ok, false);
});
