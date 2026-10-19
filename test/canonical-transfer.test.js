/*
 * The EVM transfer canonical form — the keystone of the Ethereum and BSC signing path.
 *
 * What these guard: that the bytes the palm approves and a signature binds are frozen, survive
 * the round trip a database and a network make of them, cannot silently represent a big value
 * wrong, and that the ERC-20 readable fields cannot disagree with the call data that is actually
 * signed. Every one of these is a defect that would otherwise only surface as an honest
 * signature reading as a forged one, with the rows immutable by the time it is noticed.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  canonicalTransfer, transferBytes, checkErc20Plan, checkTransferStability, TransferError,
  REFERENCE_INPUT, REFERENCE_BYTES, REFERENCE_DIGEST,
} from '../src/canonical-transfer.js';

const digestOf = text => createHash('sha256').update(text, 'utf8').digest('base64url');

test('the EVM transfer digest is locked to a vector, and the guard catches a change', () => {
  const { bytes, digest } = checkTransferStability(digestOf);
  assert.equal(bytes, REFERENCE_BYTES);
  assert.equal(digest, REFERENCE_DIGEST);
  assert.notEqual(REFERENCE_DIGEST, 'PENDING', 'the digest must be locked, not left pending');

  // The vector only earns its place if it fails when the form moves.
  assert.throws(() => checkTransferStability(() => 'a-different-digest'), /digest has changed/);
  assert.throws(() => checkTransferStability(t => digestOf(`${t} `)), /digest has changed/);
  let n = 0;
  assert.throws(() => checkTransferStability(t => (n++ ? 'x' : digestOf(t))), /not deterministic|has changed/);
  assert.throws(() => checkTransferStability('not a function'), /needs a digest function/);
});

test('a transfer survives the round trip a database and a network make of it', () => {
  const t = canonicalTransfer(REFERENCE_INPUT);
  const bytes = transferBytes(t);
  assert.equal(transferBytes(JSON.parse(JSON.stringify(t))), bytes);
  assert.equal(transferBytes(JSON.parse(bytes)), bytes);
  assert.deepEqual(JSON.parse(bytes), t);
  assert.ok(!bytes.includes('undefined'));

  // Field order on input must not reach the digest: the whole asset object supplied reversed.
  const reordered = canonicalTransfer({
    ...REFERENCE_INPUT,
    asset: { token: REFERENCE_INPUT.asset.token, kind: 'erc20', decimals: 18, symbol: 'USDT' },
  });
  assert.equal(transferBytes(reordered), bytes);
});

test('a big value is held exactly, not as a rounded Number', () => {
  // 1234567 ETH in wei — far past Number.MAX_SAFE_INTEGER. A JS number would lose the low digits.
  const big = '1234567000000000000000000';
  const t = canonicalTransfer({
    chain: 'evm', network: 'ethereum',
    from: '0x1111111111111111111111111111111111111111',
    plan: {
      chainId: '1', nonce: '0', to: '0x2222222222222222222222222222222222222222',
      value: big, data: '0x', gasLimit: '21000',
      maxFeePerGas: '30000000000', maxPriorityFeePerGas: '1000000000',
    },
  });
  assert.equal(t.value, big, 'the full value is preserved as a string');
  assert.equal(JSON.parse(transferBytes(t)).value, big, 'and survives JSON');
  assert.ok(Number(big) > Number.MAX_SAFE_INTEGER, 'the fixture is genuinely past Number range');

  // A bigint input is accepted and normalised identically.
  const fromBig = canonicalTransfer({
    chain: 'evm', network: 'ethereum',
    from: '0x1111111111111111111111111111111111111111',
    plan: {
      chainId: 1n, nonce: 0n, to: '0x2222222222222222222222222222222222222222',
      value: 1234567000000000000000000n, data: '0x', gasLimit: 21000n,
      maxFeePerGas: 30000000000n, maxPriorityFeePerGas: 1000000000n,
    },
  });
  assert.equal(fromBig.value, big);
});

test('malformed quantities and addresses are refused rather than coerced', () => {
  const base = {
    chain: 'evm', network: 'ethereum',
    from: '0x1111111111111111111111111111111111111111',
    plan: {
      chainId: '1', nonce: '0', to: '0x2222222222222222222222222222222222222222',
      value: '0', data: '0x', gasLimit: '21000',
      maxFeePerGas: '30000000000', maxPriorityFeePerGas: '1000000000',
    },
  };
  const bad = (patch, re) => assert.throws(
    () => canonicalTransfer({ ...base, plan: { ...base.plan, ...patch } }), re);
  bad({ value: '01' }, /leading zeros/);
  bad({ value: '-1' }, /non-negative/);
  bad({ value: '1.5' }, /non-negative/);
  bad({ value: 1.5 }, /string or a bigint/);          // a float number is not accepted
  bad({ nonce: 'ten' }, /non-negative/);
  bad({ to: '0x1234' }, /must be 20 bytes/);   // even hex, but wrong length
  bad({ to: '0x123' }, /odd number/);          // odd hex is caught first
  bad({ data: '0xabc' }, /odd number/);
  // The priority fee cannot exceed the cap — an unminable transaction a palm must never approve.
  bad({ maxPriorityFeePerGas: '40000000000' }, /cannot exceed maxFeePerGas/);
  assert.throws(() => canonicalTransfer({ ...base, chain: 'bitcoin' }), /for EVM chains/);
  assert.throws(() => canonicalTransfer({ ...base, from: '0xzz' }), /from must be a 0x hex/);
});

test('an ERC-20 transfer cannot say one thing and do another', () => {
  const t = canonicalTransfer(REFERENCE_INPUT);
  const decoded = checkErc20Plan(t);
  assert.deepEqual(decoded, {
    recipient: '0x2222222222222222222222222222222222222222',
    amount: '10000000000000000000',
  });

  // value must be zero on a token transfer, and `to` must be the token contract.
  assert.throws(() => checkErc20Plan({ ...t, value: '1' }), /sends no native value/);
  assert.throws(() => checkErc20Plan({ ...t, to: '0x3333333333333333333333333333333333333333' }),
    /addressed to the token contract/);
  // data that is not a bare transfer(address,uint256).
  assert.throws(() => checkErc20Plan({ ...t, data: '0xdeadbeef' }), /bare ERC-20 transfer/);
  // a recipient word with dirty high bytes (an attempt to smuggle a different call).
  const dirty = `0xa9059cbb${'ff'.repeat(12)}${'22'.repeat(20)}${'00'.repeat(32)}`;
  assert.throws(() => checkErc20Plan({ ...t, data: dirty }), /dirty high bytes/);

  // A native transfer is not an ERC-20 one, and the check says so rather than guessing.
  const native = canonicalTransfer({
    chain: 'evm', network: 'ethereum',
    from: '0x1111111111111111111111111111111111111111',
    plan: {
      chainId: '1', nonce: '0', to: '0x2222222222222222222222222222222222222222',
      value: '1000000000000000000', data: '0x', gasLimit: '21000',
      maxFeePerGas: '30000000000', maxPriorityFeePerGas: '1000000000',
    },
  });
  assert.equal(native.asset.kind, 'native');
  assert.throws(() => checkErc20Plan(native), /Not an ERC-20/);
});
