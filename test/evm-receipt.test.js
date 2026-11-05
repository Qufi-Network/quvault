/*
 * A receipt for a plain Ethereum account's transfer, checked against the chain. The Palm Wallet
 * case runs end to end in palm-wallet-app.test.js; this is the other kind of transaction.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalTransfer, transferDigest } from '../src/canonical-transfer.js';
import { chainDigestOf } from '../src/evm-receipt.js';

const plan = {
  chainId: '11155111', nonce: '7', to: '0x1111111111111111111111111111111111111111', value: '20000000000000000',
  data: '0x', gasLimit: '21000', maxFeePerGas: '3000000000', maxPriorityFeePerGas: '1500000000',
};
const from = '0x2222222222222222222222222222222222222222';
const approved = transferDigest(canonicalTransfer({ chain: 'evm', network: 'ethereum', from, plan }));
const onChain = {
  from, to: plan.to, nonce: plan.nonce, value: plan.value, input: '0x', gas: plan.gasLimit,
  maxFeePerGas: plan.maxFeePerGas, maxPriorityFeePerGas: plan.maxPriorityFeePerGas, chainId: plan.chainId, logs: [],
};

test('a plain transfer on chain reproduces the digest its receipt carries', () => {
  const rebuilt = chainDigestOf(onChain, { network: 'ethereum' });
  assert.equal(rebuilt.digest, approved);
  assert.equal(rebuilt.payee, plan.to);
  assert.equal(rebuilt.amount, plan.value);
});

test('any field the chain records differently gives a different digest', () => {
  for (const change of [{ value: '20000000000000001' }, { to: `0x${'3'.repeat(40)}` }, { nonce: '8' }, { maxFeePerGas: '3000000001' }, { chainId: '97' }]) {
    assert.notEqual(chainDigestOf({ ...onChain, ...change }, { network: 'ethereum' }).digest, approved, JSON.stringify(change));
  }
  assert.notEqual(chainDigestOf(onChain, { network: 'bsc' }).digest, approved, 'and it names its network');
});
