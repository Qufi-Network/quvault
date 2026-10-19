/*
 * The EVM JSON-RPC reader/broadcaster, against a scripted fetch — no network. It checks that
 * balances, nonce, fees, gas and receipts come back as decimal-string wei (never a rounded
 * Number), that an ERC-20 balanceOf is encoded correctly, and that a node error surfaces with
 * its own message rather than being swallowed.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createEvmChain, EvmChainError } from '../src/evm-chain.js';

/** A fetch that answers from a map of method -> result (or a function). */
function scriptedFetch(script) {
  return async (url, init) => {
    const { method, params } = JSON.parse(init.body);
    const entry = script[method];
    if (entry === undefined) return { ok: true, text: async () => JSON.stringify({ error: { code: -32601, message: `no script for ${method}` } }) };
    const result = typeof entry === 'function' ? entry(params) : entry;
    if (result && result.__error) {
      return { ok: true, text: async () => JSON.stringify({ error: result.__error }) };
    }
    return { ok: true, text: async () => JSON.stringify({ jsonrpc: '2.0', id: 1, result }) };
  };
}

const chain = script => createEvmChain({
  rpcUrl: 'https://rpc.example/evm', chainId: 1, explorer: 'https://etherscan.io',
  fetchImpl: scriptedFetch(script),
});

test('a balance past Number range comes back exact, as a decimal string', async () => {
  // 1234567 ETH in wei.
  const wei = 1234567000000000000000000n;
  const c = chain({ eth_getBalance: `0x${wei.toString(16)}` });
  const balance = await c.balance('0x1111111111111111111111111111111111111111');
  assert.equal(balance, '1234567000000000000000000');
  assert.equal(typeof balance, 'string');
  assert.ok(Number(balance) > Number.MAX_SAFE_INTEGER);
});

test('an ERC-20 balanceOf is encoded and decoded correctly', async () => {
  let seenData = null;
  const c = chain({
    eth_call: params => { seenData = params[0].data; return '0x0000000000000000000000000000000000000000000000008ac7230489e80000'; },
  });
  const bal = await c.tokenBalance('0x55d398326f99059fF775485246999027B3197955', '0x2222222222222222222222222222222222222222');
  assert.equal(bal, '10000000000000000000'); // 10 * 10^18
  assert.equal(seenData, '0x70a082310000000000000000000000002222222222222222222222222222222222222222');
});

test('nonce counts pending, and fees are built from base fee and tip', async () => {
  const c = chain({
    eth_getTransactionCount: '0x5',
    eth_maxPriorityFeePerGas: '0x59682f00', // 1.5 gwei
    eth_getBlockByNumber: { baseFeePerGas: '0x3b9aca00' }, // 1 gwei
  });
  assert.equal(await c.nonce('0x1111111111111111111111111111111111111111'), '5');
  const fees = await c.fees();
  assert.equal(fees.maxPriorityFeePerGas, '1500000000');
  assert.equal(fees.baseFeePerGas, '1000000000');
  // base*2 + tip = 2e9 + 1.5e9 = 3.5e9
  assert.equal(fees.maxFeePerGas, '3500000000');
});

test('gas estimation and broadcast pass through, and a receipt reports success', async () => {
  const c = chain({
    eth_estimateGas: '0x5208', // 21000
    eth_sendRawTransaction: '0xabc123',
    eth_getTransactionReceipt: { status: '0x1', blockNumber: '0x10', gasUsed: '0x5208' },
  });
  assert.equal(await c.estimateGas({ from: '0x11'.padEnd(42, '1'), to: '0x22'.padEnd(42, '2'), value: '1000' }), '21000');
  assert.equal(await c.broadcast('0x02deadbeef'), '0xabc123');
  const r = await c.receipt('0xabc123');
  assert.equal(r.success, true);
  assert.equal(r.blockNumber, '16');
  assert.equal(r.gasUsed, '21000');
});

test('a pending transaction has no receipt yet, and a node error is surfaced', async () => {
  const pending = chain({ eth_getTransactionReceipt: null });
  assert.equal(await pending.receipt('0xabc'), null);

  const reverting = chain({
    eth_estimateGas: { __error: { code: 3, message: 'execution reverted: ERC20: transfer amount exceeds balance' } },
  });
  await assert.rejects(
    () => reverting.estimateGas({ from: '0x11'.padEnd(42, '1'), to: '0x22'.padEnd(42, '2') }),
    err => err instanceof EvmChainError && /transfer amount exceeds balance/.test(err.message));
});
