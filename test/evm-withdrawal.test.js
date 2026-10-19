/*
 * The whole EVM send path through the server: create a vault, add an Ethereum account, propose
 * a withdrawal, approve it with a palm, unlock, sign in the browser, and broadcast — with the
 * three gates in between. The EVM node is mocked; the Veyns and Bitcoin halves are the real
 * harness. This is the app-level proof that the pieces unit-tested elsewhere compose correctly.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { createApp } from '../src/app.js';
import {
  mockWorld, ISSUER, CHAIN, ORIGIN, CLIENT_ID, SECRET, SEED,
  ok, signedIn, walletFor, addAccount, palmApprove, attestInstitutionalFor,
} from './harness.js';
import { accountsFrom, signTransfer, NETWORKS as CLIENT_NETWORKS } from '../client/wallet.js';
import { decodeSigned } from '../src/evm.js';

// The phrase the harness derives every test address from, so the Ethereum account the server
// registers is the one this phrase controls — and the one these signatures must recover to.
const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** A tiny EVM JSON-RPC node: the few methods the withdrawal path calls, plus a broadcast log. */
function evmNode() {
  const sent = [];
  const handle = (method) => ({
    eth_chainId: '0xaa36a7',
    eth_getTransactionCount: '0x4',
    eth_maxPriorityFeePerGas: '0x59682f00', // 1.5 gwei
    eth_getBlockByNumber: { baseFeePerGas: '0x3b9aca00' }, // 1 gwei
    eth_getBalance: '0xde0b6b3a7640000', // 1 ETH
  }[method]);
  return {
    sent,
    async fetch(url, init) {
      const { method, params } = JSON.parse(init.body);
      if (method === 'eth_sendRawTransaction') {
        const raw = params[0];
        const txid = `0x${crypto.createHash('sha256').update(raw).digest('hex')}`; // any 32-byte id
        sent.push({ raw, txid });
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: txid }), { status: 200 });
      }
      const result = handle(method);
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 });
    },
  };
}

/** Builds the app with a fetch that routes EVM RPC to the mock node and everything else to Veyns/BTC. */
async function startEvm(t) {
  let time = 1_800_000_000;
  const clock = () => time;
  const world = mockWorld(clock);
  const node = evmNode();
  const { NETWORKS } = await import('../src/networks.js');
  const evmHosts = new Set(['ethereum', 'bsc'].map(id => new URL(NETWORKS[id].rpc).origin));

  const fetchImpl = (url, init = {}) =>
    (evmHosts.has(new URL(url).origin) ? node.fetch(url, init) : world.fetchImpl(url, init));

  const app = createApp({
    publicOrigin: ORIGIN, issuer: ISSUER, chainApi: CHAIN, clientId: CLIENT_ID,
    backendSecret: SECRET, walletSeed: SEED, now: clock, fetchImpl, log: { info() {}, error() {}, warn() {} },
  });
  await new Promise(r => app.server.listen(0, '127.0.0.1', r));
  t.after(() => app.close());
  const { port } = app.server.address();

  function client() {
    const jar = new Map();
    const call = (method, path, body) => new Promise((resolve, reject) => {
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const req = http.request({ host: '127.0.0.1', port, method, path,
        headers: { origin: ORIGIN, cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
          ...(payload ? { 'content-type': 'application/json' } : {}) } },
        res => {
          for (const c of res.headers['set-cookie'] || []) {
            const pair = c.split(';')[0]; const i = pair.indexOf('=');
            if (/Max-Age=0\b/.test(c)) jar.delete(pair.slice(0, i)); else jar.set(pair.slice(0, i), pair.slice(i + 1));
          }
          let data = ''; res.on('data', d => data += d);
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data ? JSON.parse(data) : null }));
        });
      req.on('error', reject); req.end(payload);
    });
    return { get: p => call('GET', p), post: (p, b = {}) => call('POST', p, b) };
  }
  return { world, client, app, node, now: () => time, advance: s => { time += s; } };
}

test('an Ethereum withdrawal is proposed, palm-approved, signed and broadcast', async t => {
  const env = await startEvm(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);
  await addAccount(env, c, { network: 'ethereum' });

  const ethAddr = accountsFrom(PHRASE).ethereum.address;

  // 0.25 ETH in wei.
  const amount = '250000000000000000';
  const { operation, transfer, transactionHash } = ok(await c.post('/api/withdrawals', {
    network: 'ethereum', to: '0x3535353535353535353535353535353535353535', amount,
  }));
  assert.equal(operation.details.network, 'ethereum');
  assert.equal(operation.details.amount_wei, amount);
  assert.equal(transfer.from.toLowerCase(), ethAddr.toLowerCase());
  assert.equal(transfer.chainId, '11155111');

  // Nothing is on the network before the palm.
  assert.equal(env.node.sent.length, 0);

  await palmApprove(env, c, operation.id);

  // The browser unlocks, signs with the phrase's Ethereum key, and sends the raw tx + V2 record.
  const unlocked = ok(await c.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.equal(unlocked.transfer.transactionHash, transactionHash);
  const signed = signTransfer(PHRASE, unlocked.transfer, { path: CLIENT_NETWORKS.ethereum.path });
  const authorization = attestInstitutionalFor(env, c, unlocked);

  const result = ok(await c.post(`/api/operations/${operation.id}/broadcast`, { hex: signed.hex, authorization }));

  // It reached the network, and the broadcast bytes decode to exactly the approved transfer.
  assert.equal(env.node.sent.length, 1);
  assert.equal(env.node.sent[0].raw, signed.hex);
  const decoded = decodeSigned(env.node.sent[0].raw);
  assert.equal(decoded.to, '0x3535353535353535353535353535353535353535');
  assert.equal(decoded.value, amount);
  assert.equal(decoded.chainId, '11155111');
  assert.ok(result.txid.startsWith('0x'));

  // The operation is recorded done, and the evidence log carries the whole arc.
  const evidence = ok(await c.get(`/api/operations/${operation.id}/evidence`));
  const kinds = evidence.bundle.entries.map(e => e.kind);
  for (const k of ['proposal.created', 'authorization.attempted', 'authorization.granted', 'signature.produced', 'broadcast.attempted', 'broadcast.accepted']) {
    assert.ok(kinds.includes(k), `evidence missing ${k}: ${kinds.join(',')}`);
  }
});

test('the server refuses a signed transaction that does not match the approved transfer', async t => {
  const env = await startEvm(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);
  await addAccount(env, c, { network: 'ethereum' });

  const { operation } = ok(await c.post('/api/withdrawals', {
    network: 'ethereum', to: '0x3535353535353535353535353535353535353535', amount: '250000000000000000',
  }));
  await palmApprove(env, c, operation.id);
  const unlocked = ok(await c.post(`/api/operations/${operation.id}/unlock`, {}));
  const authorization = attestInstitutionalFor(env, c, unlocked);

  // Sign a DIFFERENT transfer (a larger amount) than the one approved.
  const tampered = { ...unlocked.transfer, value: '900000000000000000' };
  const badSigned = signTransfer(PHRASE, tampered, { path: CLIENT_NETWORKS.ethereum.path });

  const res = await c.post(`/api/operations/${operation.id}/broadcast`, { hex: badSigned.hex, authorization });
  assert.equal(res.status, 400);
  assert.match(res.body.error, /does not match the approval/);
  assert.equal(env.node.sent.length, 0, 'nothing reached the network');
});
