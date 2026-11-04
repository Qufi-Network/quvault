/*
 * The Palm Wallet inside the app: an Ethereum account locked to the palm, then spent from.
 *
 * The node here keeps state the way a chain does (balances, nonces, code, the wallet's own
 * transfer count) and deploys through the CREATE2 proxy exactly as the real one does, so the
 * test sees the wallet appear at the address the app promised. What the gas account submits is
 * decoded and every signature in it checked: the signer's against its key, the palm key's
 * against the wallet's palm signer.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hex } from '@scure/base';
import { createApp } from '../src/app.js';
import {
  ISSUER, CHAIN, ORIGIN, CLIENT_ID, SECRET, SEED, mockWorld, ok, signedIn, palmApprove, walletFor, addAccount,
  ADDRESSES, attestInstitutionalFor,
} from './harness.js';
import { cosignerFrom, signTransfer, signPalmWalletTransfer, NETWORKS as CLIENT_NETWORKS } from '../client/wallet.js';
import { signKeyProof } from '../src/key-proof.js';
import { decodeSigned, recoverSigner, transactionHash } from '../src/evm.js';
import { checkPalmProof } from '../src/palm-proof.js';
import { canonicalTransfer, transferDigest } from '../src/canonical-transfer.js';
import {
  DEPLOYER, NONCE_CALL, LAST_ACTIVITY_CALL, eip712TransferDigest, recoverAddress, evmAddressOfPublicKey,
} from '../src/palm-wallet.js';

const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PAYEE = '0x3535353535353535353535353535353535353535';
const ETH = 10n ** 18n;
const selectorOf = signature => hex.encode(keccak_256(new TextEncoder().encode(signature)).subarray(0, 4));
const TRANSFER_SELECTOR = selectorOf('transfer((address,address,uint256,uint256,address,uint256,uint256),bytes[],bytes)');
const REFRESH_SELECTOR = selectorOf('refresh(uint256,uint256,bytes[],bytes)');
// The chain's clock, for lastActivity: the same moment the app's test clock starts at.
const CHAIN_TIME = 1_800_000_000n;

/** A small chain: balances, nonces, code, deployment through the proxy, and the wallet's transfers. */
function chainNode() {
  const balances = new Map();
  const nonces = new Map();
  const code = new Map();
  const walletNonce = new Map();
  const lastActivity = new Map();
  const sent = [];
  const lower = a => String(a).toLowerCase();
  const word = (bytes, at) => BigInt(`0x${hex.encode(bytes.subarray(at, at + 32))}`);
  const quantity = n => `0x${BigInt(n).toString(16)}`;

  function apply(raw) {
    const tx = decodeSigned(raw);
    const from = lower(recoverSigner(raw));
    const to = lower(tx.to);
    nonces.set(from, (nonces.get(from) ?? 0n) + 1n);
    const value = BigInt(tx.value);
    if (value) {
      if ((balances.get(from) ?? 0n) < value) throw new Error('insufficient funds for transfer');
      balances.set(from, balances.get(from) - value);
      balances.set(to, (balances.get(to) ?? 0n) + value);
    }
    const data = hex.decode(tx.data.replace(/^0x/, ''));
    if (to === DEPLOYER) {
      const salt = data.subarray(0, 32);
      const init = data.subarray(32);
      const address = `0x${hex.encode(keccak_256(new Uint8Array([0xff, ...hex.decode(DEPLOYER.slice(2)), ...salt, ...keccak_256(init)])).subarray(12))}`;
      if (code.has(address)) throw new Error('execution reverted: already deployed');
      code.set(address, '0x6080');
      lastActivity.set(address, CHAIN_TIME);
    } else if (code.has(to) && hex.encode(data.subarray(0, 4)) === TRANSFER_SELECTOR) {
      // The Payment struct sits inline: token, to, amount, fee, feeTo, gasRefund, deadline.
      const body = data.subarray(4);
      const payee = `0x${hex.encode(body.subarray(32 + 12, 64))}`;
      const amount = word(body, 64);
      const fee = word(body, 96);
      const feeTo = `0x${hex.encode(body.subarray(128 + 12, 160))}`;
      const refund = word(body, 160);
      walletNonce.set(to, (walletNonce.get(to) ?? 0n) + 1n);
      lastActivity.set(to, CHAIN_TIME + 1000n);
      balances.set(to, (balances.get(to) ?? 0n) - amount - fee - refund);
      balances.set(payee, (balances.get(payee) ?? 0n) + amount);
      balances.set(feeTo, (balances.get(feeTo) ?? 0n) + fee);
      balances.set(from, (balances.get(from) ?? 0n) + refund);
    } else if (code.has(to) && hex.encode(data.subarray(0, 4)) === REFRESH_SELECTOR) {
      const refund = word(data.subarray(4), 0);
      walletNonce.set(to, (walletNonce.get(to) ?? 0n) + 1n);
      lastActivity.set(to, CHAIN_TIME + 5000n);
      balances.set(to, (balances.get(to) ?? 0n) - refund);
      balances.set(from, (balances.get(from) ?? 0n) + refund);
    }
    sent.push({ raw, tx, from, to, data });
    return transactionHash(raw);
  }

  const methods = {
    eth_chainId: () => '0xaa36a7',
    eth_getBalance: ([address]) => quantity(balances.get(lower(address)) ?? 0n),
    eth_getTransactionCount: ([address]) => quantity(nonces.get(lower(address)) ?? 0n),
    eth_maxPriorityFeePerGas: () => '0x59682f00',
    eth_getBlockByNumber: () => ({ baseFeePerGas: '0x3b9aca00' }),
    eth_getCode: ([address]) => code.get(lower(address)) ?? '0x',
    eth_call: ([{ to, data }]) => {
      if (data === NONCE_CALL) return `0x${(walletNonce.get(lower(to)) ?? 0n).toString(16).padStart(64, '0')}`;
      if (data === LAST_ACTIVITY_CALL) return `0x${(lastActivity.get(lower(to)) ?? 0n).toString(16).padStart(64, '0')}`;
      throw new Error('unexpected call');
    },
    eth_estimateGas: ([{ to }]) => quantity(lower(to) === DEPLOYER ? 1_500_000 : 120_000),
    eth_sendRawTransaction: ([raw]) => apply(raw),
  };

  return {
    balances, code, sent, walletNonce, lastActivity,
    async fetch(url, init) {
      const { id, method, params } = JSON.parse(init.body);
      try {
        const result = methods[method](params);
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), { status: 200 });
      } catch (error) {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message: error.message } }), { status: 200 });
      }
    },
  };
}

async function startChain(t) {
  let time = 1_800_000_000;
  const clock = () => time;
  const world = mockWorld(clock);
  const node = chainNode();
  const { NETWORKS } = await import('../src/networks.js');
  const evmHosts = new Set(['ethereum', 'bsc'].map(id => new URL(NETWORKS[id].rpc).origin));
  const fetchImpl = (url, init = {}) => (evmHosts.has(new URL(url).origin) ? node.fetch(url, init) : world.fetchImpl(url, init));
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
      const req = http.request({
        host: '127.0.0.1', port, method, path,
        headers: { origin: ORIGIN, cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '), ...(payload ? { 'content-type': 'application/json' } : {}) },
      }, res => {
        for (const c of res.headers['set-cookie'] || []) {
          const pair = c.split(';')[0];
          const i = pair.indexOf('=');
          if (/Max-Age=0\b/.test(c)) jar.delete(pair.slice(0, i)); else jar.set(pair.slice(0, i), pair.slice(i + 1));
        }
        let data = '';
        res.on('data', d => { data += d; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data ? JSON.parse(data) : null }));
      });
      req.on('error', reject);
      req.end(payload);
    });
    return { get: p => call('GET', p), post: (p, b = {}) => call('POST', p, b) };
  }
  return { world, client, app, node, now: () => time, advance: s => { time += s; } };
}

async function signingKey(env, client, vaultOwnerId) {
  const started = ok(await client.post('/api/signing-key/approval', { vaultOwnerId }));
  await palmApprove(env, client, started.operation.id);
  ok(await client.post(`/api/operations/${started.operation.id}/unlock`, {}));
  const key = cosignerFrom(PHRASE, started.index);
  ok(await client.post('/api/signing-key/register', {
    operationId: started.operation.id,
    publicKey: Buffer.from(key.publicKey).toString('hex'),
    proof: signKeyProof(key.privateKey, { vaultOwnerId, memberId: client.id, publicKey: Buffer.from(key.publicKey).toString('hex') }),
  }));
  return key;
}

const ethereum = async client => ok(await client.get('/api/wallet')).accounts.find(a => a.network === 'ethereum');

/** The signatures inside transfer(...) calldata: the signers' bytes[] and the palm key's bytes. */
function signaturesIn(data) {
  const body = data.subarray(4);
  const at = n => Number(BigInt(`0x${hex.encode(body.subarray(n, n + 32))}`));
  const bytesAt = start => `0x${hex.encode(body.subarray(start + 32, start + 32 + at(start)))}`;
  const sigs = at(224);
  const count = at(sigs);
  return {
    signers: Array.from({ length: count }, (_, i) => bytesAt(sigs + 32 + at(sigs + 32 + 32 * i))),
    palm: bytesAt(at(256)),
  };
}

/** One person, an Ethereum account with 1 ETH, locked to their palm. */
async function lockedWallet(env, days = 90) {
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await addAccount(env, alex, { network: 'ethereum' });
  const key = await signingKey(env, alex, alex.id);
  const eoa = ADDRESSES.ethereum.address.toLowerCase();
  env.node.balances.set(eoa, ETH);

  const asked = ok(await alex.post('/api/accounts/lock', { network: 'ethereum', required: 1, palm: true, recoveryDays: days }));
  await palmApprove(env, alex, asked.operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${asked.operation.id}/unlock`, {}));
  const signed = signTransfer(PHRASE, unlocked.transfer, { path: CLIENT_NETWORKS.ethereum.path });
  ok(await alex.post(`/api/operations/${asked.operation.id}/broadcast`, { hex: signed.hex, authorization: attestInstitutionalFor(env, alex, unlocked) }));
  return { alex, key, eoa, asked, account: await ethereum(alex) };
}

test('locking Ethereum to the palm moves every coin to a Palm Wallet whose address was known in advance', async t => {
  const env = await startChain(t);
  const { asked, account, eoa, key } = await lockedWallet(env);
  assert.match(asked.operation.statement, /^Lock my Ethereum to my palm on the chain and move 0\.99\d* ETH to it$/);
  assert.match(asked.operation.details.recovery, /if the palm approves nothing in the wallet for about 90 days, the signers alone can move the coins/);
  assert.match(asked.operation.details.fees, /Palm 0\.1% and its own network fee/);
  assert.match(asked.operation.details.warning, /if you die/);
  assert.equal(account.address, asked.quorum.address, 'the account is now the wallet');
  assert.equal(account.quorum.required, 1);
  assert.deepEqual(account.quorum.palmWallet.signers, [evmAddressOfPublicKey(Buffer.from(key.publicKey).toString('hex'))]);
  assert.equal(account.quorum.palmWallet.recoveryDelayDays, 90);
  assert.equal(account.quorum.palmWallet.built, false, 'nothing is deployed until it is needed');
  assert.equal(env.node.sent.length, 1);
  assert.equal(env.node.sent[0].from, eoa, 'the owner\'s own account paid to move its coins');
  assert.equal(env.node.sent[0].to, account.address);
  assert.ok(env.node.balances.get(account.address) > ETH * 99n / 100n, 'the coins are at the wallet address');
});

test('a payment: the palm, the signer\'s key, the palm key, then the gas account builds the wallet and sends', async t => {
  const env = await startChain(t);
  const { alex, account } = await lockedWallet(env);
  const config = ok(await env.client().get('/api/config'));
  assert.match(config.gasAccount, /^0x[0-9a-f]{40}$/);

  const amount = (ETH / 4n).toString();
  const { operation } = ok(await alex.post('/api/withdrawals', { network: 'ethereum', to: PAYEE, amount }));
  assert.equal(operation.details.wallet, account.address);
  assert.equal(operation.details.amount_units, amount);
  assert.equal(operation.details.approvals_required, '1 of 1 signer and the palm');
  await palmApprove(env, alex, operation.id);

  let view = ok(await alex.get('/api/wallet')).pending.find(op => op.id === operation.id);
  assert.equal(view.needsSignature, true, 'the dashboard asks for this person\'s signature');

  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.equal(unlocked.palmWallet.wallet, account.address);
  const { signature } = signPalmWalletTransfer(PHRASE, unlocked);

  // No gas yet: nothing goes out, and the person is told where to send test coins.
  const empty = await alex.post(`/api/operations/${operation.id}/signature`, { signature });
  assert.equal(empty.status, 409);
  assert.match(empty.body.error, new RegExp(`needs ETH to pay the network fee\\. Send some from a faucet to ${config.gasAccount}`));
  assert.equal(env.node.sent.length, 1, 'only the earlier move');

  env.node.balances.set(config.gasAccount, ETH);
  const { txid } = ok(await alex.post(`/api/operations/${operation.id}/signature`, {}));
  assert.ok(txid);
  const [build, pay] = env.node.sent.slice(-2);
  assert.equal(build.to, DEPLOYER);
  assert.equal(build.from, config.gasAccount);
  assert.ok(env.node.code.has(account.address), 'the wallet now exists, exactly where it was promised');
  assert.equal(pay.to, account.address);
  assert.equal(pay.from, config.gasAccount);

  const digest = eip712TransferDigest({ chainId: 11155111, wallet: account.address, transfer: unlocked.palmWallet.transfer });
  const sigs = signaturesIn(pay.data);
  assert.deepEqual(sigs.signers.map(sig => recoverAddress(digest, sig)), account.quorum.palmWallet.signers);
  assert.equal(recoverAddress(digest, sigs.palm), account.quorum.palmWallet.palmSigner.toLowerCase());
  assert.equal(env.node.balances.get(PAYEE.toLowerCase()), ETH / 4n);

  // A second payment: the wallet is built, so one transaction, at the wallet's next number.
  const second = ok(await alex.post('/api/withdrawals', { network: 'ethereum', to: PAYEE, amount: '1000' }));
  await palmApprove(env, alex, second.operation.id);
  const again = ok(await alex.post(`/api/operations/${second.operation.id}/unlock`, {}));
  assert.equal(again.palmWallet.transfer.nonce, '1');
  const before = env.node.sent.length;
  ok(await alex.post(`/api/operations/${second.operation.id}/signature`, { signature: signPalmWalletTransfer(PHRASE, again).signature }));
  assert.equal(env.node.sent.length, before + 1);
  view = ok(await alex.get('/api/wallet')).history.find(op => op.id === second.operation.id);
  assert.equal(view.status, 'done');
});

test('a Palm Wallet takes only its own signer\'s signature, over exactly the approved transfer', async t => {
  const env = await startChain(t);
  const { alex } = await lockedWallet(env);
  const { operation } = ok(await alex.post('/api/withdrawals', { network: 'ethereum', to: PAYEE, amount: '5000' }));
  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));

  // Another key entirely.
  const stranger = signPalmWalletTransfer('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong', unlocked);
  const refused = await alex.post(`/api/operations/${operation.id}/signature`, { signature: stranger.signature });
  assert.equal(refused.status, 400);
  assert.match(refused.body.error, /only add a signature from its own key/);

  // The right key, over a different transfer: the browser refuses before it signs.
  assert.throws(() => signPalmWalletTransfer(PHRASE, {
    ...unlocked, palmWallet: { ...unlocked.palmWallet, transfer: { ...unlocked.palmWallet.transfer, amount: '9999' } },
  }), /not what was approved/);
});

/* ------------------------------------------------------------- the audit's findings, closed */

/** What a signer's browser trusts to check a palm decision: Veyns' published keys, and who they are. */
async function trustFor(env, sub) {
  const { keys } = await (await env.world.fetchImpl(`${ISSUER}/jwks.json`)).json();
  return { issuer: ISSUER, audience: CLIENT_ID, keys, subjects: [sub, `pairwise:${CLIENT_ID}:${sub}`] };
}

test('every payment pays Palm 0.1% and its own network fee, shown before the palm; send everything fits exactly', async t => {
  const env = await startChain(t);
  const { alex, account } = await lockedWallet(env);
  const config = ok(await env.client().get('/api/config'));
  env.node.balances.set(config.gasAccount, ETH);

  const amount = ETH / 2n;
  const { operation } = ok(await alex.post('/api/withdrawals', { network: 'ethereum', to: PAYEE, amount: amount.toString() }));
  const d = operation.details;
  assert.equal(d.palm_fee_units, (amount / 1000n).toString(), 'Palm takes exactly 0.1%');
  assert.equal(d.palm_fee_to, config.gasAccount, 'to the gas account until PALM_FEE_ADDRESS is set');
  assert.match(d.palm_fee, /which is 0\.1%/);
  assert.ok(BigInt(d.network_fee_units) > 0n, 'the network fee is paid back by the wallet');
  assert.match(d.network_fee, /including building the wallet/, 'the first payment also pays for building it');
  assert.match(operation.statement, /plus .* in fees$/);
  assert.ok(d.good_until, 'the signed payment expires');

  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  const before = env.node.balances.get(account.address);
  ok(await alex.post(`/api/operations/${operation.id}/signature`, { signature: signPalmWalletTransfer(PHRASE, unlocked).signature }));
  assert.equal(env.node.balances.get(PAYEE.toLowerCase()), amount);
  assert.equal(before - env.node.balances.get(account.address), amount + amount / 1000n + BigInt(d.network_fee_units));

  // Send everything: amount, fee and network fee add up to no more than the wallet holds.
  const all = ok(await alex.post('/api/withdrawals', { network: 'ethereum', to: PAYEE, amount: 'max' }));
  const total = BigInt(all.operation.details.amount_units) + BigInt(all.operation.details.palm_fee_units) + BigInt(all.operation.details.network_fee_units);
  assert.ok(total <= env.node.balances.get(account.address));
  assert.ok(env.node.balances.get(account.address) - total < 1000n, 'and leaves next to nothing behind');
});

test('a refresh: the palm, the signer and the palm key close the recovery path again, and the wallet pays its fee', async t => {
  const env = await startChain(t);
  const { alex, account } = await lockedWallet(env, 90);
  const config = ok(await env.client().get('/api/config'));
  env.node.balances.set(config.gasAccount, ETH);
  const { operation } = ok(await alex.post('/api/vault/refresh/approval', { network: 'ethereum' }));
  assert.match(operation.statement, /^Refresh my Ethereum Palm Wallet, so its recovery path stays closed$/);
  assert.match(operation.details.effect, /about 90 more days/);
  await palmApprove(env, alex, operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.equal(unlocked.palmWallet.kind, 'refresh');
  const { txid } = ok(await alex.post(`/api/operations/${operation.id}/signature`, { signature: signPalmWalletTransfer(PHRASE, unlocked).signature }));
  assert.ok(txid);
  assert.equal(env.node.sent.at(-1).to, account.address);
  assert.equal(env.node.lastActivity.get(account.address), 1_800_005_000n, 'the wallet records the refresh');
  const view = await ethereum(alex);
  assert.equal(view.quorum.palmWallet.clock.opensAt, 1_800_005_000 + 90 * 86400);
});

test('audit H4: a vault cannot be erased while its Palm Wallet holds coins', async t => {
  const env = await startChain(t);
  const { alex } = await lockedWallet(env);
  const refused = await alex.post('/api/wallet/reset/approval', {});
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /cannot be erased while coins are locked to the chain: Ethereum at 0x[0-9a-f]{40} holds 0\.99/);
});

test('audit H2: a database writer who redirects the lock move is refused by the browser\'s own check of the palm', async t => {
  const env = await startChain(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await addAccount(env, alex, { network: 'ethereum' });
  await signingKey(env, alex, alex.id);
  env.node.balances.set(ADDRESSES.ethereum.address.toLowerCase(), ETH);
  const asked = ok(await alex.post('/api/accounts/lock', { network: 'ethereum', required: 1, palm: true }));
  await palmApprove(env, alex, asked.operation.id);
  const trust = await trustFor(env, 'sub-alex');

  // Untouched, the browser's check passes.
  const honest = ok(await alex.post(`/api/operations/${asked.operation.id}/unlock`, {}));
  assert.doesNotThrow(() => checkPalmProof(honest, trust));

  // The attacker rewrites where the coins go, and every hash the server keeps, consistently.
  const db = await env.app.db();
  const [row] = (await db.query('SELECT payload, details FROM operations WHERE id = $1', [asked.operation.id])).rows;
  const payload = JSON.parse(row.payload);
  const details = JSON.parse(row.details);
  payload.to = '0x6666666666666666666666666666666666666666';
  const digest = transferDigest(canonicalTransfer({ chain: 'evm', network: payload.network, from: payload.from, plan: payload }));
  payload.transactionHash = digest;
  details.to = payload.to;
  details.transaction_hash = digest;
  await db.query('UPDATE operations SET payload = $1, details = $2 WHERE id = $3', [JSON.stringify(payload), JSON.stringify(details), asked.operation.id]);

  const tampered = ok(await alex.post(`/api/operations/${asked.operation.id}/unlock`, {}));
  assert.equal(tampered.transfer.to, payload.to, 'the server hands over the rewritten transfer');
  assert.throws(() => checkPalmProof(tampered, trust), /approves a different action/);
});

test('the wallet code the app deploys was built from the contract source in this repository', async () => {
  const fs = await import('node:fs');
  const crypto = await import('node:crypto');
  const { PALM_WALLET_SOURCE_SHA256 } = await import('../src/palm-wallet-code.js');
  const source = fs.readFileSync(new URL('../contracts/contracts/PalmWallet.sol', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  assert.equal(crypto.createHash('sha256').update(source).digest('hex'), PALM_WALLET_SOURCE_SHA256,
    'PalmWallet.sol changed: compile it and run node scripts/export-palm-wallet.js');
});
