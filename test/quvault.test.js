import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { actionDigest } from '../src/veyns.js';
import { serverKeys, seal, open as openSealed } from '../src/vault.js';
import { createKey, publicKeyOf, addressOf, planSpend, signPlan } from '../src/bitcoin.js';
import { PolicyError, requiredFor, requiredToChange, validatePolicy } from '../src/policy.js';
import { deriveAttestationKeys } from '../src/authorization.js';
import { DEST, SEED, start, ok, signedIn, palmApprove, walletFor, signAndSend, setRules, attestFor } from './harness.js';

test('the vault seals a key so only this server seed can open it', () => {
  const keys = serverKeys(SEED);
  const secret = crypto.randomBytes(32);
  const sealed = seal(secret, keys);
  assert.deepEqual(openSealed(sealed, keys), secret);
  assert.notEqual(seal(secret, keys), seal(secret, keys), 'every sealing is different');
  assert.throws(() => openSealed(sealed, serverKeys(crypto.randomBytes(64).toString('base64'))));
  const tampered = Buffer.from(sealed, 'base64');
  tampered[tampered.length - 5] ^= 1;
  assert.throws(() => openSealed(tampered.toString('base64'), keys));
});

test('the rules pick a quorum by amount and cannot be written badly', () => {
  const policy = validatePolicy({ rules: [{ upToSats: 100_000, approvals: 1 }, { upToSats: 5_000_000, approvals: 2 }, { upToSats: null, approvals: 3 }] }, 3);
  assert.equal(requiredFor(policy, 50_000).approvals, 1);
  assert.equal(requiredFor(policy, 100_000).approvals, 1, 'the limit is inclusive');
  assert.equal(requiredFor(policy, 100_001).approvals, 2);
  assert.equal(requiredFor(policy, 9_000_000).approvals, 3);
  assert.equal(requiredToChange(policy, 3), 3, 'weakening the rules needs the strongest quorum');
  assert.equal(requiredToChange(policy, 2), 2, 'never more than the people available');

  const bad = [
    [{ rules: [] }, 1, /at least one rule/],
    [{ rules: [{ upToSats: 10, approvals: 1 }] }, 1, /last rule must cover any amount/],
    [{ rules: [{ upToSats: null, approvals: 2 }] }, 1, /2 approvals but the wallet has 1 approver/],
    [{ rules: [{ upToSats: 100, approvals: 2 }, { upToSats: null, approvals: 1 }] }, 2, /cannot need fewer approvals/],
    [{ rules: [{ upToSats: 500, approvals: 1 }, { upToSats: 100, approvals: 2 }, { upToSats: null, approvals: 3 }] }, 3, /in order/],
    [{ rules: [{ upToSats: null, approvals: 1 }, { upToSats: null, approvals: 2 }] }, 2, /Only the last rule/],
    [{ rules: [{ upToSats: 1.5, approvals: 1 }, { upToSats: null, approvals: 1 }] }, 2, /whole number of satoshis/],
  ];
  for (const [input, members, message] of bad) {
    assert.throws(() => validatePolicy(input, members), error => error instanceof PolicyError && message.test(error.message), JSON.stringify(input));
  }
});

test('creating the wallet needs a palm scan, and binds the key to that account', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  assert.equal(ok(await c.get('/api/wallet')).wallet, null);

  const { operation } = ok(await c.post('/api/wallet/approval', { label: 'Alex' }));
  assert.equal(operation.statement, 'Create a testnet4 Bitcoin wallet that only my palm can spend from');
  assert.equal(operation.required, 1);
  assert.equal(ok(await c.get('/api/wallet')).wallet, null, 'no wallet until the palm scan');

  const settled = await palmApprove(env, c, operation.id);
  assert.equal(settled.operation.status, 'done');
  assert.equal(ok(await c.get('/api/wallet')).wallet, null, 'still no wallet: the browser has not made a key yet');

  const unlocked = ok(await c.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.ok(unlocked.unlock && unlocked.salt, 'the browser gets its unlock secret and salt');
  const key = createKey();
  const publicKey = publicKeyOf(key);
  const address = addressOf(publicKey);

  // The address must match the public key, and the public key must look like one.
  assert.equal((await c.post('/api/wallet/register', { operationId: operation.id, address, publicKey: 'nope' })).status, 400);
  assert.equal((await c.post('/api/wallet/register', { operationId: operation.id, address: DEST, publicKey: publicKey.toString('hex') })).status, 400);
  const attestation = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  // A vault with no attestation key of its own cannot be registered at all.
  const noKey = await c.post('/api/wallet/register', { operationId: operation.id, address, publicKey: publicKey.toString('hex') });
  assert.equal(noKey.status, 400);
  assert.match(noKey.body.error, /attestation public key/);
  assert.equal((await c.post('/api/wallet/register', {
    operationId: operation.id, address, publicKey: publicKey.toString('hex'), attestationPublicKey: 'not-a-key',
  })).status, 400);
  ok(await c.post('/api/wallet/register', {
    operationId: operation.id, address, publicKey: publicKey.toString('hex'),
    attestationPublicKey: attestation.publicKeyBase64, attestationEpoch: 1,
  }));

  const view = ok(await c.get('/api/wallet'));
  assert.equal(view.wallet.address, address);
  // The server holds the public half, and says whose key it is.
  assert.equal(view.wallet.attestation.publicKey, attestation.publicKeyBase64);
  assert.equal(view.wallet.attestation.keyId, attestation.keyId);
  assert.equal(view.wallet.attestation.epoch, 1);
  assert.equal(view.members.length, 1);
  assert.equal(view.members[0].label, 'Alex');
  assert.ok(view.members[0].owner);
  // Putting a palm to the vault gives that person an identity inside it.
  assert.match(view.members[0].palmId, /^PALM-[0-9A-Z]{12}$/);
  assert.ok(view.members[0].palmAt > 0);
  assert.deepEqual(view.policy.rules, [{ upToSats: null, approvals: 1 }]);
  assert.equal(env.world.log.acks.length, 1);

  assert.equal((await c.post('/api/wallet/approval', {})).status, 409);
  const other = await signedIn(env, 'sub-omar');
  assert.notEqual((await walletFor(env, other)).address, view.wallet.address);
});

test('the server keeps no key: it never receives one and cannot sign', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);
  env.world.chain.utxos = [{ txid: '9'.repeat(64), vout: 0, value: 300_000 }];

  const { operation } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 70_000 }));
  const settled = await palmApprove(env, c, operation.id);
  assert.equal(settled.operation.status, 'running', 'approved, and now waiting for the owner to sign');
  assert.equal(env.world.log.broadcast.length, 0, 'the server did not sign anything itself');

  const sent = await signAndSend(env, c, operation.id);
  assert.ok(sent.txid);
  assert.equal(env.world.log.broadcast.length, 1);
  assert.equal(ok(await c.get('/api/wallet')).history[0].txid, sent.txid);
});

test('a transaction that does not match the approved plan is never sent', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);
  const other = await signedIn(env, 'sub-omar');
  env.world.chain.utxos = [{ txid: '8'.repeat(64), vout: 0, value: 300_000 }];

  const { operation, plan } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 70_000 }));
  assert.equal((await c.post(`/api/operations/${operation.id}/unlock`, {})).status, 409, 'no unlock before the palms');
  assert.equal((await c.post(`/api/operations/${operation.id}/broadcast`, { hex: '00' })).status, 409, 'no sending before the palms');
  await palmApprove(env, c, operation.id);
  assert.equal((await other.post(`/api/operations/${operation.id}/unlock`, {})).status, 404, 'nobody else can unlock it');

  // Sign a transaction that pays somewhere else.
  const sneaky = signPlan({
    privateKey: c.key,
    publicKey: c.publicKey,
    plan: { ...plan, outputs: [{ address: addressOf(publicKeyOf(createKey())), sats: plan.outputs[0].sats }, plan.outputs[1]] },
  });
  const unlockedForAttack = ok(await c.post(`/api/operations/${operation.id}/unlock`, {}));
  const genuine = attestFor(env, c, unlockedForAttack);
  const refused = await c.post(`/api/operations/${operation.id}/broadcast`, { hex: sneaky.hex, authorization: genuine });
  assert.equal(refused.status, 400);
  assert.match(refused.body.error, /different amounts|different coins/);
  assert.match((await c.post(`/api/operations/${operation.id}/broadcast`, { hex: 'not hex at all', authorization: genuine })).body.error, /not a readable/);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing reached the network');

  const sent = await signAndSend(env, c, operation.id);
  assert.equal(env.world.log.broadcast.length, 1);
  assert.equal(ok(await c.post(`/api/operations/${operation.id}/broadcast`, { hex: '00' })).txid, sent.txid, 'repeats return the same result');
  assert.equal(env.world.log.broadcast.length, 1);
});

test('accounts on other networks are added with a palm, and addresses are checked', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);

  const first = ok(await c.get('/api/wallet'));
  assert.deepEqual(first.accounts.map(a => a.network), ['bitcoin'], 'the wallet starts with its Bitcoin account');
  assert.deepEqual(first.networks.map(n => n.id), ['bitcoin', 'ethereum', 'tron', 'solana', 'stellar']);
  assert.deepEqual(first.networks.filter(n => n.canSend).map(n => n.id), ['bitcoin'], 'only Bitcoin can send today');

  assert.match((await c.post('/api/accounts/approval', { network: 'dogecoin' })).body.error, /supported networks/);
  const { operation } = ok(await c.post('/api/accounts/approval', { network: 'ethereum' }));
  assert.equal(operation.statement, 'Add a Ethereum account to my vault');
  assert.equal(ok(await c.get('/api/wallet')).accounts.length, 1, 'nothing added before the palm');

  const settled = await palmApprove(env, c, operation.id);
  assert.equal(settled.operation.status, 'done');
  // The browser derives the address from the same phrase; a wrong-looking one is refused.
  assert.match((await c.post('/api/accounts/register', { operationId: operation.id, address: 'not-an-address' })).body.error, /does not look like a Ethereum address/);
  ok(await c.post('/api/accounts/register', {
    operationId: operation.id, address: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', publicKey: 'ab'.repeat(33),
  }));

  const after = ok(await c.get('/api/wallet'));
  assert.deepEqual(after.accounts.map(a => a.network), ['bitcoin', 'ethereum']);
  const ethereum = after.accounts[1];
  assert.equal(ethereum.symbol, 'ETH');
  assert.equal(ethereum.chain, 'sepolia');
  assert.equal(ethereum.canSend, false);
  assert.match(ethereum.explorer, /sepolia\.etherscan\.io/);
  assert.ok(ethereum.qr.startsWith('<svg'));
  assert.equal((await c.post('/api/accounts/approval', { network: 'ethereum' })).status, 409, 'one account per network');
});

test('the recovery phrase needs two palm scans', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);

  const { operation } = ok(await c.post('/api/recovery', {}));
  assert.equal(operation.required, 2);
  assert.match(operation.details.scans, /two palm scans/);

  const first = await palmApprove(env, c, operation.id);
  assert.equal(first.operation.status, 'collecting', 'one hand is not enough');
  assert.equal((await c.post(`/api/operations/${operation.id}/unlock`, {})).status, 409);

  const second = await palmApprove(env, c, operation.id);
  assert.equal(second.operation.status, 'done');
  const unlocked = ok(await c.post(`/api/operations/${operation.id}/unlock`, {}));
  assert.equal(unlocked.unlock, c.unlock, 'the same unlock secret opens the phrase on this device');
  assert.equal((await c.post(`/api/operations/${operation.id}/approval`, {})).status, 409, 'no third scan');
});

test('a decision that is not a palm scan never creates a wallet', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  const { operation } = ok(await c.post('/api/wallet/approval', {}));
  const settled = await palmApprove(env, c, operation.id, { amr: ['veyns:browser'] });
  assert.equal(settled.approval.status, 'failed');
  assert.match(settled.approval.error, /not a palm scan/);
  assert.equal(settled.operation.status, 'collecting');
  assert.equal(ok(await c.get('/api/wallet')).wallet, null);
});

test('a withdrawal is planned, signed only after the palm scan, and broadcast exactly once', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  const wallet = await walletFor(env, c);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 200_000 }];

  const view = ok(await c.get('/api/wallet'));
  assert.equal(view.balance.confirmed, 200_000);
  assert.ok(view.qr.startsWith('<svg'));

  const { operation, plan } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 120_000 }));
  assert.equal(operation.statement, `Send 0.00120000 tBTC to ${DEST}`);
  assert.equal(operation.details.approvals_required, '1 of 1 signer');
  assert.equal(env.world.log.broadcast.length, 0, 'nothing is broadcast before the palm scan');

  const approved = await palmApprove(env, c, operation.id);
  assert.equal(approved.operation.status, 'running', 'approved, waiting for the owner to sign');
  const settled = { operation: { ...approved.operation, ...(await signAndSend(env, c, operation.id)) } };
  assert.ok(settled.operation.txid);
  assert.equal(env.world.log.broadcast.length, 1);

  const sent = env.world.log.broadcast[0].tx;
  assert.equal(sent.id, settled.operation.txid);
  const outputs = [...Array(sent.outputsLength).keys()].map(i => ({
    address: btc.Address(btc.TEST_NETWORK).encode(btc.OutScript.decode(sent.getOutput(i).script)),
    sats: Number(sent.getOutput(i).amount),
  }));
  assert.deepEqual(outputs, plan.outputs);
  assert.equal(outputs.find(o => o.address === DEST).sats, 120_000);
  assert.equal(outputs.find(o => o.address === wallet.address).sats, 200_000 - 120_000 - plan.feeSats);

  ok(await c.get('/api/wallet'));
  assert.equal(env.world.log.broadcast.length, 1, 'polling again does not send it twice');
});

test('a bigger amount needs two palms, from two different people', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 1_000_000 }];

  const after = await setRules(env, alex, {
    add: [{ code: bob.id, label: 'Bob', client: bob }],
    rules: [{ upToSats: 100_000, approvals: 1 }, { upToSats: null, approvals: 2 }],
  });
  assert.deepEqual(after.members.map(m => m.label).sort(), ['Bob', 'Owner']);
  assert.deepEqual(after.policy.rules, [{ upToSats: 100_000, approvals: 1 }, { upToSats: null, approvals: 2 }]);

  // Small: one palm is enough.
  const small = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 50_000 }));
  assert.equal(small.operation.required, 1);
  assert.equal((await palmApprove(env, alex, small.operation.id)).operation.status, 'running');
  await signAndSend(env, alex, small.operation.id);
  assert.equal(env.world.log.broadcast.length, 1);

  // Large: Alex alone is not enough; Bob completes it.
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 1_000_000 }];
  const big = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 400_000 }));
  assert.equal(big.operation.required, 2);
  assert.equal(big.operation.details.approvals_required, '2 of 2 signers');

  const first = await palmApprove(env, alex, big.operation.id);
  assert.equal(first.operation.status, 'collecting');
  assert.deepEqual(first.operation.approvedBy, [alex.id]);
  assert.equal(env.world.log.broadcast.length, 1, 'still nothing sent on one approval');

  assert.equal((await alex.post(`/api/operations/${big.operation.id}/approval`, {})).status, 409, 'one person cannot approve twice');

  const second = await palmApprove(env, bob, big.operation.id);
  assert.equal(second.operation.status, 'running', 'both palms in; now the owner device signs');
  const sent = await signAndSend(env, alex, big.operation.id);
  assert.equal(env.world.log.broadcast.length, 2);
  assert.equal(ok(await bob.get('/api/wallet')).history[0].txid, sent.txid, 'the approver sees it too');
});

test('only approvers can approve, and the rules cannot be weakened alone', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  const mallory = await signedIn(env, 'sub-mallory');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'd'.repeat(64), vout: 0, value: 900_000 }];
  await setRules(env, alex, {
    add: [{ code: bob.id, label: 'Bob', client: bob }],
    rules: [{ upToSats: null, approvals: 2 }],
  });

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 200_000 }));
  assert.equal((await mallory.post(`/api/operations/${operation.id}/approval`, {})).status, 404, 'a stranger cannot even see it');

  // Going back to one approval is itself a two-palm change.
  const relax = ok(await alex.post('/api/policy', { rules: [{ upToSats: null, approvals: 1 }] }));
  assert.equal(relax.operation.required, 2);
  await palmApprove(env, alex, relax.operation.id);
  assert.deepEqual(ok(await alex.get('/api/wallet')).policy.rules, [{ upToSats: null, approvals: 2 }], 'one palm did not change it');
  await palmApprove(env, bob, relax.operation.id);
  assert.deepEqual(ok(await alex.get('/api/wallet')).policy.rules, [{ upToSats: null, approvals: 1 }]);

  // And a rule cannot ask for more approvals than there are people.
  assert.match((await alex.post('/api/policy', { rules: [{ upToSats: null, approvals: 5 }] })).body.error, /5 approvals but the wallet has 2/);
});

test('a withdrawal approved for a different action is refused', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);
  env.world.chain.utxos = [{ txid: 'e'.repeat(64), vout: 0, value: 200_000 }];
  const { operation } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 50_000 }));

  const { approval } = ok(await c.post(`/api/operations/${operation.id}/approval`, {}));
  ok(await c.post(`/api/approvals/${approval.id}/palm`, {}));
  const request = env.world.requests.get(env.world.log.created.at(-1).request_id);
  request.action.digest = actionDigest('Send everything to someone else', {});
  env.world.approvePalm(request.request_id);

  const settled = ok(await c.get(`/api/approvals/${approval.id}`));
  assert.equal(settled.approval.status, 'failed');
  assert.match(settled.approval.error, /different action/);
  assert.equal(settled.operation.status, 'collecting');
  assert.equal(env.world.log.broadcast.length, 0);
});

test('bad withdrawals are refused before any approval is created', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);
  env.world.chain.utxos = [{ txid: 'f'.repeat(64), vout: 1, value: 60_000 }];
  const before = env.world.log.created.length;

  assert.match((await c.post('/api/withdrawals', { to: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', amount: 1000 })).body.error, /not a valid testnet4 address/);
  assert.match((await c.post('/api/withdrawals', { to: DEST, amount: 500_000 })).body.error, /Not enough coins/);
  assert.match((await c.post('/api/withdrawals', { to: DEST, amount: 100 })).body.error, /at least/);
  assert.match((await c.post('/api/withdrawals', { to: DEST, amount: 0 })).body.error, /amount in satoshis/);
  assert.equal(env.world.log.created.length, before, 'no palm request was made for any of them');

  const { plan } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 'max' }));
  assert.equal(plan.sentSats + plan.feeSats, 60_000);
  assert.equal(plan.changeSats, 0);
});

test('a failed broadcast is reported and never marked as sent', async t => {
  const env = await start(t);
  const c = await signedIn(env, 'sub-alex');
  await walletFor(env, c);
  env.world.chain.utxos = [{ txid: '1'.repeat(64), vout: 0, value: 150_000 }];
  env.world.chain.broadcastError = 'sendrawtransaction RPC error: txn-mempool-conflict';

  const { operation } = ok(await c.post('/api/withdrawals', { to: DEST, amount: 40_000 }));
  await palmApprove(env, c, operation.id);
  const unlocked = ok(await c.post(`/api/operations/${operation.id}/unlock`, {}));
  const signed = signPlan({ privateKey: c.key, publicKey: c.publicKey, plan: unlocked.plan });
  const rejected = await c.post(`/api/operations/${operation.id}/broadcast`, {
    hex: signed.hex, authorization: attestFor(env, c, unlocked),
  });
  assert.equal(rejected.status, 502);
  assert.match(rejected.body.error, /txn-mempool-conflict/);
  assert.equal(ok(await c.get('/api/wallet')).history[0].status, 'failed');
});

test('a request that never gathers its quorum expires', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: '2'.repeat(64), vout: 0, value: 800_000 }];
  await setRules(env, alex, { add: [{ code: bob.id, label: 'Bob', client: bob }], rules: [{ upToSats: null, approvals: 2 }] });

  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, operation.id);
  env.advance(1801);

  const view = ok(await alex.get('/api/wallet'));
  assert.equal(view.pending.length, 0);
  assert.equal(view.history[0].status, 'failed');
  assert.match(view.history[0].error, /Not enough palm approvals in time/);
  assert.equal((await bob.post(`/api/operations/${operation.id}/approval`, {})).status, 409);
  assert.equal(env.world.log.broadcast.length, 0);
});

test('one person cannot touch another person\'s wallet', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const omar = await signedIn(env, 'sub-omar');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: '3'.repeat(64), vout: 0, value: 100_000 }];
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 30_000 }));

  assert.equal((await omar.post(`/api/operations/${operation.id}/approval`, {})).status, 404);
  assert.equal((await omar.post(`/api/operations/${operation.id}/cancel`, {})).status, 404);
  assert.equal((await omar.post('/api/withdrawals', { to: DEST, amount: 1000 })).status, 409, 'omar has no wallet');
  assert.equal(ok(await omar.get('/api/wallet')).pending.length, 0);
  assert.equal(env.world.log.broadcast.length, 0);
});

test('the signed transaction always matches the stored plan', () => {
  const key = createKey();
  const publicKey = publicKeyOf(key);
  const utxos = [{ txid: '4'.repeat(64), vout: 2, value: 90_000 }];
  const plan = planSpend({ publicKey, utxos, toAddress: DEST, amountSats: 30_000, feeRate: 3 });
  const signed = signPlan({ privateKey: key, publicKey, plan });
  const tx = btc.Transaction.fromRaw(hex.decode(signed.hex));
  assert.equal(tx.id, signed.txid);
  assert.equal(Number(tx.getOutput(0).amount), 30_000);
  assert.ok(Math.abs(plan.feeSats / signed.vsize - 3) < 0.25, 'fee rate is close to the one asked for');
  assert.throws(() => signPlan({ privateKey: key, publicKey, plan: { ...plan, feeSats: plan.feeSats + 500 } }), /does not match the approved plan/);
  assert.equal(addressOf(publicKey), plan.outputs.find(o => o.address !== DEST).address, 'change comes home');
});
