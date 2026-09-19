/*
 * Signers and thresholds belong to an account. Changing either takes the palms that guard
 * that account as it stands — a new signer cannot wave themselves in, and one account's
 * rules never loosen another's.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { start, ok, signedIn, palmApprove, walletFor, setRules, addAccount, ADDRESSES } from './harness.js';

const DEST = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
const bitcoin = view => view.accounts.find(account => account.network === 'bitcoin');
const accountOn = (view, network) => view.accounts.find(account => account.network === network);

test('a new account is created with its own signers and threshold', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);

  const view = await addAccount(env, alex, {
    network: 'ethereum',
    add: [{ code: bob.id, label: 'Bob' }],
    rules: [{ upToSats: null, approvals: 2 }],
  });

  const ethereum = accountOn(view, 'ethereum');
  assert.equal(ethereum.address, ADDRESSES.ethereum.address);
  assert.deepEqual(ethereum.signers.map(s => s.label).sort(), ['Bob', 'Owner']);
  assert.deepEqual(ethereum.policy.rules, [{ upToSats: null, approvals: 2 }]);
  assert.equal(ethereum.changeRequired, 2, 'two palms to change what two palms guard');

  // The Bitcoin account it was added beside is untouched.
  assert.deepEqual(bitcoin(view).signers.map(s => s.label), ['Owner']);
  assert.deepEqual(bitcoin(view).policy.rules, [{ upToSats: null, approvals: 1 }]);
  assert.equal(bitcoin(view).changeRequired, 1);
});

test('every signer is given a palm identity, and it is the same one everywhere', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);

  const view = await addAccount(env, alex, { network: 'tron', add: [{ code: bob.id, label: 'Bob' }] });
  const tron = accountOn(view, 'tron');
  for (const signer of tron.signers) assert.match(signer.palmId, /^PALM-[0-9A-Z]{12}$/, signer.label);

  const alexPalm = tron.signers.find(s => s.id === alex.id);
  const bobPalm = tron.signers.find(s => s.id === bob.id);
  assert.notEqual(alexPalm.palmId, bobPalm.palmId, 'two people, two identities');
  assert.equal(alexPalm.palmId, bitcoin(view).signers.find(s => s.id === alex.id).palmId, 'one identity per person, per vault');
  assert.ok(alexPalm.palmAt > 0, 'Alex has put a palm to this vault');
  assert.equal(bobPalm.palmAt, null, 'Bob has been named but has not scanned yet');

  // Bob approves something, and the moment his palm lands is recorded.
  const { operation } = ok(await alex.post('/api/policy', { network: 'tron', rules: [{ upToSats: null, approvals: 2 }] }));
  await palmApprove(env, bob, operation.id);
  const after = ok(await alex.get('/api/wallet'));
  assert.ok(accountOn(after, 'tron').signers.find(s => s.id === bob.id).palmAt > 0);
});

test('changing signers or thresholds takes the palms that guard the account today', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  const cara = await signedIn(env, 'sub-cara');
  const dan = await signedIn(env, 'sub-dan');
  await walletFor(env, alex);

  // Three signers, two of three.
  const view = await setRules(env, alex, {
    add: [{ code: bob.id, label: 'Bob', client: bob }, { code: cara.id, label: 'Cara', client: cara }],
    rules: [{ upToSats: null, approvals: 2 }],
  });
  assert.equal(bitcoin(view).signers.length, 3);
  assert.equal(bitcoin(view).changeRequired, 2);

  // Any further change needs two of those three.
  const { operation } = ok(await alex.post('/api/policy', {
    add: [{ code: dan.id, label: 'Dan' }],
    rules: [{ upToSats: null, approvals: 1 }],
  }));
  assert.equal(operation.required, 2);

  // Dan is named in the change but cannot approve his own arrival.
  const dansTry = await dan.post(`/api/operations/${operation.id}/approval`, {});
  assert.equal(dansTry.status, 404, 'Dan is not part of this vault yet');

  const first = await palmApprove(env, alex, operation.id);
  assert.equal(first.operation.status, 'collecting', 'one palm is not enough');
  assert.deepEqual(bitcoin(ok(await alex.get('/api/wallet'))).policy.rules, [{ upToSats: null, approvals: 2 }], 'nothing changed yet');

  await palmApprove(env, cara, operation.id);
  const after = ok(await alex.get('/api/wallet'));
  assert.equal(bitcoin(after).signers.length, 4);
  assert.deepEqual(bitcoin(after).policy.rules, [{ upToSats: null, approvals: 1 }]);
  assert.ok(ok(await dan.get('/api/wallet')).pending !== undefined, 'Dan can see the vault now');
});

test('one account cannot be changed with another account\'s signers', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);

  // Bob signs for Stellar only.
  await addAccount(env, alex, { network: 'stellar', add: [{ code: bob.id, label: 'Bob' }] });
  const view = ok(await alex.get('/api/wallet'));
  assert.deepEqual(accountOn(view, 'stellar').signers.map(s => s.label).sort(), ['Bob', 'Owner']);
  assert.deepEqual(bitcoin(view).signers.map(s => s.label), ['Owner']);

  const { operation } = ok(await alex.post('/api/policy', { network: 'bitcoin', rules: [{ upToSats: null, approvals: 1 }] }));
  const refused = await bob.post(`/api/operations/${operation.id}/approval`, {});
  assert.equal(refused.status, 403);
  assert.match(refused.body.error, /not a signer on that account/);
});

test('a spend answers to the Bitcoin account\'s own threshold', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);
  await setRules(env, alex, {
    add: [{ code: bob.id, label: 'Bob', client: bob }],
    rules: [{ upToSats: 100_000, approvals: 1 }, { upToSats: null, approvals: 2 }],
  });
  // A second account with a single signer must not soften that.
  await addAccount(env, alex, { network: 'solana', approvers: [bob], rules: [{ upToSats: null, approvals: 1 }] });

  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const big = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 400_000 }));
  assert.equal(big.operation.required, 2);
  assert.equal(big.operation.details.approvals_required, '2 of 2 signers');

  await palmApprove(env, alex, big.operation.id);
  assert.equal(env.world.log.broadcast.length, 0, 'still waiting for the second palm');
  const done = await palmApprove(env, bob, big.operation.id);
  assert.equal(done.operation.status, 'running', 'the quorum is in; the owner device signs it');
});
