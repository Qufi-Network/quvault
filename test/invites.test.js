/*
 * Joining a vault by invitation. The vault's own quorum authorises the invitation; the code
 * that comes out of it is worth nothing without the invited person's palm; and it works once.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEST, start, ok, signedIn, palmApprove, walletFor, setRules } from './harness.js';

/** Creates an invitation and returns its code, with the palms it takes. */
async function invite(env, owner, { label, network = 'bitcoin', approvers = [] } = {}) {
  const { operation } = ok(await owner.post('/api/invites/approval', { network, label }));
  const palms = [owner, ...approvers];
  for (let i = 0; i < operation.required; i++) await palmApprove(env, palms[i], operation.id);
  const { invites } = ok(await owner.get('/api/invites'));
  return { operation, code: invites.find(item => item.label === label)?.code };
}

test('an invitation is authorised by the vault, and redeemed by the invited palm', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);

  // Nothing exists until the palms that guard the account approve it.
  const request = ok(await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Bob' }));
  assert.equal(request.operation.kind, 'invite');
  assert.match(request.operation.statement, /Invite Bob/);
  assert.equal(ok(await alex.get('/api/invites')).invites.length, 0, 'no code before the palm');

  await palmApprove(env, alex, request.operation.id);
  const { invites } = ok(await alex.get('/api/invites'));
  assert.equal(invites.length, 1);
  const code = invites[0].code;
  assert.match(code, /^QV-[A-Z0-9]{1,8}-[A-Z0-9]{1,8}$/);
  assert.equal(invites[0].label, 'Bob');

  // Bob is not a signer yet, and the code alone changes nothing.
  assert.deepEqual(ok(await alex.get('/api/wallet')).members.map(m => m.label), ['Owner']);
  const join = ok(await bob.post('/api/invites/join', { code }));
  assert.equal(join.operation.kind, 'join');
  assert.deepEqual(ok(await alex.get('/api/wallet')).members.map(m => m.label), ['Owner'], 'still nothing');

  // His palm is what accepts it.
  await palmApprove(env, bob, join.operation.id);
  const view = ok(await alex.get('/api/wallet'));
  assert.deepEqual(view.members.map(m => m.label).sort(), ['Bob', 'Owner']);
  const account = view.accounts.find(item => item.network === 'bitcoin');
  assert.deepEqual(account.signers.map(s => s.label).sort(), ['Bob', 'Owner'], 'and he signs for the account');

  // The code is spent, and Bob now sees the vault he signs for.
  assert.equal(ok(await alex.get('/api/invites')).invites.length, 0);
  assert.equal((await bob.post('/api/invites/join', { code })).status, 404, 'a spent code is not an open invitation');
  assert.equal(ok(await bob.get('/api/wallet')).wallet, null, 'he has no vault of his own');
});

test('a code is useless without the invited palm, and nobody else can spend it', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  const mallory = await signedIn(env, 'sub-mallory');
  await walletFor(env, alex);
  const { code } = await invite(env, alex, { label: 'Bob' });

  // Mallory has the code. She still needs a palm, and hers only adds her.
  const hers = ok(await mallory.post('/api/invites/join', { code }));
  const stranger = await bob.post(`/api/operations/${hers.operation.id}/approval`, {});
  assert.ok(stranger.status >= 400, 'somebody else cannot approve her joining');
  // Alex cannot wave it through on her behalf either.
  assert.equal((await alex.post(`/api/operations/${hers.operation.id}/approval`, {})).status, 403);
  assert.deepEqual(ok(await alex.get('/api/wallet')).members.map(m => m.label), ['Owner']);

  // A code that was never issued is refused outright.
  assert.equal((await bob.post('/api/invites/join', { code: 'QV-NOPE-NOPE' })).status, 404);
});

test('an invitation takes the account\'s own quorum, and can be cancelled', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  const cara = await signedIn(env, 'sub-cara');
  await walletFor(env, alex);

  // Two of two, so one palm is not enough to invite a third person.
  const { code: firstCode } = await invite(env, alex, { label: 'Bob' });
  const join = ok(await bob.post('/api/invites/join', { code: firstCode }));
  await palmApprove(env, bob, join.operation.id);
  await setRules(env, alex, { rules: [{ upToSats: null, approvals: 2 }], approvers: [bob] });

  const request = ok(await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Cara' }));
  assert.equal(request.operation.required, 2);
  await palmApprove(env, alex, request.operation.id);
  assert.equal(ok(await alex.get('/api/invites')).invites.length, 0, 'one palm of two issues nothing');

  await palmApprove(env, bob, request.operation.id);
  const { invites } = ok(await alex.get('/api/invites'));
  assert.equal(invites.length, 1);

  // And an invitation can be withdrawn before it is used.
  ok(await alex.post('/api/invites/cancel', { code: invites[0].code }));
  assert.equal(ok(await alex.get('/api/invites')).invites.length, 0);
  assert.equal((await cara.post('/api/invites/join', { code: invites[0].code })).status, 404);
});

test('a signer is told what is waiting for their palm', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);
  const { code } = await invite(env, alex, { label: 'Bob' });
  const join = ok(await bob.post('/api/invites/join', { code }));
  await palmApprove(env, bob, join.operation.id);
  await setRules(env, alex, { rules: [{ upToSats: null, approvals: 2 }], approvers: [bob] });

  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 600_000 }];
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 200_000 }));

  // Bob's own view says it is waiting for him, before he has done anything.
  const waiting = ok(await bob.get('/api/wallet')).pending.find(op => op.id === operation.id);
  assert.ok(waiting, 'he can see it at all');
  assert.equal(waiting.needsYou, true);
  assert.match(waiting.statement, /Send 0.00200000 tBTC/);

  // Once he has approved, it no longer asks him.
  await palmApprove(env, bob, operation.id);
  const after = ok(await bob.get('/api/wallet')).pending.find(op => op.id === operation.id);
  assert.equal(after?.needsYou ?? false, false);
  // And Alex, who has not approved yet, is still being asked.
  assert.equal(ok(await alex.get('/api/wallet')).pending.find(op => op.id === operation.id).needsYou, true);
});
