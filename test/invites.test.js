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
  assert.match(code, /^[A-HJ-NP-Z2-9]{8}$/, 'eight characters, none that read alike');
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
  ok(await alex.post('/api/invites/cancel', { id: invites[0].id }));
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

  // A change that needs both palms shows up in each signer's pending view, before a vault is
  // ever locked. (A shared vault's spend lives on the locked multisig path, covered elsewhere.)
  const { operation } = ok(await alex.post('/api/policy', { rules: [{ upToSats: 100_000, approvals: 2 }, { upToSats: null, approvals: 2 }] }));

  // Bob's own view says it is waiting for him, before he has done anything.
  const waiting = ok(await bob.get('/api/wallet')).pending.find(op => op.id === operation.id);
  assert.ok(waiting, 'he can see it at all');
  assert.equal(waiting.needsYou, true);

  // Once he has approved, it no longer asks him.
  await palmApprove(env, bob, operation.id);
  const after = ok(await bob.get('/api/wallet')).pending.find(op => op.id === operation.id);
  assert.equal(after?.needsYou ?? false, false);
  // And Alex, who has not approved yet, is still being asked.
  assert.equal(ok(await alex.get('/api/wallet')).pending.find(op => op.id === operation.id).needsYou, true);
});

test('an invitation code changes every ten minutes, only its maker sees it, and it lapses in a day', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  const cara = await signedIn(env, 'sub-cara');
  await walletFor(env, alex);
  const { code: first } = await invite(env, alex, { label: 'Bob' });

  // Bob, who was invited, is not shown the code by the server: only Alex, who made it.
  assert.equal(ok(await bob.get('/api/invites')).invites.length, 0);
  assert.equal(ok(await cara.get('/api/invites')).invites.length, 0);

  // Ten minutes on, the code is a different one; the one just before still works for a moment.
  env.advance(600);
  const second = ok(await alex.get('/api/invites')).invites[0].code;
  assert.notEqual(second, first);
  // Twenty minutes on, the first code is dead, and the current one is what Bob needs.
  env.advance(600);
  const third = ok(await alex.get('/api/invites')).invites[0].code;
  assert.equal((await bob.post('/api/invites/join', { code: first })).status, 404, 'an old code is refused');
  const join = ok(await bob.post('/api/invites/join', { code: third.toLowerCase() }));
  assert.equal(join.operation.kind, 'join');

  // An invitation nobody redeems lapses after a day, whatever its code.
  const { code: forCara } = await invite(env, alex, { label: 'Cara' });
  assert.ok(forCara);
  env.advance(24 * 3600 + 1);
  assert.equal(ok(await alex.get('/api/invites')).invites.some(item => item.label === 'Cara'), false);
});

test('an invitation made for one person cannot be redeemed by anyone else', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  const mallory = await signedIn(env, 'sub-mallory');
  await walletFor(env, alex);

  // A code nobody has is refused before any palm is asked for.
  assert.equal((await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Bob', approverCode: 'nobody' })).status, 400);

  const { operation } = ok(await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Bob', approverCode: bob.id }));
  assert.match(JSON.stringify(operation.details), /only_for/);
  await palmApprove(env, alex, operation.id);
  const [made] = ok(await alex.get('/api/invites')).invites;
  assert.equal(made.onlyFor, bob.id);

  // Mallory has the code, and it does her no good.
  assert.equal((await mallory.post('/api/invites/join', { code: made.code })).status, 403);
  const join = ok(await bob.post('/api/invites/join', { code: made.code }));
  await palmApprove(env, bob, join.operation.id);
  assert.deepEqual(ok(await alex.get('/api/wallet')).members.map(m => m.label).sort(), ['Bob', 'Owner']);
});
