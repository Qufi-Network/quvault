/*
 * Spending from an account the chain guards.
 *
 * The palms gather first, as they always did. What is new is that each of those people then
 * has to sign with their own key, in their own browser. The server can put signatures
 * together; it cannot make one, and nobody can reach the threshold without the others.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend, setRules } from './harness.js';
import { cosignerFrom, signQuorum } from '../client/wallet.js';

const PHRASES = {
  alex: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  bea: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  cara: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
};

async function signingKey(env, client, vaultOwnerId, phrase) {
  const started = ok(await client.post('/api/signing-key/approval', { vaultOwnerId }));
  await palmApprove(env, client, started.operation.id);
  ok(await client.post(`/api/operations/${started.operation.id}/unlock`, {}));
  const key = cosignerFrom(phrase, started.index);
  ok(await client.post('/api/signing-key/register', {
    operationId: started.operation.id,
    publicKey: Buffer.from(key.publicKey).toString('hex'),
  }));
  return key;
}

async function joins(env, owner, guest, label) {
  const { operation } = ok(await owner.post('/api/invites/approval', { network: 'bitcoin', label }));
  for (let i = 0; i < operation.required; i++) await palmApprove(env, owner, operation.id);
  const { invites } = ok(await owner.get('/api/invites'));
  const join = ok(await guest.post('/api/invites/join', { code: invites[0].code }));
  await palmApprove(env, guest, join.operation.id);
}

/** A 2-of-3 vault whose coins already live in the script, with fresh coins to spend. */
async function locked(env, required = 2) {
  const alex = await signedIn(env, 'sub-alex');
  const bea = await signedIn(env, 'sub-bea');
  const cara = await signedIn(env, 'sub-cara');
  for (const who of [alex, bea, cara]) await walletFor(env, who);
  await joins(env, alex, bea, 'Bea');
  await joins(env, alex, cara, 'Cara');
  await signingKey(env, alex, alex.id, PHRASES.alex);
  await signingKey(env, bea, alex.id, PHRASES.bea);
  await signingKey(env, cara, alex.id, PHRASES.cara);
  await setRules(env, alex, { rules: [{ upToSats: null, approvals: 2 }], approvers: [bea] });

  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required }));
  await palmApprove(env, alex, asked.operation.id);
  await palmApprove(env, bea, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);

  const account = ok(await alex.get('/api/wallet')).accounts.find(a => a.network === 'bitcoin');
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 700_000 }];
  return { alex, bea, cara, account };
}

/** A withdrawal with its palms already on it, waiting for signatures. */
async function approvedSpend(env, { owner, palms, amount = 250_000 }) {
  const { operation } = ok(await owner.post('/api/withdrawals', { to: DEST, amount }));
  for (const who of palms) await palmApprove(env, who, operation.id);
  return operation;
}

/** What a signer's browser does once the palms are in: open its own key, add one signature. */
async function addSignature(env, client, operationId, phrase, tweak = {}) {
  const unlocked = ok(await client.post(`/api/operations/${operationId}/unlock`, {}));
  const { psbt } = signQuorum(phrase, {
    psbt: unlocked.psbt,
    plan: unlocked.plan,
    index: unlocked.keyIndex,
    address: unlocked.address,
    transactionHash: unlocked.transactionHash,
    network: 'testnet4',
    ...tweak,
  });
  return { unlocked, result: await client.post(`/api/operations/${operationId}/signature`, { psbt }) };
}

test('two signers send the money, each with their own key after their own palm', async t => {
  const env = await start(t);
  const { alex, bea, account } = await locked(env);
  const operation = await approvedSpend(env, { owner: alex, palms: [alex, bea] });
  assert.equal(operation.required, 2, 'the threshold is the one the chain keeps');

  const first = await addSignature(env, alex, operation.id, PHRASES.alex);
  assert.equal(ok(first.result).signatures, 1);
  assert.equal(ok(first.result).txid, null, 'one signature sends nothing');
  assert.equal(env.world.log.broadcast.length, 1, 'only the lock has gone out so far');
  assert.equal(first.unlocked.address, account.address, 'and it is the script being spent');

  const second = await addSignature(env, bea, operation.id, PHRASES.bea);
  assert.equal(ok(second.result).signatures, 2);
  assert.ok(ok(second.result).txid, 'the second signature sends it');

  const sent = env.world.log.broadcast.at(-1);
  assert.equal(sent.txid, ok(second.result).txid);
  const outputs = [...Array(sent.tx.outputsLength).keys()].map(i => Number(sent.tx.getOutput(i).amount));
  assert.ok(outputs.includes(250_000), 'the amount that was approved really left');
  assert.equal(ok(await alex.get('/api/wallet')).history.find(op => op.id === operation.id).txid, sent.txid);
});

test('a key on the account is not enough without that person\'s palm', async t => {
  const env = await start(t);
  const { alex, bea, cara } = await locked(env);
  const operation = await approvedSpend(env, { owner: alex, palms: [alex, bea] });

  // Cara holds a key this account is locked to, but she did not approve this spend.
  const refused = await cara.post(`/api/operations/${operation.id}/unlock`, {});
  assert.equal(refused.status, 409);
  assert.match(refused.body.error, /Put your palm to this request first/);

  // Nor can she push a signature she made some other way.
  const mine = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  const hers = signQuorum(PHRASES.cara, {
    psbt: mine.psbt, plan: mine.plan, index: 0,
    address: mine.address, transactionHash: mine.transactionHash, network: 'testnet4',
  });
  const pushed = await cara.post(`/api/operations/${operation.id}/signature`, { psbt: hers.psbt });
  assert.equal(pushed.status, 409);
  assert.match(pushed.body.error, /Put your palm/);
  assert.equal(env.world.log.broadcast.length, 1);
});

test('one signer cannot reach the threshold alone, however many times they sign', async t => {
  const env = await start(t);
  const { alex, bea } = await locked(env);
  const operation = await approvedSpend(env, { owner: alex, palms: [alex, bea] });

  assert.equal(ok((await addSignature(env, alex, operation.id, PHRASES.alex)).result).signatures, 1);
  const again = await addSignature(env, alex, operation.id, PHRASES.alex);
  assert.equal(again.result.status, 400, 'a second signature from the same key adds nothing');
  assert.match(again.result.body.error, /added no signature/);
  assert.equal(env.world.log.broadcast.length, 1, 'and nothing further was sent');
});

test('a browser may only add a signature from its own key', async t => {
  const env = await start(t);
  const { alex, bea } = await locked(env);
  const operation = await approvedSpend(env, { owner: alex, palms: [alex, bea] });

  // Bea has approved, so she may sign — but she offers Cara's signature instead of her own.
  const unlocked = ok(await bea.post(`/api/operations/${operation.id}/unlock`, {}));
  const cara = signQuorum(PHRASES.cara, {
    psbt: unlocked.psbt, plan: unlocked.plan, index: 0,
    address: unlocked.address, transactionHash: unlocked.transactionHash, network: 'testnet4',
  });
  const pushed = await bea.post(`/api/operations/${operation.id}/signature`, { psbt: cara.psbt });
  assert.equal(pushed.status, 400);
  assert.match(pushed.body.error, /own key/);
  assert.equal(env.world.log.broadcast.length, 1);
});

test('a signature for one spend cannot be carried to another', async t => {
  const env = await start(t);
  const { alex, bea } = await locked(env);
  const one = await approvedSpend(env, { owner: alex, palms: [alex, bea], amount: 250_000 });
  const mine = ok(await alex.post(`/api/operations/${one.id}/unlock`, {}));

  ok(await alex.post(`/api/operations/${one.id}/cancel`, {}));
  const two = await approvedSpend(env, { owner: alex, palms: [alex, bea], amount: 400_000 });

  const stale = signQuorum(PHRASES.alex, {
    psbt: mine.psbt, plan: mine.plan, index: mine.keyIndex,
    address: mine.address, transactionHash: mine.transactionHash, network: 'testnet4',
  });
  const pushed = await alex.post(`/api/operations/${two.id}/signature`, { psbt: stale.psbt });
  assert.equal(pushed.status, 400);
  assert.match(pushed.body.error, /not for this transaction|added no signature/);
  assert.equal(env.world.log.broadcast.length, 1);
});

test('the browser refuses to sign a plan that is not the one the palm approved', async t => {
  const env = await start(t);
  const { alex, bea } = await locked(env);
  const operation = await approvedSpend(env, { owner: alex, palms: [alex, bea] });
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));

  const tampered = { ...unlocked.plan, outputs: unlocked.plan.outputs.map(o => ({ ...o, sats: o.sats + 1 })) };
  assert.throws(() => signQuorum(PHRASES.alex, {
    psbt: unlocked.psbt, plan: tampered, index: unlocked.keyIndex,
    address: unlocked.address, transactionHash: unlocked.transactionHash, network: 'testnet4',
  }), /not the transaction that was approved/);
});

test('somebody outside the quorum gets nothing to sign with', async t => {
  const env = await start(t);
  const { alex, bea } = await locked(env);
  const mallory = await signedIn(env, 'sub-mallory');
  await walletFor(env, mallory);
  const operation = await approvedSpend(env, { owner: alex, palms: [alex, bea] });

  assert.equal((await mallory.post(`/api/operations/${operation.id}/unlock`, {})).status, 404);
  assert.equal((await mallory.post(`/api/operations/${operation.id}/signature`, { psbt: '' })).status, 404);
});

test('the window runs from the last palm, so whoever approved first can still sign', async t => {
  const env = await start(t);
  const { alex, bea } = await locked(env);
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 250_000 }));

  // Alex approves, and nothing is signable yet because the quorum is not complete.
  await palmApprove(env, alex, operation.id);
  assert.equal((await alex.post(`/api/operations/${operation.id}/unlock`, {})).status, 409);

  // Bea approves twenty minutes later, well past Alex's own five. That later moment is when
  // there is something to sign, and the window starts there for both of them.
  env.advance(1200);
  await palmApprove(env, bea, operation.id);
  assert.equal(ok((await addSignature(env, alex, operation.id, PHRASES.alex)).result).signatures, 1);
  assert.ok(ok((await addSignature(env, bea, operation.id, PHRASES.bea)).result).txid);
});

test('a quorum that is left too long is asked for new palms', async t => {
  const env = await start(t);
  const { alex, bea } = await locked(env);
  const operation = await approvedSpend(env, { owner: alex, palms: [alex, bea] });

  env.advance(301);
  const late = await alex.post(`/api/operations/${operation.id}/unlock`, {});
  assert.equal(late.status, 409);
  assert.match(late.body.error, /been used/);
  assert.equal(env.world.log.broadcast.length, 1);
});

test('the half-signed transaction is rebuilt from the approved plan, never trusted as stored', async t => {
  const env = await start(t);
  const { alex, bea } = await locked(env);
  const operation = await approvedSpend(env, { owner: alex, palms: [alex, bea] });
  ok((await addSignature(env, alex, operation.id, PHRASES.alex)).result);

  // A database that lost or rewrote the half-signed transaction cannot make signatures appear:
  // the transaction is rebuilt from the plan, and what was signed before is genuinely gone.
  const db = await env.app.db();
  await db.query('UPDATE operations SET psbt = $1 WHERE id = $2', [null, operation.id]);

  const second = await addSignature(env, bea, operation.id, PHRASES.bea);
  assert.equal(ok(second.result).signatures, 1, 'one signature, not two');
  assert.equal(ok(second.result).txid, null, 'so nothing is sent');
  assert.equal(env.world.log.broadcast.length, 1);
});
