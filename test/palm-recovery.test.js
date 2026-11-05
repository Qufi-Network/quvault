/*
 * What happens to a palm vault over years and over lives: the recovery clock and the refresh that
 * restarts it, replacing a signer who can never approve again (the owner included), the
 * recovery door an heir uses with nothing but the inheritance sheet and twelve words, and the
 * reminders that come before the recovery path opens.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import * as btc from '@scure/btc-signer';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSend } from './harness.js';
import { cosignerFrom, signQuorum, signRecovery } from '../client/wallet.js';
import { signKeyProof } from '../src/key-proof.js';
import {
  palmVaultOf, palmVaultFromDescriptor, recoveryClock, LEAF_VERSION, DEFAULT_RECOVERY_DELAY,
} from '../src/palm-vault.js';
import { NETWORK } from '../src/bitcoin.js';

const PHRASES = {
  alex: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  bea: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  cara: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
  dave: 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
};
const FCM = 'https://fcm.googleapis.com/fcm/send/';
const subscription = id => ({ endpoint: `${FCM}${id}`, keys: { p256dh: 'B'.repeat(87), auth: 'a'.repeat(22) } });

async function signingKey(env, client, vaultOwnerId, phrase) {
  const started = ok(await client.post('/api/signing-key/approval', { vaultOwnerId }));
  await palmApprove(env, client, started.operation.id);
  ok(await client.post(`/api/operations/${started.operation.id}/unlock`, {}));
  const key = cosignerFrom(phrase, started.index);
  ok(await client.post('/api/signing-key/register', {
    operationId: started.operation.id,
    publicKey: Buffer.from(key.publicKey).toString('hex'),
    proof: signKeyProof(key.privateKey, { vaultOwnerId, memberId: client.id, publicKey: Buffer.from(key.publicKey).toString('hex') }),
  }));
  return key;
}

/** An invitation asked for by `asker` on `ownerId`'s vault, approved by `approvers`, redeemed by `guest`. */
async function invite(env, { asker, ownerId, guest, label, approvers }) {
  const body = { network: 'bitcoin', label, ...(asker.id === ownerId ? {} : { vaultOwnerId: ownerId }) };
  const { operation } = ok(await asker.post('/api/invites/approval', body));
  for (let i = 0; i < operation.required; i++) await palmApprove(env, approvers[i], operation.id);
  const view = ok(await asker.get('/api/wallet'));
  const code = [...view.history, ...view.pending].find(op => op.id === operation.id).inviteCode;
  assert.ok(code, 'the approved invitation has a code');
  const join = ok(await guest.post('/api/invites/join', { code }));
  await palmApprove(env, guest, join.operation.id);
  return operation;
}

const bitcoinAccount = async client => ok(await client.get('/api/wallet')).accounts.find(a => a.network === 'bitcoin');

const vaultOf = account => palmVaultFromDescriptor(account.quorum.palm.descriptor, NETWORK);

async function lockOne(env, body = {}) {
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await signingKey(env, alex, alex.id, PHRASES.alex);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 1, palm: true, ...body }));
  await palmApprove(env, alex, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 700_000 }];
  return { alex, asked, account: await bitcoinAccount(alex) };
}

async function lockThree(env) {
  const [alex, bea, cara] = [await signedIn(env, 'sub-alex'), await signedIn(env, 'sub-bea'), await signedIn(env, 'sub-cara')];
  for (const who of [alex, bea, cara]) await walletFor(env, who);
  await invite(env, { asker: alex, ownerId: alex.id, guest: bea, label: 'Bea', approvers: [alex] });
  await invite(env, { asker: alex, ownerId: alex.id, guest: cara, label: 'Cara', approvers: [alex, bea] });
  await signingKey(env, alex, alex.id, PHRASES.alex);
  await signingKey(env, bea, alex.id, PHRASES.bea);
  await signingKey(env, cara, alex.id, PHRASES.cara);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 2, palm: true }));
  for (let i = 0; i < asked.operation.required; i++) await palmApprove(env, [alex, bea, cara][i], asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 700_000 }];
  return { alex, bea, cara, account: await bitcoinAccount(alex) };
}

async function addSignature(client, operationId, phrase) {
  const unlocked = ok(await client.post(`/api/operations/${operationId}/unlock`, {}));
  const { psbt } = signQuorum(phrase, {
    psbt: unlocked.psbt, plan: unlocked.plan, index: unlocked.keyIndex, address: unlocked.address,
    transactionHash: unlocked.transactionHash, network: 'testnet4', lockKind: unlocked.lockKind,
  });
  return client.post(`/api/operations/${operationId}/signature`, { psbt });
}

/** Every signature in a broadcast palm vault spend, checked the way Bitcoin would, through `path`. */
function checkSpend(sent, vault, amount, path = 'normal') {
  const leaf = vault.leaves[path].script;
  for (let i = 0; i < sent.tx.inputsLength; i++) {
    const witness = sent.tx.getInput(i).finalScriptWitness;
    assert.equal(hex.encode(witness.at(-2)), hex.encode(leaf), `it spends through the ${path} leaf`);
    const message = sent.tx.preimageWitnessV1(i, [vault.script], btc.SigHash.DEFAULT, [BigInt(amount)], undefined, leaf, LEAF_VERSION);
    if (path === 'normal') assert.ok(schnorr.verify(witness.at(-3), message, vault.palmKey), 'the palm key signed');
    const slots = witness.slice(0, vault.keys.length).reverse();
    const valid = slots.filter((sig, k) => sig.length && schnorr.verify(sig, message, vault.keys[k])).length;
    assert.equal(valid, vault.required, `exactly ${vault.required} signer signature(s), each valid`);
  }
}

const outputAddress = (sent, i = 0) => btc.Address(NETWORK).encode(btc.OutScript.decode(sent.tx.getOutput(i).script));

/* ------------------------------------------------------------------ the vault module */

test('a vault description reads back into exactly the vault it describes, and a typo is caught', () => {
  const keys = [PHRASES.alex, PHRASES.bea].map((p, i) => cosignerFrom(p, i).publicKey);
  const palmKey = cosignerFrom(PHRASES.cara, 9).publicKey;
  const vault = palmVaultOf({ palmKey, signerKeys: keys, required: 2, delay: 12960, network: NETWORK });
  const read = palmVaultFromDescriptor(vault.descriptor, NETWORK);
  assert.equal(read.address, vault.address);
  assert.equal(read.delay, 12960);
  assert.equal(read.required, 2);
  // Pasted with spaces and line breaks, as from a printed sheet: still the same vault.
  assert.equal(palmVaultFromDescriptor(vault.descriptor.replace(/(.{40})/g, '$1\n '), NETWORK).address, vault.address);

  const typo = vault.descriptor.replace(/older\(12960\)/, 'older(12961)');
  assert.throws(() => palmVaultFromDescriptor(typo, NETWORK), /checksum does not match/);
  assert.throws(() => palmVaultFromDescriptor('wpkh(02aa)#abcdefgh', NETWORK), /not a Palm vault description/);
});

test('the recovery clock counts from each coin, and opens in the first block late enough', () => {
  const keys = [cosignerFrom(PHRASES.alex, 0).publicKey];
  const vault = palmVaultOf({ palmKey: cosignerFrom(PHRASES.bea, 3).publicKey, signerKeys: keys, required: 1, delay: 1000, network: NETWORK });
  const coins = [{ txid: 'a'.repeat(64), vout: 0, value: 5, height: 500 }, { txid: 'b'.repeat(64), vout: 1, value: 7, height: 200 }];
  const early = recoveryClock(vault, coins, 1100);
  assert.equal(early.nextOpensAt, 1200, 'the oldest coin opens first');
  assert.equal(early.blocksLeft, 99, 'block 1101 is next; 1200 is the first late enough');
  assert.equal(early.readySats, 0);
  const open = recoveryClock(vault, coins, 1199);
  assert.equal(open.coins[0].ready, true);
  assert.equal(open.readySats, 7);
  assert.equal(open.coins[1].ready, false, 'the newer coin is still closed');
});

/* ------------------------------------------------------------------ locking choices */

test('a palm vault can be made with a shorter recovery delay, and a vault of one is warned plainly', async t => {
  const env = await start(t);
  const { asked, account } = await lockOne(env, { recoveryDays: 90 });
  assert.equal(account.quorum.palm.recoveryDelayBlocks, 90 * 144);
  assert.equal(account.quorum.palm.recoveryDelayDays, 90);
  assert.match(asked.operation.details.recovery, /after about 90 days/);
  assert.match(asked.operation.details.warning, /if you die, these coins can only be moved after about 90 days, and only with your twelve words/);
  assert.equal(vaultOf(account).address, account.address);

  const env2 = await start(t);
  const alex = await signedIn(env2, 'sub-alex');
  await walletFor(env2, alex);
  await signingKey(env2, alex, alex.id, PHRASES.alex);
  const refused = await alex.post('/api/accounts/lock', { required: 1, palm: true, recoveryDays: 30 });
  assert.equal(refused.status, 400);
  assert.match(refused.body.error, /90, 180, 365 days/);
});

test('the vault view shows the clock: when the recovery path opens and whether a refresh is due', async t => {
  const env = await start(t);
  const { alex } = await lockOne(env);
  let clock = (await bitcoinAccount(alex)).quorum.palm.clock;
  assert.equal(clock.nextOpensAt, 100 + DEFAULT_RECOVERY_DELAY);
  assert.equal(clock.daysLeft, 365);
  assert.equal(clock.refreshDue, false);

  env.world.chain.tip = 100 + DEFAULT_RECOVERY_DELAY - 40 * 144 - 1;
  env.advance(120);
  clock = (await bitcoinAccount(alex)).quorum.palm.clock;
  assert.equal(clock.daysLeft, 40);
  assert.equal(clock.refreshDue, true);
});

/* ------------------------------------------------------------------ refresh */

test('a refresh sends every coin back into the same vault through the normal path, palm and all', async t => {
  const env = await start(t);
  const { alex, account } = await lockOne(env);
  const { operation, plan } = ok(await alex.post('/api/vault/refresh/approval', {}));
  assert.match(operation.statement, /^Refresh my vault: move 0\.00\d+ tBTC back into it, so its recovery clock starts again, network fee 0\.\d{8} tBTC$/);
  assert.equal(operation.details.to, account.address);
  assert.equal(plan.outputs.length, 1);
  assert.equal(plan.outputs[0].address, account.address, 'the only output is the vault itself');

  await palmApprove(env, alex, operation.id);
  const { txid } = ok(await addSignature(alex, operation.id, PHRASES.alex));
  assert.ok(txid);
  const sent = env.world.log.broadcast.at(-1);
  assert.equal(outputAddress(sent), account.address);
  checkSpend(sent, vaultOf(account), 700_000);
});

/* ------------------------------------------------------------------ a signer who is gone */

test('the owner dies: the other two invite a replacement, move the vault to them, and spend from it', async t => {
  const env = await start(t);
  const { alex, bea, cara, account } = await lockThree(env);
  const dave = await signedIn(env, 'sub-dave');
  await walletFor(env, dave);

  // Alex never approves anything again. Bea asks to bring Dave in; Bea and Cara approve.
  const asked = await invite(env, { asker: bea, ownerId: alex.id, guest: dave, label: 'Dave', approvers: [bea, cara] });
  assert.equal(asked.required, 2, 'the chain threshold is the most a change can ask for, so a dead signer cannot block it');
  await signingKey(env, dave, alex.id, PHRASES.dave);

  // Dave is on the roster now, but his key is not in the vault: his palm cannot move its coins.
  const early = ok(await cara.post('/api/withdrawals', { vaultOwnerId: alex.id, to: DEST, amount: 10_000 }));
  const refused = await dave.post(`/api/operations/${early.operation.id}/approval`, {});
  assert.equal(refused.status, 403);
  assert.match(refused.body.error, /not one of the ones this vault is locked to/);
  ok(await cara.post(`/api/operations/${early.operation.id}/cancel`, {}));

  // Cara asks to move the vault to Bea, Cara and Dave, 2 of 3.
  const view = ok(await cara.get('/api/wallet'));
  const shared = view.signsFor.find(v => v.ownerId === alex.id);
  assert.ok(shared.holdsKey && shared.palm, 'Cara sees the vault she signs for, with its clock');
  const ids = Object.fromEntries(shared.members.map(m => [m.label, m.id]));
  const moved = ok(await cara.post('/api/vault/move/approval', {
    vaultOwnerId: alex.id, signers: [ids.Bea, ids.Cara, ids.Dave], required: 2,
  }));
  assert.match(moved.operation.statement, /^Move the vault to Bea, Cara, Dave, 2 of 3 and the palm, and send 0\.00\d+ tBTC to it at tb1p[a-z0-9]+, network fee 0\.\d{8} tBTC$/);
  assert.equal(moved.operation.details.leaving, 'Owner');
  assert.equal(moved.operation.details.joining, 'Dave');
  assert.equal(moved.operation.required, 2);

  await palmApprove(env, bea, moved.operation.id);
  await palmApprove(env, cara, moved.operation.id);
  assert.equal(ok(await addSignature(bea, moved.operation.id, PHRASES.bea)).txid, null);
  const { txid } = ok(await addSignature(cara, moved.operation.id, PHRASES.cara));
  assert.ok(txid);
  const sent = env.world.log.broadcast.at(-1);
  checkSpend(sent, vaultOf(account), 700_000);

  const after = ok(await cara.get('/api/wallet')).signsFor.find(v => v.ownerId === alex.id);
  assert.notEqual(after.address, account.address, 'the vault has a new address');
  assert.equal(outputAddress(sent), after.address, 'and every coin went to it');
  assert.equal(after.keyCount, 3);
  assert.equal(after.required, 2);
  assert.ok(after.keyHolders.includes(ids.Dave) && !after.keyHolders.includes(alex.id), 'Dave signs now; Alex does not');

  // Dave, who was never the owner, asks for a payment from the new vault. Dave and Bea sign it.
  const pay = ok(await dave.post('/api/withdrawals', { vaultOwnerId: alex.id, to: DEST, amount: 250_000 }));
  await palmApprove(env, dave, pay.operation.id);
  await palmApprove(env, bea, pay.operation.id);
  assert.equal(ok(await addSignature(dave, pay.operation.id, PHRASES.dave)).txid, null);
  ok(await addSignature(bea, pay.operation.id, PHRASES.bea));
  const owner = ok(await alex.get('/api/wallet')).accounts.find(a => a.network === 'bitcoin');
  checkSpend(env.world.log.broadcast.at(-1), vaultOf(owner), 700_000);
});

test('only someone whose key the vault is locked to can refresh or move a vault they do not own', async t => {
  const env = await start(t);
  const { alex } = await lockOne(env);
  const eve = await signedIn(env, 'sub-eve');
  for (const path of ['/api/vault/refresh/approval', '/api/vault/move/approval', '/api/withdrawals']) {
    const refused = await eve.post(path, { vaultOwnerId: alex.id, to: DEST, amount: 1000, signers: [eve.id], required: 1 });
    assert.equal(refused.status, 404, path);
  }
});

/* ------------------------------------------------------------------ the recovery door */

test('an heir with the sheet and the twelve words takes the coins through the recovery door, once it opens', async t => {
  const env = await start(t);
  const { account } = await lockOne(env, { recoveryDays: 90 });
  const descriptor = account.quorum.palm.descriptor;
  const stranger = await env.client().post('/api/recovery-door/plan', { descriptor });
  assert.equal(stranger.status, 401, 'the recovery door is only inside the signed in app');
  const heir = await signedIn(env, 'sub-heir'); // their own Palm sign in; no vault of their own

  const looked = ok(await heir.post('/api/recovery-door/plan', { descriptor }));
  assert.equal(looked.address, account.address);
  assert.equal(looked.clock.daysLeft, 90);
  const early = await heir.post('/api/recovery-door/plan', { descriptor, to: DEST });
  assert.equal(early.status, 409);
  assert.match(early.body.error, /first opens in about 90 days/);

  env.world.chain.tip = 100 + 90 * 144 - 1;
  env.advance(120);
  const planned = ok(await heir.post('/api/recovery-door/plan', { descriptor, to: DEST }));
  assert.equal(planned.plan.outputs[0].address, DEST);

  assert.throws(() => signRecovery(planned.psbt, [PHRASES.bea], planned.keys), /does not hold a key for this vault/);
  const { psbt, signedWith } = signRecovery(planned.psbt, [`  ${PHRASES.alex.toUpperCase()} `], planned.keys);
  assert.equal(signedWith, 1);
  const { txid } = ok(await heir.post('/api/recovery-door/send', { descriptor, psbt }));
  const sent = env.world.log.broadcast.at(-1);
  assert.equal(sent.txid, txid);
  assert.equal(sent.tx.getInput(0).sequence, 90 * 144, 'the input carries the delay Bitcoin checks');
  assert.equal(sent.tx.version, 2);
  checkSpend(sent, vaultOf(account), 700_000, 'recovery');
});

test('the recovery door refuses a description with a typo, and a transaction that is not a recovery', async t => {
  const env = await start(t);
  const { account } = await lockOne(env);
  const heir = await signedIn(env, 'sub-heir');
  const typo = account.quorum.palm.descriptor.replace(/#(.)/, (m, c) => `#${c === 'q' ? 'p' : 'q'}`);
  const refused = await heir.post('/api/recovery-door/plan', { descriptor: typo });
  assert.equal(refused.status, 400);
  assert.match(refused.body.error, /typing mistake/);
  const wrong = await heir.post('/api/recovery-door/send', { descriptor: account.quorum.palm.descriptor, psbt: 'not a psbt' });
  assert.equal(wrong.status, 400);
});

/* ------------------------------------------------------------------ reminders */

test('reminders: one alert per step as the recovery path nears, never twice, and none after a refresh', async t => {
  const env = await start(t);
  const { alex } = await lockOne(env);
  ok(await alex.post('/api/push/subscribe', subscription('alex-phone')));
  const opens = 100 + DEFAULT_RECOVERY_DELAY;
  const run = async () => ok(await env.client().get('/api/cron/reminders'));
  const pushes = () => env.world.log.push.length;

  env.advance(3600);
  assert.equal((await run()).reminded, 0, 'a year away: nothing to say');

  env.world.chain.tip = opens - 50 * 144 - 1;
  env.advance(3600);
  assert.equal((await run()).reminded, 1, '50 days left: the first reminder');
  assert.equal(pushes(), 1);
  assert.equal((await run()).ran, false, 'a second run in the same hour does nothing');

  env.advance(3600);
  assert.equal((await run()).reminded, 0, 'still 50 days: already told');

  env.world.chain.tip = opens - 6 * 144 - 1;
  env.advance(3600);
  assert.equal((await run()).reminded, 1, '6 days left: one more');
  assert.equal(pushes(), 2);

  // A refresh: the coin is new, so the clock is a year away again and there is nothing to say.
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 690_000, height: env.world.chain.tip }];
  env.advance(3600);
  assert.equal((await run()).reminded, 0);
});

test('with CRON_SECRET set, only the scheduler can start a reminder run', async t => {
  const env = await start(t, { cronSecret: 's3cret' });
  const refused = await env.client().get('/api/cron/reminders');
  assert.equal(refused.status, 401);
});

test('one signer asking for a payment never cancels another signer\'s request', async t => {
  const env = await start(t);
  const { alex, bea } = await lockThree(env);
  const mine = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 10_000 }));
  const theirs = ok(await bea.post('/api/withdrawals', { vaultOwnerId: alex.id, to: DEST, amount: 20_000 }));
  const pending = ok(await alex.get('/api/wallet')).pending.map(op => op.id);
  assert.ok(pending.includes(mine.operation.id) && pending.includes(theirs.operation.id), 'both requests stand');
  // Asking again replaces only your own earlier request.
  const again = ok(await bea.post('/api/withdrawals', { vaultOwnerId: alex.id, to: DEST, amount: 30_000 }));
  const after = ok(await alex.get('/api/wallet')).pending.map(op => op.id);
  assert.ok(after.includes(mine.operation.id) && after.includes(again.operation.id) && !after.includes(theirs.operation.id));
});
