/*
 * The second audit's findings, each closed: what was found, and the check that now stops it.
 * The contract's own attacks are in contracts/test; the browser's palm check in audit-fixes.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { start, ok, signedIn, walletFor, palmApprove, signAndSend, SEED, DEST } from './harness.js';
import { serverKeys, seal, open, sealIsBound } from '../src/vault.js';
import { verifyChainOfEvidence } from '../src/evidence.js';
import { cosignerFrom, checkLockTarget } from '../client/wallet.js';
import { signKeyProof } from '../src/key-proof.js';
import { bitcoinWordsProblem, evmWordsProblem, evmTokenWordsProblem, btcText, unitsText } from '../src/approval-words.js';

const VAULT = 'tb1pvault';
const PAYEE = 'tb1qpayee';

test('a sealed unlock secret opens only for the person it was sealed to', () => {
  const keys = serverKeys(SEED);
  const sealed = seal(Buffer.from('the unlock secret'), keys, 'palm unlock secret v2:alex');
  assert.equal(sealIsBound(sealed), true);
  assert.equal(open(sealed, keys, 'palm unlock secret v2:alex').toString(), 'the unlock secret');
  // Copied into someone else's record, it opens for nobody.
  assert.throws(() => open(sealed, keys, 'palm unlock secret v2:mallory'));
  assert.throws(() => open(sealed, keys), /does not belong here/);
  // And an old, unbound seal is never handed to a caller that asks for a bound one.
  const legacy = seal(Buffer.from('old'), keys);
  assert.equal(sealIsBound(legacy), false);
  assert.throws(() => open(legacy, keys, 'palm unlock secret v2:alex'), /does not belong here/);
});

test('the words a palm approves must name every payee, every amount and the fee of the transaction', () => {
  const plan = { inputs: [{ value: 100_000 }], outputs: [{ address: PAYEE, sats: 60_000 }, { address: VAULT, sats: 39_700 }], feeSats: 300 };
  const right = `Send ${btcText(60_000)} tBTC to ${PAYEE}, network fee ${btcText(300)} tBTC`;
  assert.equal(bitcoinWordsProblem({ statement: right, plan, vaultAddress: VAULT, details: { fee_sats: 300 } }), null);
  // A harmless sentence left in place over a swapped transaction is caught, whichever part changed.
  assert.match(bitcoinWordsProblem({ statement: right.replace(PAYEE, 'tb1qother'), plan, vaultAddress: VAULT }), /do not name tb1qpayee/);
  assert.match(bitcoinWordsProblem({ statement: right.replace(btcText(60_000), btcText(6_000)), plan, vaultAddress: VAULT }), /do not say that/);
  assert.match(bitcoinWordsProblem({ statement: `Send ${btcText(60_000)} tBTC to ${PAYEE}`, plan, vaultAddress: VAULT }), /network fee/);
  assert.match(bitcoinWordsProblem({ statement: right, plan, vaultAddress: VAULT, details: { fee_sats: 1 } }), /fee is not this/);

  const to = '0x1111111111111111111111111111111111111111';
  const amount = '20000000000000000';
  const ethRight = `Send ${unitsText(amount)} ETH to ${to}, plus ${unitsText('25000000000000')} ETH in fees`;
  assert.equal(evmWordsProblem({ statement: ethRight, to, amount, fees: '25000000000000' }), null);
  assert.match(evmWordsProblem({ statement: ethRight, to: `0x${'2'.repeat(40)}`, amount, fees: '25000000000000' }), /payee/);
  assert.match(evmWordsProblem({ statement: ethRight, to, amount: '30000000000000000', fees: '25000000000000' }), /amount/);
  assert.match(evmWordsProblem({ statement: ethRight, to, amount, fees: '99000000000000' }), /fees/);

  const token = `0x${'3'.repeat(40)}`;
  const tokenRight = `Send 5000 base units of token ${token} to ${to}, plus Palm fee 5 base units and network fee ${unitsText('1000')} ETH`;
  assert.equal(evmTokenWordsProblem({ statement: tokenRight, to, token, amount: '5000', fee: '5', gasRefund: '1000' }), null);
  assert.match(evmTokenWordsProblem({ statement: tokenRight, to, token: `0x${'4'.repeat(40)}`, amount: '5000', fee: '5', gasRefund: '1000' }), /token/);
  assert.match(evmTokenWordsProblem({ statement: tokenRight, to, token, amount: '9000', fee: '5', gasRefund: '1000' }), /amount/);
});

test('an evidence export shows other customers only as the links that hold the chain together', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bob = await signedIn(env, 'sub-bob');
  await walletFor(env, alex);
  await walletFor(env, bob);
  // Each pays someone, so the shared log holds entries of both.
  for (const person of [alex, bob]) {
    env.world.chain.utxos = [{ txid: (person === alex ? 'a' : 'b').repeat(64), vout: 0, value: 1_000_000 }];
    const { operation } = ok(await person.post('/api/withdrawals', { to: DEST, amount: 50_000 }));
    await palmApprove(env, person, operation.id);
    await signAndSend(env, person, operation.id);
  }

  const { bundle } = ok(await alex.get('/api/evidence'));
  const chain = verifyChainOfEvidence(bundle.entries);
  assert.equal(chain.ok, true, JSON.stringify(chain.problems));
  assert.ok(chain.redacted > 0, 'Bob\'s entries are in the chain');
  for (const entry of bundle.entries.filter(item => item.redacted)) {
    assert.deepEqual(Object.keys(entry).sort(), ['at', 'hash', 'id', 'kind', 'prev', 'redacted', 'seq'], 'and say nothing of what he did');
  }
  assert.ok(bundle.entries.some(item => !item.redacted), 'Alex\'s own entries are there in full');
});

test('only the owner\'s own palm can approve what opens the owner\'s key', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bea = await signedIn(env, 'sub-bea');
  await walletFor(env, alex);
  await walletFor(env, bea);
  // Bea signs for Alex's vault, by invitation.
  const made = ok(await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Bea' }));
  await palmApprove(env, alex, made.operation.id);
  const [invite] = ok(await alex.get('/api/invites')).invites;
  const join = ok(await bea.post('/api/invites/join', { code: invite.code }));
  await palmApprove(env, bea, join.operation.id);

  // Showing the recovery words is the owner's alone: a signer cannot add their palm to it.
  const { operation } = ok(await alex.post('/api/recovery', { network: 'bitcoin' }));
  const tried = await bea.post(`/api/operations/${operation.id}/approval`, {});
  assert.equal(tried.status, 403);
  assert.match(tried.body.error, /owner/);
});

const PHRASES = {
  alex: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  bea: 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
};
const keyHex = key => Buffer.from(key.publicKey).toString('hex');

/** Creates and registers this person's signing key for a vault, from their twelve words. */
async function signingKey(env, client, vaultOwnerId, phrase) {
  const started = ok(await client.post('/api/signing-key/approval', { vaultOwnerId }));
  await palmApprove(env, client, started.operation.id);
  ok(await client.post(`/api/operations/${started.operation.id}/unlock`, {}));
  const key = cosignerFrom(phrase, started.index);
  ok(await client.post('/api/signing-key/register', {
    operationId: started.operation.id, publicKey: keyHex(key),
    proof: signKeyProof(key.privateKey, { vaultOwnerId, memberId: client.id, publicKey: keyHex(key) }),
  }));
  return key;
}

test('a database writer who swaps in their own key before a lock is refused by the owner’s browser', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await signingKey(env, alex, alex.id, PHRASES.alex);
  // One UPDATE puts an attacker's key where Alex's registered key was.
  const db = await env.app.db();
  const evil = cosignerFrom(PHRASES.bea, 0);
  await db.query('UPDATE members SET public_key = $1 WHERE wallet_user_id = $2 AND member_id = $2', [keyHex(evil), alex.id]);

  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 1, palm: true, recoveryDays: 90 }));
  await palmApprove(env, alex, asked.operation.id);
  const unlocked = ok(await alex.post(`/api/operations/${asked.operation.id}/unlock`, {}));
  const payee = unlocked.plan.outputs.find(output => output.address === unlocked.quorum.address)?.address;
  // The browser rebuilds the vault from its own words before it signs the move, and stops.
  assert.throws(() => checkLockTarget(PHRASES.alex, unlocked, payee), /Your own signing key is not one of this vault/);
});

test('a signer cannot erase their vault while their key is built into someone else’s, even an empty one', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  const bea = await signedIn(env, 'sub-bea');
  await walletFor(env, alex);
  await walletFor(env, bea);
  const made = ok(await alex.post('/api/invites/approval', { network: 'bitcoin', label: 'Bea' }));
  await palmApprove(env, alex, made.operation.id);
  const [invite] = ok(await alex.get('/api/invites')).invites;
  const join = ok(await bea.post('/api/invites/join', { code: invite.code }));
  await palmApprove(env, bea, join.operation.id);
  await signingKey(env, alex, alex.id, PHRASES.alex);
  await signingKey(env, bea, alex.id, PHRASES.bea);
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const asked = ok(await alex.post('/api/accounts/lock', { required: 2, palm: true }));
  for (const person of [alex, bea].slice(0, asked.operation.required)) await palmApprove(env, person, asked.operation.id);
  await signAndSend(env, alex, asked.operation.id);

  // Alex's vault reads empty now, but its address stays, and the next coin would need Bea's key.
  env.world.chain.utxos = [];
  const reset = await bea.post('/api/wallet/reset/approval', {});
  assert.equal(reset.status, 409);
  assert.match(reset.body.error, /signs for someone else's vault/);
});
