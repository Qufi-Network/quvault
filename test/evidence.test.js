/*
 * Authorisation evidence, end to end through the API.
 *
 * Phase A found two defects in what a completed payment can prove about itself:
 *
 *   F1 — no receipt could establish the policy the payment was authorised under. Version 1
 *        does not carry it; version 2 did, but was gated on scanner evidence that cannot
 *        exist in this build, so nothing could emit one.
 *   F2 — the receipt verdict shown to a user compared the record's digest against the
 *        record's own digest. Circular: it proved the signature, not that the record was
 *        about the payment being viewed.
 *
 * These go through the real server, not the record format in isolation.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEST, start, ok, signedIn, palmApprove, walletFor, attestFor, signAndSend, signAndSendV2,
} from './harness.js';

/** Walks a payment to the point where it is approved and the key has been released. */
async function approvedPayment(env, client, amount = 100_000) {
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const { operation } = ok(await client.post('/api/withdrawals', { to: DEST, amount }));
  await palmApprove(env, client, operation.id);
  const unlocked = ok(await client.post(`/api/operations/${operation.id}/unlock`, {}));
  return { operation, unlocked };
}

/* ======================================================= F1: the policy is provable */

test('the server releases everything a receipt needs to establish its own policy', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked } = await approvedPayment(env, alex);

  // Each of these is a field version 1 could not carry, and without which an independent
  // verifier cannot answer "under what rules, and how many approvals were required?".
  assert.equal(unlocked.proposalId, operation.id, 'the proposal it belongs to');
  assert.equal(unlocked.threshold, 1, 'the requirement, as an integer');
  assert.ok(unlocked.policyVersion, 'a digest of the rules in force');
  assert.equal(unlocked.chain, 'bitcoin');
  assert.equal(unlocked.network, 'testnet4');
  assert.ok(unlocked.subject, 'an opaque identity for the vault owner');
  assert.ok(unlocked.expiresAt > 0, 'and when the authorisation stops being usable');

  // The subject is opaque: it is a digest, not the Veyns identity it was derived from.
  assert.ok(!unlocked.subject.includes('sub-alex'), 'the subject is not the raw identity');
});

test('a version 2 receipt is accepted at broadcast and proves its policy afterwards', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked } = await approvedPayment(env, alex);

  const sent = await signAndSendV2(env, alex, operation.id);
  assert.ok(sent.txid, 'the server accepted a version 2 authorisation');

  const receipt = ok(await alex.get(`/api/operations/${operation.id}/receipt`));
  assert.equal(receipt.authorization.record.v, 2);
  assert.equal(receipt.verified.ok, true);

  // The point of the whole change: the verdict says the policy is established.
  assert.equal(receipt.verified.proves.policy, true, 'the policy is provable');
  assert.equal(receipt.verified.proves.threshold, true, 'and so is the requirement');
  assert.equal(receipt.verified.proves.chain, true);
  assert.equal(receipt.verified.proves.proposal, true);

  // And it still claims no measurement, because there is no scanner in this build.
  assert.equal(receipt.verified.proves.sensorMeasurement, false);
  assert.equal(receipt.authorization.record.verification.sensorEvidence, 'none');

  // The record's own numbers match what the server said the rules asked for.
  assert.equal(receipt.authorization.record.threshold, 1);
  assert.equal(receipt.authorization.record.approvalCount, 1);
  assert.equal(receipt.authorization.record.policyVersion, unlocked.policyVersion);
  assert.equal(receipt.authorization.record.proposalId, operation.id);
});

test('a version 2 receipt claiming the wrong proposal or threshold is refused at broadcast', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation } = await approvedPayment(env, alex);

  // The server checks the record against the operation, so a record that names another
  // proposal — or a requirement the rules did not ask for — does not get broadcast.
  for (const [what, tweak] of Object.entries({
    'another proposal': { proposalId: 'some-other-proposal' },
    'another policy': { policyVersion: 'policy-of-my-choosing' },
    'another chain': { chain: 'ethereum' },
    'another network': { network: 'mainnet' },
  })) {
    await assert.rejects(
      () => signAndSendV2(env, alex, operation.id, tweak),
      /./,
      what,
    );
    assert.equal(env.world.log.broadcast.length, 0, `nothing broadcast for ${what}`);
  }
});

/* ============================================= F2: the verdict is not circular */

test('a receipt that describes another transaction is not reported as verified', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, unlocked } = await approvedPayment(env, alex);
  const sent = await signAndSend(env, alex, operation.id);
  assert.ok(sent.txid);

  // Honest first: the stored receipt verifies against the operation it belongs to.
  const honest = ok(await alex.get(`/api/operations/${operation.id}/receipt`));
  assert.equal(honest.verified.ok, true);

  /*
   * Now somebody with database write access replaces the stored receipt with one that is
   * internally consistent and correctly signed by the vault's own attestation key, but
   * describes a different transaction. The old verdict read the expected digest out of the
   * record itself, so this would have been reported as verified.
   */
  const elsewhere = attestFor(env, alex, { ...unlocked, transactionHash: 'a-different-digest' });
  const db = await env.app.db();
  await db.query('UPDATE operations SET human_authorization = $1 WHERE id = $2',
    [JSON.stringify(elsewhere), operation.id]);

  const swapped = ok(await alex.get(`/api/operations/${operation.id}/receipt`));
  assert.equal(swapped.verified.ok, false, 'the verdict is about the payment, not the record');
  assert.match(swapped.verified.reason, /different transaction/);
});

test('a version 1 receipt verifies, and says it cannot establish the policy', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation } = await approvedPayment(env, alex);
  await signAndSend(env, alex, operation.id);

  /*
   * The harness signs version 1, which is what every wallet produced until this change. It
   * still verifies — historical receipts are not invalidated — and the verdict states plainly
   * that it establishes no policy. A verified version 1 record is not a stronger record for
   * having been verified by newer code.
   */
  const receipt = ok(await alex.get(`/api/operations/${operation.id}/receipt`));
  assert.equal(receipt.authorization.record.v, 1);
  assert.equal(receipt.verified.ok, true);
  assert.equal(receipt.verified.proves.transaction, true);
  assert.equal(receipt.verified.proves.policy, false);
  assert.equal(receipt.verified.proves.threshold, false);
  assert.match(receipt.verified.proves.notes, /does NOT establish the policy/);
});
