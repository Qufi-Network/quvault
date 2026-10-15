/*
 * The F4 closure: the three things the evidence log could not do when it was first built.
 *
 *   1. It failed open everywhere, so a payment could be broadcast with no durable record of
 *      the authorisation or the policy that permitted it.
 *   2. An uncertain broadcast had no resolution — the log just said "signed" forever.
 *   3. A privileged operator could rewrite the whole history and recompute the chain, and
 *      nothing would notice.
 *
 * Each of those now has a mechanism, and each mechanism is tested here by breaking the thing
 * it depends on.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  EVIDENCE, GENESIS, summarisePayment, checkpointsAgree, buildBundle, verifyBundle,
} from '../src/evidence.js';
import {
  signCheckpoint, verifyCheckpoint, deriveAttestationKeys,
} from '../src/authorization.js';
import { checkpointDisagreement } from '../client/wallet.js';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSendV2 } from './harness.js';

async function approved(env, client, amount = 100_000) {
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const { operation } = ok(await client.post('/api/withdrawals', { to: DEST, amount }));
  await palmApprove(env, client, operation.id);
  return operation;
}

const entriesOf = rows => rows.map(r => ({
  id: r.id, at: Number(r.at), kind: r.kind, actor: r.actor ?? null, scope: r.scope ?? null,
  subjectKind: r.subject_kind ?? null, subjectId: r.subject_id ?? null,
  payload: JSON.parse(r.payload), prev: r.prev_hash, hash: r.hash,
}));

/* =========================================== 1. nothing irreversible without a record */

test('a payment is refused rather than broadcast when evidence cannot be recorded', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);

  // The log becomes unwritable at the worst possible moment: after approval, before signing.
  const db = await env.app.db();
  await db.query('DROP TABLE evidence');

  /*
   * The old behaviour broadcast anyway and logged the failure. A high-value transaction must
   * not reach the network without durable evidence of the authorisation that permitted it, so
   * this now refuses — and nothing reaches the network, which is the assertion that matters.
   */
  await assert.rejects(() => signAndSendV2(env, alex, operation.id), /./);
  assert.equal(env.world.log.broadcast.length, 0, 'nothing was broadcast');
});

test('the refusal is a 503 saying nothing changed, not a rejection of the request', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  const db = await env.app.db();
  await db.query('DROP TABLE evidence');

  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  const { attestInstitutionalFor } = await import('./harness.js');
  const { signPlan } = await import('../src/bitcoin.js');
  const signed = signPlan({ privateKey: alex.key, publicKey: alex.publicKey, plan: unlocked.plan });
  const refused = await alex.post(`/api/operations/${operation.id}/broadcast`, {
    hex: signed.hex, authorization: attestInstitutionalFor(env, alex, unlocked),
  });

  // 503, not 409: the request is fine, the system cannot currently record what it would do.
  assert.equal(refused.status, 503);
  assert.match(refused.body.error, /evidence log is unavailable/);
  assert.match(refused.body.error, /Nothing has changed/);
  assert.equal(env.world.log.broadcast.length, 0);
});

test('the attempt is recorded before the network is touched, and names the transaction', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  const sent = await signAndSendV2(env, alex, operation.id);

  const { bundle } = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  const kinds = bundle.entries.map(e => e.kind);

  /*
   * The ordering is the guarantee. Everything reversible is recorded before the one
   * irreversible step, so a crash can leave an unknown outcome but never an unrecorded
   * authorisation.
   */
  const order = [
    EVIDENCE.AUTHORIZATION_GRANTED, EVIDENCE.SIGNATURE_PRODUCED,
    EVIDENCE.BROADCAST_ATTEMPTED, EVIDENCE.BROADCAST_ACCEPTED,
  ].map(k => kinds.indexOf(k));
  assert.ok(order.every(i => i >= 0), 'all four facts are present');
  assert.deepEqual([...order].sort((a, b) => a - b), order, 'and in that order');

  // The attempt carries the txid, which is what makes an unknown outcome resolvable.
  const attempt = bundle.entries.find(e => e.kind === EVIDENCE.BROADCAST_ATTEMPTED);
  assert.equal(attempt.payload.txid, sent.txid, 'known before the broadcast, not after');
});

/* ================================= 2. an uncertain outcome is reconciled against Bitcoin */

test('an outcome lost to a crash is reconciled from the chain', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  const sent = await signAndSendV2(env, alex, operation.id);
  const db = await env.app.db();

  /*
   * Simulating the crash window: the transaction reached the network and the acceptance was
   * never written. The trigger forbids DELETE, so this is the privileged case again — which is
   * the only way this state can arise, and the state reconciliation exists for.
   */
  await db.query('DROP TRIGGER evidence_append_only ON evidence');
  await db.query('DELETE FROM evidence WHERE kind = $1', [EVIDENCE.BROADCAST_ACCEPTED]);

  const before = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  assert.equal(before.summary.outcomeUnknown, true, 'attempted, with no outcome');
  assert.equal(before.summary.broadcastAccepted, false);

  // The chain is the authority, and it has the transaction.
  const result = ok(await alex.post(`/api/operations/${operation.id}/reconcile`, {}));
  assert.equal(result.reconciled, true);
  assert.equal(result.outcome, 'accepted');
  assert.equal(result.txid, sent.txid);

  const after = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  assert.equal(after.summary.broadcastAccepted, true, 'the outcome is now recorded');
  assert.equal(after.summary.outcomeUnknown, false);
  const reconciled = after.bundle.entries.find(
    e => e.kind === EVIDENCE.BROADCAST_ACCEPTED && e.payload.outcome === 'reconciled');
  assert.ok(reconciled, 'and marked as reconciled rather than observed directly');
});

test('a transaction the chain has never seen reconciles to refused', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);

  /*
   * An attempt naming a txid the chain does not have: the broadcast never landed. Appended
   * after the real head, because `prev_hash` is unique — chaining off the genesis a second
   * time is exactly the fork the constraint exists to prevent.
   */
  const db = await env.app.db();
  const unlocked = ok(await alex.post(`/api/operations/${operation.id}/unlock`, {}));
  const head = (await db.query('SELECT hash FROM evidence ORDER BY seq DESC LIMIT 1')).rows[0]?.hash ?? GENESIS;
  await db.query(
    `INSERT INTO evidence (id, at, kind, subject_kind, subject_id, payload, prev_hash, hash, idempotency_key)
     VALUES ($1, $2, $3, 'operation', $4, $5, $6, $7, $8)`,
    ['lost-1', env.now(), EVIDENCE.BROADCAST_ATTEMPTED, operation.id,
      JSON.stringify({ txid: 'f'.repeat(64) }), head, 'a-hash-for-the-test', 'k-lost-1']);

  const result = ok(await alex.post(`/api/operations/${operation.id}/reconcile`, {}));
  assert.equal(result.reconciled, true);
  assert.equal(result.outcome, 'refused', 'the chain has never seen it');
  assert.ok(unlocked.transactionHash);
});

test('reconciliation writes nothing when the chain cannot be reached', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  const sent = await signAndSendV2(env, alex, operation.id);
  const db = await env.app.db();
  await db.query('DROP TRIGGER evidence_append_only ON evidence');
  await db.query('DELETE FROM evidence WHERE kind = $1', [EVIDENCE.BROADCAST_ACCEPTED]);

  // The chain service stops answering. "We could not ask" is not "it did not happen", and
  // writing either outcome here would be a guess.
  env.world.chain.unreachable = true;
  const result = ok(await alex.post(`/api/operations/${operation.id}/reconcile`, {}));
  assert.equal(result.reconciled, false, 'nothing was concluded');
  assert.match(result.reason, /could not be reached/);

  const after = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  assert.equal(after.summary.outcomeUnknown, true, 'the outcome stays open, which is the truth');
  assert.ok(sent.txid);
});

test('reconciling a settled payment changes nothing, however often it runs', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  await signAndSendV2(env, alex, operation.id);
  const db = await env.app.db();
  const before = (await db.query('SELECT count(*)::int AS n FROM evidence')).rows[0].n;

  for (let i = 0; i < 3; i++) {
    const result = ok(await alex.post(`/api/operations/${operation.id}/reconcile`, {}));
    assert.equal(result.reconciled, false);
    assert.match(result.reason, /already recorded/);
  }
  assert.equal((await db.query('SELECT count(*)::int AS n FROM evidence')).rows[0].n, before);
});

/* ============================ 3. a full rewrite is detectable, by a key the server lacks */

test('a checkpoint is signed by the vault key and refuses a head the log does not have', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  await signAndSendV2(env, alex, operation.id);

  const target = ok(await alex.get('/api/evidence/checkpoint'));
  assert.ok(target.head && target.count > 0, 'the server states a head to commit to');
  assert.equal(target.lastCheckpoint, null, 'and nothing has been committed to yet');

  const signed = signCheckpoint(target, alex.attestation);
  const stored = ok(await alex.post('/api/evidence/checkpoint', { checkpoint: signed }));
  assert.equal(stored.appended, true);
  assert.equal(stored.checkpoint.head, target.head);

  // A checkpoint for a head this log does not hold is refused: storing it would create a
  // commitment to a log nobody has.
  const elsewhere = signCheckpoint({ ...target, head: 'a-head-of-my-choosing' }, alex.attestation);
  const refused = await alex.post('/api/evidence/checkpoint', { checkpoint: elsewhere });
  assert.equal(refused.status, 409);

  // And one signed by a key this vault has not registered.
  const stranger = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const forged = signCheckpoint(ok(await alex.get('/api/evidence/checkpoint')), stranger);
  const rejected = await alex.post('/api/evidence/checkpoint', { checkpoint: forged });
  assert.equal(rejected.status, 409);
  assert.match(rejected.body.error, /has not registered|does not verify/);
});

test('a rewritten log fails against its own checkpoint, however well the chain is recomputed', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  await signAndSendV2(env, alex, operation.id);

  // Commit to the log as it stands.
  const target = ok(await alex.get('/api/evidence/checkpoint'));
  ok(await alex.post('/api/evidence/checkpoint', { checkpoint: signCheckpoint(target, alex.attestation) }));

  const honest = ok(await alex.get('/api/evidence'));
  assert.equal(honest.verified.ok, true);
  assert.equal(honest.checkpoints.ok, true, 'the log agrees with its commitment');
  assert.equal(honest.checkpoints.checked, 1);

  /*
   * The privileged-operator attack, done properly: drop the trigger, rewrite an entry, and
   * recompute every hash after it so the chain is internally perfect. This is the attack a
   * hash chain alone cannot survive — and the checkpoint is what survives it, because the
   * operator cannot produce a new one without a key the server has never held.
   */
  const db = await env.app.db();
  await db.query('DROP TRIGGER evidence_append_only ON evidence');
  const rows = (await db.query('SELECT * FROM evidence ORDER BY seq')).rows;
  const { sealEntry } = await import('../src/evidence.js');

  let prev = GENESIS;
  for (const row of rows) {
    const payload = row.kind === EVIDENCE.AUTHORIZATION_GRANTED
      ? { ...JSON.parse(row.payload), threshold: 99 }   // the lie being told
      : JSON.parse(row.payload);
    const resealed = sealEntry({
      id: row.id, at: Number(row.at), kind: row.kind, actor: row.actor ?? null,
      scope: row.scope ?? null, subjectKind: row.subject_kind ?? null,
      subjectId: row.subject_id ?? null, payload, prev,
    });
    await db.query('UPDATE evidence SET payload = $1, prev_hash = $2, hash = $3 WHERE id = $4',
      [JSON.stringify(payload), resealed.prev, resealed.hash, row.id]);
    prev = resealed.hash;
  }

  const rewritten = ok(await alex.get('/api/evidence'));
  // The chain itself is now flawless. That is the point.
  assert.equal(rewritten.verified.ok, true, 'the recomputed chain verifies — a chain alone is not enough');
  // And the commitment catches it anyway.
  assert.equal(rewritten.checkpoints.ok, false, 'the checkpoint does not agree');
  assert.ok(rewritten.checkpoints.results.some(r => /rewritten/.test(r.problems.join(' '))));
});

test('the exported bundle carries what is needed to check a checkpoint offline', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  await signAndSendV2(env, alex, operation.id);
  const target = ok(await alex.get('/api/evidence/checkpoint'));
  ok(await alex.post('/api/evidence/checkpoint', { checkpoint: signCheckpoint(target, alex.attestation) }));

  const exported = ok(await alex.get('/api/evidence'));
  assert.ok(exported.vaultPublicKey, 'the vault PUBLIC key travels with the bundle');
  assert.equal(exported.bundle.checkpoints.length, 1);

  /*
   * Verified with nothing but the bundle: no database, no server, no call back to anything.
   * `checkpointsAgree` re-derives the head the checkpoint should name from the entries it was
   * given, and the signature is checked against the public key in the bundle.
   */
  const standalone = checkpointsAgree(exported.bundle,
    cp => verifyCheckpoint(cp, exported.vaultPublicKey, { vaultId: cp.record.vaultId }));
  assert.equal(standalone.ok, true);
  assert.equal(verifyBundle(exported.bundle).ok, true);

  // A bundle whose entries were truncated no longer satisfies a checkpoint covering more.
  const short = buildBundle({
    entries: exported.bundle.entries.slice(0, 2), exportedAt: 1,
    checkpoints: exported.bundle.checkpoints,
  });
  assert.equal(checkpointsAgree(short).ok, false, 'a missing tail is caught');
});

test('a checkpoint is not an authorisation and says nothing about a palm', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const target = ok(await alex.get('/api/evidence/checkpoint'));
  const signed = signCheckpoint(target, alex.attestation);

  /*
   * Separate contexts, so neither can be replayed as the other. A checkpoint is a statement
   * about a log; keeping it apart from the authorisation receipt is what stops anyone reading
   * it as evidence that a human — or a sensor — did anything.
   */
  assert.equal(signed.context, 'QUVAULT-EVIDENCE-CHECKPOINT-V1');
  const asAuthorization = await import('../src/authorization.js');
  assert.equal(
    asAuthorization.verifyAuthorization(signed, alex.attestation.publicKeyBase64).ok, false,
    'a checkpoint does not verify as an authorisation',
  );
  /*
   * Checked by field name, not by searching the serialised blob — an ML-DSA-65 signature is
   * some three thousand characters of base64 and will contain the letters "pad" or "palm"
   * sooner or later by chance. A substring search over it tests nothing.
   */
  const fields = Object.keys(signed.record);
  assert.ok(!fields.some(f => /biometric|palm|pad|sensor|verification/i.test(f)),
    `a checkpoint has no measurement field: ${fields.join(', ')}`);
  assert.deepEqual(fields.sort(), ['at', 'context', 'count', 'head', 'nonce', 'v', 'vaultId']);
});

/* ============ 3a. the browser's own copy, for when the checkpoints are deleted too */

test('a browser that kept its own head notices a rewrite even with the checkpoints deleted', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const operation = await approved(env, alex);
  await signAndSendV2(env, alex, operation.id);

  // Commit, and keep this browser's own note of what it committed to.
  const target = ok(await alex.get('/api/evidence/checkpoint'));
  ok(await alex.post('/api/evidence/checkpoint', { checkpoint: signCheckpoint(target, alex.attestation) }));
  const mine = { checkpoints: [{ head: target.head, count: target.count, at: target.at }] };

  /*
   * The complete attack: rewrite every entry, recompute the chain so it is internally perfect,
   * AND destroy the server-side checkpoints so there is nothing left to contradict it. This is
   * the case a checkpoint stored only in the operator's own database does not survive.
   */
  const db = await env.app.db();
  await db.query('DROP TRIGGER evidence_append_only ON evidence');
  await db.query('DROP TRIGGER evidence_checkpoints_append_only ON evidence_checkpoints');
  // The anchor records reference the checkpoints and are append-only in their own right, so
  // even this attack has to disable a third trigger and clear them first. Needing to is the
  // protection working.
  await db.query('DROP TRIGGER evidence_anchors_append_only ON evidence_anchors');
  await db.query('DELETE FROM evidence_anchors');
  await db.query('DELETE FROM evidence_checkpoints');
  const rows = (await db.query('SELECT * FROM evidence ORDER BY seq')).rows;
  const { sealEntry } = await import('../src/evidence.js');
  let prev = GENESIS;
  for (const row of rows) {
    const payload = row.kind === EVIDENCE.AUTHORIZATION_GRANTED
      ? { ...JSON.parse(row.payload), threshold: 99 }
      : JSON.parse(row.payload);
    const resealed = sealEntry({
      id: row.id, at: Number(row.at), kind: row.kind, actor: row.actor ?? null,
      scope: row.scope ?? null, subjectKind: row.subject_kind ?? null,
      subjectId: row.subject_id ?? null, payload, prev,
    });
    await db.query('UPDATE evidence SET payload = $1, prev_hash = $2, hash = $3 WHERE id = $4',
      [JSON.stringify(payload), resealed.prev, resealed.hash, row.id]);
    prev = resealed.hash;
  }

  // The server now presents a perfect chain with no checkpoints at all.
  const exported = ok(await alex.get('/api/evidence'));
  assert.equal(exported.verified.ok, true, 'the chain verifies');
  assert.equal(exported.checkpoints.anyPresent, false, 'and there is nothing left to contradict it');

  /*
   * Except in this browser, which kept its own note. The head it committed to at that count is
   * not the head the server now reports, and that is the disagreement — held in storage the
   * operator does not control, which is what "externally retained" has to mean.
   */
  const after = ok(await alex.get('/api/evidence/checkpoint'));
  const found = checkpointDisagreement(mine, [{ count: mine.checkpoints[0].count, head: after.head }]);
  assert.ok(found, 'the browser notices');
  assert.equal(found.expected, target.head);
  assert.notEqual(found.found, target.head);
  assert.match(found.reason, /different history at a point this browser already committed to/);

  // And a log that merely grew is not a disagreement.
  assert.equal(checkpointDisagreement(mine, [{ count: 999, head: 'something-later' }]), null);
});
