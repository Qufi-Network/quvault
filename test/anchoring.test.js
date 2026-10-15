/*
 * Bounded checkpointing, and the three tiers of anchor kept honestly apart.
 *
 * The gap this closes: a checkpoint that lives only in the operator's own database can be
 * deleted by the operator, and a browser's copy of it dies with cleared site data. Neither is
 * a durable external record. These tests cover the sink that is, plus every way the mechanism
 * can be degraded — sink outage, delayed checkpointing, a missed window, lost browser storage,
 * a server-side rewrite, and recovery from a checkpoint held outside.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  ANCHOR, ANCHOR_POLICY, CHECKPOINT_SELF_COST, anchorWindow, createNullSink, createHttpSink,
  assertSink, compareAgainstExternal,
} from '../src/anchor.js';
import { EVIDENCE, GENESIS, sealEntry } from '../src/evidence.js';
import { deriveAttestationKeys, signCheckpoint, verifyCheckpoint } from '../src/authorization.js';
import { canonicalJson } from '../src/canonical.js';
import { checkpointDisagreement, signEvidenceCheckpoint } from '../client/wallet.js';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSendV2 } from './harness.js';

/** A sink that records what it was given and can be made to fail on demand. */
function recordingSink({ fail = null, operatorControlled = false } = {}) {
  const held = [];
  return assertSink({
    name: 'recording',
    describe: () => ({ configured: true, external: !operatorControlled, reason: 'test sink' }),
    async store(checkpoint) {
      if (fail) return { result: fail, ref: null, detail: 'made to fail' };
      held.push(checkpoint);
      return { result: ANCHOR.STORED, ref: `ref-${held.length}` };
    },
    async fetchLatest() {
      return held.length
        ? { result: ANCHOR.STORED, checkpoint: held.at(-1) }
        : { result: ANCHOR.REFUSED, checkpoint: null };
    },
    held,
    setFailure: next => { fail = next; },
  });
}

async function paid(env, client, amount = 100_000) {
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 2_000_000 }];
  const { operation } = ok(await client.post('/api/withdrawals', { to: DEST, amount }));
  await palmApprove(env, client, operation.id);
  await signAndSendV2(env, client, operation.id);
  return operation;
}

/** Signs a checkpoint the way the browser does, and registers it. */
async function checkpoint(env, client) {
  const target = ok(await client.get('/api/evidence/checkpoint'));
  const signed = signCheckpoint(target, client.attestation);
  const stored = ok(await client.post('/api/evidence/checkpoint', { checkpoint: signed }));
  return { target, signed, stored };
}

/* ======================================================== the window, in isolation */

test('the window measures the unanchored tail, not the time since a job ran', () => {
  const now = 1_800_000_000;
  const policy = ANCHOR_POLICY;

  // Nothing written since the last checkpoint: nothing to rewrite, nothing to do.
  assert.equal(anchorWindow({ lastCheckpointAt: now - 99_999, lastCheckpointCount: 10, entryCount: 10, now, policy }).state, 'anchored');

  // Entries present and never checkpointed is overdue by definition — none of it is anchored.
  const never = anchorWindow({ lastCheckpointAt: null, lastCheckpointCount: 0, entryCount: 3, now, policy });
  assert.equal(never.state, 'overdue');
  assert.equal(never.unanchoredEntries, 3);
  assert.match(never.reason, /never been checkpointed/);

  // A small recent tail is fine.
  assert.equal(anchorWindow({ lastCheckpointAt: now - 60, lastCheckpointCount: 10, entryCount: 12, now, policy }).state, 'anchored');
  // Enough entries, or enough time, makes one due.
  assert.equal(anchorWindow({ lastCheckpointAt: now - 60, lastCheckpointCount: 0, entryCount: policy.dueAfterEntries, now, policy }).state, 'due');
  assert.equal(anchorWindow({ lastCheckpointAt: now - policy.dueAfterSeconds, lastCheckpointCount: 10, entryCount: 11, now, policy }).state, 'due');
  // And more of either makes it overdue.
  assert.equal(anchorWindow({ lastCheckpointAt: now - 60, lastCheckpointCount: 0, entryCount: policy.overdueAfterEntries, now, policy }).state, 'overdue');
  assert.equal(anchorWindow({ lastCheckpointAt: now - policy.overdueAfterSeconds, lastCheckpointCount: 10, entryCount: 11, now, policy }).state, 'overdue');

  // The count is what an auditor cares about: how much could be altered uncontradicted.
  assert.equal(anchorWindow({ lastCheckpointAt: now, lastCheckpointCount: 40, entryCount: 100, now, policy }).unanchoredEntries, 60);
});

test('a deployment with no sink is told it has no durable external anchor', () => {
  const none = createNullSink();
  assert.equal(none.describe().configured, false);
  assert.equal(none.describe().external, false);
  assert.match(none.describe().reason, /not a durable record/);
  assert.equal(none.name, 'none');
});

test('a sink the operator controls is not reported as external', () => {
  const theirs = createHttpSink({ url: 'https://auditor.example/anchors', fetchImpl: async () => ({ ok: true, json: async () => ({}) }) });
  assert.equal(theirs.describe().external, true);

  const ours = createHttpSink({ url: 'https://our-own-bucket.example/anchors', operatorControlled: true, fetchImpl: async () => ({ ok: true, json: async () => ({}) }) });
  assert.equal(ours.describe().external, false, 'a backup is not an anchor');
  assert.match(ours.describe().reason, /backup rather than|cannot write to/);

  // And nothing calling itself a sink may hold signing material.
  assert.throws(() => assertSink({ name: 'x', describe: () => ({}), store: () => {}, fetchLatest: () => {}, sign: () => {} }), /must not hold signing material/);
  assert.throws(() => assertSink({ name: 'x', describe: () => ({}) }), /missing/);
});

/* ============================================= a checkpoint reaches the sink, or waits */

test('a checkpoint is forwarded to the sink as soon as it is signed', async t => {
  const sink = recordingSink();
  const env = await start(t, { anchorSink: sink });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paid(env, alex);

  const { stored } = await checkpoint(env, alex);
  assert.equal(stored.external.result, ANCHOR.STORED);
  assert.equal(sink.held.length, 1, 'the sink has it');
  assert.equal(sink.held[0].record.head, stored.checkpoint.head);

  const status = ok(await alex.get('/api/evidence/anchor'));
  assert.equal(status.externalAnchor.configured, true);
  assert.equal(status.externalAnchor.external, true);
  assert.equal(status.externalAnchor.awaitingForwarding, 0);
  assert.equal(status.window.state, 'anchored');
  // Said in the response, because it is the thing most easily misread.
  assert.equal(status.browserCopyIsNotAnAnchor, true);
});

test('a sink outage keeps the checkpoint and leaves it waiting, then recovers', async t => {
  const sink = recordingSink({ fail: ANCHOR.UNREACHABLE });
  const env = await start(t, { anchorSink: sink });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paid(env, alex);

  // The sink is down when the checkpoint is signed.
  const { stored } = await checkpoint(env, alex);
  assert.equal(stored.appended, true, 'the checkpoint is still stored locally');
  assert.equal(stored.external.result, ANCHOR.UNREACHABLE);
  assert.equal(sink.held.length, 0);

  let status = ok(await alex.get('/api/evidence/anchor'));
  assert.equal(status.externalAnchor.awaitingForwarding, 1, 'and it is waiting, not lost');
  assert.equal(status.externalAnchor.lastStoredAt, null);

  // The outage is itself recorded: an audit trail must not forget it was unprotected.
  const { bundle } = ok(await alex.get('/api/evidence'));
  const failed = bundle.entries.filter(
    e => e.kind === EVIDENCE.CHECKPOINT_ANCHORED && e.payload.outcome === ANCHOR.UNREACHABLE);
  assert.ok(failed.length >= 1, 'the failed attempt is in the log');

  // The sink comes back, and the retry needs no key — so it can run unattended.
  sink.setFailure(null);
  const retried = ok(await alex.post('/api/evidence/anchor/retry', {}));
  assert.equal(retried.attempted, 1);
  assert.equal(retried.results[0].result, ANCHOR.STORED);
  assert.equal(sink.held.length, 1, 'the sink has it now');

  status = ok(await alex.get('/api/evidence/anchor'));
  assert.equal(status.externalAnchor.awaitingForwarding, 0);
  assert.ok(status.externalAnchor.lastStoredAt > 0);
});

test('a refusing sink is recorded differently from an unreachable one', async t => {
  const sink = recordingSink({ fail: ANCHOR.REFUSED });
  const env = await start(t, { anchorSink: sink });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paid(env, alex);
  const { stored } = await checkpoint(env, alex);

  assert.equal(stored.external.result, ANCHOR.REFUSED, 'the sink answered, and said no');
  const { bundle } = ok(await alex.get('/api/evidence'));
  assert.ok(bundle.entries.some(
    e => e.kind === EVIDENCE.CHECKPOINT_ANCHORED && e.payload.outcome === ANCHOR.REFUSED));
  // Distinct from UNREACHABLE, because one is a configuration problem and the other an outage.
  assert.ok(!bundle.entries.some(e => e.payload?.outcome === ANCHOR.UNREACHABLE));
});

/* ================================================= delayed, and missed, checkpointing */

test('an unanchored tail is reported, and closes at the next payment', async t => {
  const sink = recordingSink();
  const env = await start(t, {
    anchorSink: sink,
    // A tight policy, so the test exercises the thresholds rather than the defaults.
    anchorPolicy: { dueAfterEntries: 4, overdueAfterEntries: 6, dueAfterSeconds: 60, overdueAfterSeconds: 120 },
  });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);

  await paid(env, alex, 10_000);
  let status = ok(await alex.get('/api/evidence/anchor'));
  assert.equal(status.window.state, 'overdue', 'never checkpointed, so none of it is anchored');
  assert.ok(status.window.unanchoredEntries >= 5);

  /*
   * The checkpoint closes the window — down to the floor, not to zero. Signing one writes two
   * entries of its own (that it was signed, and what the sink said), and those necessarily come
   * after the head being committed to. See CHECKPOINT_SELF_COST.
   */
  await checkpoint(env, alex);
  status = ok(await alex.get('/api/evidence/anchor'));
  assert.equal(status.window.state, 'anchored');
  assert.ok(status.window.unanchoredEntries <= CHECKPOINT_SELF_COST,
    `the tail is down to the floor, not zero: ${status.window.unanchoredEntries}`);

  // More activity reopens it, in proportion to the activity.
  await paid(env, alex, 11_000);
  status = ok(await alex.get('/api/evidence/anchor'));
  assert.notEqual(status.window.state, 'anchored');
  assert.ok(status.window.unanchoredEntries > 0);
});

test('a missed schedule is a reported condition, not a silent one', async t => {
  const env = await start(t, {
    anchorSink: recordingSink(),
    anchorPolicy: { dueAfterEntries: 4, overdueAfterEntries: 6, dueAfterSeconds: 10, overdueAfterSeconds: 20 },
  });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paid(env, alex);
  await checkpoint(env, alex);
  assert.equal(ok(await alex.get('/api/evidence/anchor')).window.state, 'anchored');
  // And a policy that does not allow for the self-cost is rejected rather than alarming forever.
  assert.throws(
    () => anchorWindow({ lastCheckpointAt: 1, lastCheckpointCount: 0, entryCount: 1, now: 2, policy: { ...ANCHOR_POLICY, dueAfterEntries: 2 } }),
    /must exceed 2/,
  );

  // Time passes with nothing signing a checkpoint — an idle vault, or a browser nobody opened.
  env.advance(1_000);
  await paid(env, alex, 12_000);
  const status = ok(await alex.get('/api/evidence/anchor'));
  assert.equal(status.window.state, 'overdue');
  assert.ok(status.window.age >= 1_000, 'the age of the oldest unanchored evidence is reported');
  assert.match(status.window.reason, /entries and \d+h since the last checkpoint/);
});

/* ============================================ browser storage loss, and the rewrite */

test('losing browser storage loses the tripwire and not the anchor', async t => {
  const sink = recordingSink();
  const env = await start(t, { anchorSink: sink });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paid(env, alex);
  const { target } = await checkpoint(env, alex);

  // What the browser had kept.
  const browserHad = { checkpoints: [{ head: target.head, count: target.count, at: target.at }] };

  /*
   * Site data cleared: the local tripwire is gone. This is exactly why it cannot be the durable
   * anchor — and why the sink's copy, which survives this, is.
   */
  const afterLoss = { checkpoints: [] };
  assert.equal(checkpointDisagreement(afterLoss, [{ count: target.count, head: 'anything' }]), null,
    'an empty browser detects nothing, which is the limitation');
  assert.ok(checkpointDisagreement(browserHad, [{ count: target.count, head: 'rewritten' }]),
    'whereas a browser that still remembers does detect it');

  // The sink still holds the checkpoint, and it is still verifiable.
  const held = await sink.fetchLatest(target.vaultId);
  assert.equal(held.result, ANCHOR.STORED);
  const exported = ok(await alex.get('/api/evidence'));
  assert.equal(verifyCheckpoint(held.checkpoint, exported.vaultPublicKey, { vaultId: target.vaultId }).ok, true);
});

test('a server-side rewrite is caught by the externally held checkpoint', async t => {
  const sink = recordingSink();
  const env = await start(t, { anchorSink: sink });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paid(env, alex);
  const { target } = await checkpoint(env, alex);
  const externallyHeld = (await sink.fetchLatest(target.vaultId)).checkpoint;

  /*
   * The complete attack: rewrite every entry, recompute the chain so it verifies perfectly,
   * delete the local checkpoints so nothing in the database contradicts it. The one thing the
   * operator cannot reach is the sink's copy.
   */
  const db = await env.app.db();
  await db.query('DROP TRIGGER evidence_append_only ON evidence');
  await db.query('DROP TRIGGER evidence_checkpoints_append_only ON evidence_checkpoints');
  // The anchor records are append-only too, so even this attack has to disable a third
  // trigger first. Needing to is the protection working.
  await db.query('DROP TRIGGER evidence_anchors_append_only ON evidence_anchors');
  await db.query('DELETE FROM evidence_anchors');
  await db.query('DELETE FROM evidence_checkpoints');
  const rows = (await db.query('SELECT * FROM evidence ORDER BY seq')).rows;
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

  const exported = ok(await alex.get('/api/evidence'));
  assert.equal(exported.verified.ok, true, 'the chain verifies — a chain alone proves nothing here');
  assert.equal(exported.checkpoints.anyPresent, false, 'and nothing in the database contradicts it');

  // The externally held checkpoint does.
  const verdict = compareAgainstExternal(exported.bundle.entries, externallyHeld.record);
  assert.equal(verdict.verdict, 'REWRITTEN');
  assert.match(verdict.reason, /has been rewritten/);
  assert.equal(verdict.expectedHead, target.head);
  assert.notEqual(verdict.foundHead, target.head);
  // And its signature still checks out, because the operator never had the key.
  assert.equal(verifyCheckpoint(externallyHeld, exported.vaultPublicKey, { vaultId: target.vaultId }).ok, true);
});

test('a truncated log is distinguished from a rewritten one', async t => {
  const sink = recordingSink();
  const env = await start(t, { anchorSink: sink });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paid(env, alex);
  const { target } = await checkpoint(env, alex);
  const externallyHeld = (await sink.fetchLatest(target.vaultId)).checkpoint;
  const exported = ok(await alex.get('/api/evidence'));

  // The end of the log removed rather than altered. A different failure, and it must read as one.
  const truncated = exported.bundle.entries.slice(0, target.count - 2);
  const verdict = compareAgainstExternal(truncated, externallyHeld.record);
  assert.equal(verdict.verdict, 'TAIL_MISSING');
  assert.equal(verdict.expectedCount, target.count);
  assert.equal(verdict.foundCount, truncated.length);
  assert.match(verdict.reason, /are missing from the end/);

  // The untouched log matches, and says how much sits past the committed point.
  const honest = compareAgainstExternal(exported.bundle.entries, externallyHeld.record);
  assert.equal(honest.verdict, 'MATCHES');
  assert.equal(honest.unanchoredTail, exported.bundle.entries.length - target.count);

  // A checkpoint naming nothing usable is its own answer.
  assert.equal(compareAgainstExternal(exported.bundle.entries, { count: null }).verdict, 'UNUSABLE');
});

/* ================================================ recovery, from the trusted copy */

test('an operator recovers the truth from the externally held checkpoint alone', async t => {
  const sink = recordingSink();
  const env = await start(t, { anchorSink: sink });
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paid(env, alex);
  const { target } = await checkpoint(env, alex);
  const externallyHeld = (await sink.fetchLatest(target.vaultId)).checkpoint;
  const exported = ok(await alex.get('/api/evidence'));

  /*
   * Recovery means: holding only the sink's file and the vault's public key, establish what the
   * log must have been. Nothing here asks the deployment anything — which is the definition of
   * an independent anchor.
   */
  const signature = verifyCheckpoint(externallyHeld, exported.vaultPublicKey, { vaultId: target.vaultId });
  assert.equal(signature.ok, true, 'the checkpoint is genuine');
  assert.equal(signature.record.head, target.head, 'and names the head the log must have had');
  assert.equal(signature.record.count, target.count, 'at this many entries');

  // Which is enough to adjudicate any log presented later, without trusting its presenter.
  assert.equal(compareAgainstExternal(exported.bundle.entries, signature.record).verdict, 'MATCHES');
  assert.equal(compareAgainstExternal([], signature.record).verdict, 'TAIL_MISSING');

  // A checkpoint signed by some other key is not an anchor for this vault.
  const { deriveAttestationKeys } = await import('../src/authorization.js');
  const stranger = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const forged = signCheckpoint(target, stranger);
  assert.equal(verifyCheckpoint(forged, exported.vaultPublicKey, { vaultId: target.vaultId }).ok, false);
});

/*
 * The three tests below were written after a demonstration of the verifier produced
 * `chain BROKEN` on a log that had just been sealed correctly. The cause was in the hashing
 * primitive, not in the anchoring: see src/canonical.js.
 */

test('a digest survives the round trip that a database and a network make of it', () => {
  // The bug: `canonicalJson` emitted the bare token `undefined`, which is not JSON. A record
  // with one absent field therefore hashed one way when it was signed, and another way after
  // it had been stored and fetched back — so an honest signature read as a forged one.
  const withAbsent = { a: 1, b: undefined, c: 'x' };
  const roundTripped = JSON.parse(JSON.stringify(withAbsent));

  assert.equal(canonicalJson(withAbsent), canonicalJson(roundTripped));
  assert.equal(canonicalJson(withAbsent), '{"a":1,"c":"x"}');
  assert.ok(!canonicalJson(withAbsent).includes('undefined'));
  // Valid JSON, which is the property the whole round trip rests on.
  assert.deepEqual(JSON.parse(canonicalJson(withAbsent)), { a: 1, c: 'x' });

  // Arrays cannot drop an element without renumbering the rest, so JSON writes null and so
  // does this. Nested, because that is where it would be missed.
  assert.equal(canonicalJson({ xs: [1, undefined, 3] }), '{"xs":[1,null,3]}');
  assert.equal(canonicalJson({ xs: [1, undefined, 3] }), canonicalJson(JSON.parse(JSON.stringify({ xs: [1, undefined, 3] }))));

  // There is no digest of nothing, and pretending otherwise is how the bug got in.
  assert.throws(() => canonicalJson(undefined), /no canonical form/);
});

test('a checkpoint missing a field is refused rather than signed as absent', () => {
  const keys = deriveAttestationKeys(new Uint8Array(crypto.randomBytes(64)), 1);
  const complete = { vaultId: 'tb1qvault', head: 'aGVhZA', count: 7, at: 1_770_000_000, nonce: 'n-1' };

  // The control: the complete record signs and verifies, so the refusals below are about the
  // missing field and not about the fixture.
  assert.equal(verifyCheckpoint(signCheckpoint(complete, keys), keys.publicKeyBase64).ok, true);

  // `at` is the one that was unchecked. The unanchored window is measured from it, so a
  // checkpoint without one cannot do the job the mechanism exists for.
  for (const bad of [undefined, null, 0, -1, 1.5, '1770000000']) {
    assert.throws(() => signCheckpoint({ ...complete, at: bad }, keys), /when it was made/,
      `at: ${String(bad)} must be refused`);
  }
  for (const field of ['vaultId', 'head', 'nonce']) {
    assert.throws(() => signCheckpoint({ ...complete, [field]: undefined }, keys), /must name/);
  }
  assert.throws(() => signCheckpoint({ ...complete, count: undefined }, keys), /must count/);

  /*
   * And the verify side refuses the same record even carrying a valid signature — because a
   * checkpoint is only useful if every field it needs is there, and a verifier holding one
   * fetched from a sink has no way to ask where the missing part went.
   */
  const unusable = signCheckpoint(complete, keys);
  for (const [field, reason] of [['at', /when it was made/], ['head', /missing a vault/], ['nonce', /missing a vault/]]) {
    const stripped = { ...unusable, record: { ...unusable.record } };
    delete stripped.record[field];
    const verdict = verifyCheckpoint(stripped, keys.publicKeyBase64);
    assert.equal(verdict.ok, false);
    assert.match(verdict.reason, reason);
  }
});

test('the browser refuses to sign a checkpoint the server did not fully supply', async () => {
  /*
   * The server supplies every field of a checkpoint, and the server is the party a checkpoint
   * exists to hold to account. One it left out would have been signed as absent — giving an
   * operator a way to make every checkpoint unverifiable while the page, the sink and the
   * status all reported success. Anchoring that reports success and proves nothing is worse
   * than anchoring that is visibly off.
   */
  const unlocked = { unlock: 'not reached', attestationEpoch: 1 };
  const complete = { vaultId: 'tb1qvault', head: 'aGVhZA', count: 7, at: 1_770_000_000, nonce: 'n-1' };

  for (const field of ['vaultId', 'head', 'nonce', 'count', 'at']) {
    const target = { ...complete };
    delete target[field];
    await assert.rejects(
      () => signEvidenceCheckpoint({}, unlocked, target),
      /did not supply/,
      `a missing ${field} must be refused`);
  }

  // It refuses before touching the phrase: `record` is empty and `unlock` is not a key, so
  // anything that got as far as opening the vault would throw something else entirely.
  await assert.rejects(() => signEvidenceCheckpoint({}, unlocked, { ...complete, at: 0 }), /did not supply/);
});
