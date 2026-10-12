/*
 * The evidence log: does it survive, does it refuse to be edited, and can an outsider check it.
 *
 * Phase A finding F4 was that security events reached only a log line, so a process restart
 * lost them. These tests exercise the nine things the evidence phase asked for: persistence
 * across restart, append-only enforcement, concurrent writes, duplicate events, tampering,
 * missing events, failed database writes, and export verification.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  EVIDENCE, GENESIS, EVIDENCE_FORMAT, sealEntry, evidenceHash, verifyChainOfEvidence,
  buildBundle, verifyBundle, summarisePayment,
} from '../src/evidence.js';
import { DEST, start, ok, signedIn, palmApprove, walletFor, signAndSendV2 } from './harness.js';

/** A payment taken all the way through, which is what produces a full chain of facts. */
async function paidOnce(env, client) {
  env.world.chain.utxos = [{ txid: 'a'.repeat(64), vout: 0, value: 900_000 }];
  const { operation } = ok(await client.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, client, operation.id);
  const sent = await signAndSendV2(env, client, operation.id);
  return { operation, sent };
}

/* ====================================================== the chain, on its own terms */

test('an entry hashes over its contents and commits to the one before it', () => {
  const first = sealEntry({
    id: 'e1', at: 1_800_000_000, kind: EVIDENCE.PROPOSAL_CREATED,
    actor: 'alex', subjectKind: 'operation', subjectId: 'op-1',
    payload: { network: 'testnet4' }, prev: GENESIS,
  });
  const second = sealEntry({
    id: 'e2', at: 1_800_000_001, kind: EVIDENCE.AUTHORIZATION_GRANTED,
    actor: 'alex', subjectKind: 'operation', subjectId: 'op-1',
    payload: { threshold: 1 }, prev: first.hash,
  });

  assert.equal(verifyChainOfEvidence([first, second]).ok, true);
  assert.equal(verifyChainOfEvidence([first, second]).head, second.hash);

  // Editing any field changes the hash, so the recorded hash no longer matches.
  for (const change of [{ actor: 'sam' }, { at: 1_900_000_000 }, { subjectId: 'op-2' },
    { payload: { threshold: 9 } }, { kind: EVIDENCE.BROADCAST_ACCEPTED }]) {
    const edited = { ...first, ...change };
    assert.notEqual(evidenceHash(edited), first.hash, JSON.stringify(change));
    const broken = verifyChainOfEvidence([edited, second]);
    assert.equal(broken.ok, false);
    assert.ok(broken.problems.some(p => /does not hash/.test(p)), 'the edit is reported');
  }

  // Reordering breaks the link, because the order IS the chain.
  assert.equal(verifyChainOfEvidence([second, first]).ok, false);
  // Removing the first leaves the second pointing at something absent.
  assert.equal(verifyChainOfEvidence([second]).ok, false);
  // An entry whose kind nobody recognises is reported rather than silently accepted.
  assert.equal(verifyChainOfEvidence([sealEntry({ ...first, kind: EVIDENCE.PROPOSAL_CREATED })]).ok, true);
  assert.throws(() => sealEntry({ ...first, kind: 'something.invented' }), /Unknown evidence kind/);
  // And nothing may be sealed without committing to a predecessor.
  assert.throws(() => sealEntry({ ...first, prev: null }), /must commit to a predecessor/);
});

test('a bundle is verifiable on its own, and reports its own inconsistencies', () => {
  const one = sealEntry({ id: 'e1', at: 1, kind: EVIDENCE.PROPOSAL_CREATED, payload: {}, prev: GENESIS });
  const two = sealEntry({ id: 'e2', at: 2, kind: EVIDENCE.SIGNATURE_PRODUCED, payload: {}, prev: one.hash });
  const bundle = buildBundle({ entries: [one, two], exportedAt: 1_800_000_000 });

  assert.equal(verifyBundle(bundle).ok, true);
  assert.equal(verifyBundle({ ...bundle, format: 'something-else' }).ok, false);
  assert.equal(verifyBundle({ ...bundle, count: 99 }).ok, false);
  assert.equal(verifyBundle({ ...bundle, head: 'a-head-of-my-choosing' }).ok, false);
  assert.equal(verifyBundle({ ...bundle, genesis: 'another-genesis' }).ok, false);

  // A slice says so, and is not reported as a broken chain for not reaching the genesis.
  const slice = buildBundle({ entries: [two], exportedAt: 1, complete: false });
  assert.equal(verifyBundle(slice).ok, true, 'a declared slice verifies');
  assert.equal(verifyBundle({ ...slice, complete: true }).ok, false, 'claiming to be whole does not');
});

/* ============================================= through the server, and across a restart */

test('evidence is written to the database and survives a restart', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'quvault-evidence-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  // A persisted database, so the second app sees what the first wrote.
  const first = await start(t, { dataDir: dir });
  const alex = await signedIn(first, 'sub-alex');
  await walletFor(first, alex);
  const { operation } = await paidOnce(first, alex);

  const before = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  assert.ok(before.bundle.entries.length >= 4, 'several facts were recorded');
  assert.equal(before.verified.ok, true);
  const head = before.bundle.head;
  await first.app.close();

  /*
   * A new process against the same storage. This is the finding being fixed: before this
   * phase the events existed only in a log line and were gone at this point.
   */
  const second = await start(t, { dataDir: dir });
  const { rows } = await (await second.app.db()).query('SELECT * FROM evidence ORDER BY seq');
  assert.ok(rows.length >= 4, 'the entries are still there');
  assert.equal(rows.at(-1).hash, head, 'and the chain head is unchanged');
});

test('the six facts of a payment are recorded separately and never inferred', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation, sent } = await paidOnce(env, alex);

  const { bundle, summary } = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  const kinds = bundle.entries.map(e => e.kind);

  // An attempt, a grant, a signature and a broadcast are four facts, in that order.
  assert.ok(kinds.includes(EVIDENCE.PROPOSAL_CREATED), 'the proposal');
  assert.ok(kinds.includes(EVIDENCE.AUTHORIZATION_ATTEMPTED), 'the attempt');
  assert.ok(kinds.includes(EVIDENCE.AUTHORIZATION_GRANTED), 'the grant');
  assert.ok(kinds.includes(EVIDENCE.SIGNATURE_PRODUCED), 'the signature');
  assert.ok(kinds.includes(EVIDENCE.BROADCAST_ACCEPTED), 'the broadcast');
  assert.equal(kinds.indexOf(EVIDENCE.SIGNATURE_PRODUCED) < kinds.indexOf(EVIDENCE.BROADCAST_ACCEPTED), true);

  assert.equal(summary.signatureProduced, true);
  assert.equal(summary.broadcastAccepted, true);
  // Nothing confirmed it, and nothing pretends otherwise.
  assert.equal(summary.confirmed, false, 'a broadcast is not a confirmation');

  // The grant carries what the policy was and what a sensor measured, which is nothing here.
  const granted = bundle.entries.find(e => e.kind === EVIDENCE.AUTHORIZATION_GRANTED);
  assert.equal(granted.payload.receiptVersion, 2);
  assert.ok(granted.payload.policyVersion, 'the policy version digest');
  assert.equal(granted.payload.threshold, 1);
  assert.equal(granted.payload.sensorEvidence, 'none', 'no palm measurement is claimed');
  assert.equal(summary.sensorMeasurement, false);

  const broadcast = bundle.entries.find(e => e.kind === EVIDENCE.BROADCAST_ACCEPTED);
  assert.equal(broadcast.payload.txid, sent.txid);
});

test('a refusal is recorded as a refusal, with no grant and no signature', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'b'.repeat(64), vout: 0, value: 900_000 }];
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, operation.id);

  // No authorisation at all: refused.
  const refused = await alex.post(`/api/operations/${operation.id}/broadcast`, { hex: '00' });
  assert.equal(refused.status, 409);

  const { bundle, summary } = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  assert.equal(summary.authorizationAttempted, true, 'the attempt is recorded');
  assert.equal(summary.authorizationRejected, true, 'and so is the rejection');
  assert.equal(summary.authorizationGranted, false, 'nothing was granted');
  assert.equal(summary.signatureProduced, false, 'and nothing was signed');
  assert.equal(summary.broadcastAccepted, false);
  assert.equal(verifyBundle(bundle).ok, true, 'the chain is intact through a refusal');
});

/* ==================================================== append only, actually enforced */

test('the database refuses to update or delete a committed entry', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation } = await paidOnce(env, alex);
  const db = await env.app.db();

  const { rows } = await db.query('SELECT * FROM evidence ORDER BY seq LIMIT 1');
  const entry = rows[0];

  /*
   * Enforced by a trigger, not by the application declining to write. This holds against every
   * connection this app makes. It does NOT hold against somebody privileged enough to drop
   * the trigger — see EVIDENCE.md — and the point of this test is that the weaker claim is at
   * least true.
   */
  await assert.rejects(
    () => db.query('UPDATE evidence SET payload = $1 WHERE id = $2', ['{}', entry.id]),
    /append only/,
  );
  await assert.rejects(
    () => db.query('DELETE FROM evidence WHERE id = $1', [entry.id]),
    /append only/,
  );

  // And the entry is untouched, so the chain still verifies.
  const after = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  assert.equal(after.verified.ok, true);
});

test('tampering that gets past the application is still visible in the chain', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation } = await paidOnce(env, alex);

  /*
   * The trigger stops an UPDATE, so an attacker has to drop it first — which is exactly the
   * privileged-operator case. Having done so, they edit one entry. The chain is what catches
   * it: the entry no longer hashes to its recorded hash.
   */
  const db = await env.app.db();
  await db.query('DROP TRIGGER evidence_append_only ON evidence');
  const { rows } = await db.query(
    'SELECT id FROM evidence WHERE kind = $1', [EVIDENCE.AUTHORIZATION_GRANTED]);
  await db.query('UPDATE evidence SET payload = $1 WHERE id = $2',
    [JSON.stringify({ threshold: 99, sensorEvidence: 'measured' }), rows[0].id]);

  const after = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  assert.equal(after.verified.ok, false, 'the edit is detected');
  assert.ok(after.verified.problems.some(p => /does not hash/.test(p)));
});

/* ================================================= duplicates, concurrency, failure */

test('the same fact written twice lands once', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation } = await paidOnce(env, alex);
  const db = await env.app.db();

  const before = (await db.query('SELECT count(*)::int AS n FROM evidence')).rows[0].n;

  // Replaying the broadcast is idempotent at the API, and must not append a second set of
  // facts either — the same logical event has the same idempotency key.
  ok(await alex.post(`/api/operations/${operation.id}/broadcast`, { hex: '00' }));
  const after = (await db.query('SELECT count(*)::int AS n FROM evidence')).rows[0].n;
  assert.equal(after, before, 'a replay recorded nothing new');
});

test('concurrent payments produce one unbroken chain, not a fork', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'c'.repeat(64), vout: 0, value: 2_000_000 }];

  // Several proposals raised at once: each appends, and the uniqueness constraint on the
  // predecessor is what stops two of them claiming the same place in the chain.
  const proposals = await Promise.all(
    Array.from({ length: 6 }, () => alex.post('/api/withdrawals', { to: DEST, amount: 10_000 })));
  assert.ok(proposals.every(p => p.status === 200), 'all of them succeeded');

  const db = await env.app.db();
  const { rows } = await db.query('SELECT * FROM evidence ORDER BY seq');
  assert.ok(rows.length >= 6, 'every proposal was recorded');

  // No two entries share a predecessor, and the chain reads straight through.
  const prevs = rows.map(r => r.prev_hash);
  assert.equal(new Set(prevs).size, prevs.length, 'no fork');

  const entries = rows.map(r => ({
    id: r.id, at: Number(r.at), kind: r.kind, actor: r.actor ?? null, scope: r.scope ?? null,
    subjectKind: r.subject_kind ?? null, subjectId: r.subject_id ?? null,
    payload: JSON.parse(r.payload), prev: r.prev_hash, hash: r.hash,
  }));
  assert.equal(verifyChainOfEvidence(entries).ok, true, 'and it verifies end to end');
});

test('an unwritable log blocks the payment, and the payment survives to be retried', async t => {
  /*
   * THIS TEST'S PREMISE WAS DELIBERATELY REVERSED.
   *
   * It used to assert that a payment completed even when its evidence could not be written —
   * the fail-open behaviour of the first evidence phase. That was identified as the priority-one
   * defect of the F4 closure: a high-value transaction must not reach the network without a
   * durable record of the authorisation and the policy that permitted it. So the payment is now
   * refused, which `test/evidence-closure.test.js` covers directly.
   *
   * What is tested here instead is the property that makes refusing acceptable: the refusal is
   * not destructive. The operation is not marked failed, so once the log is writable again the
   * same payment goes through. Without that, fail-closed would turn a transient database
   * problem into a dead proposal and somebody would turn it off.
   */
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  env.world.chain.utxos = [{ txid: 'd'.repeat(64), vout: 0, value: 900_000 }];
  const { operation } = ok(await alex.post('/api/withdrawals', { to: DEST, amount: 100_000 }));
  await palmApprove(env, alex, operation.id);

  // The log becomes unwritable. Renamed rather than dropped, so it can come back without this
  // test having to restate the schema.
  const db = await env.app.db();
  await db.query('ALTER TABLE evidence RENAME TO evidence_unavailable');

  await assert.rejects(() => signAndSendV2(env, alex, operation.id), /./, 'refused while unwritable');
  assert.equal(env.world.log.broadcast.length, 0, 'and nothing reached the network');

  // The proposal is still alive: refusing to record is not the same as refusing the request.
  const waiting = ok(await alex.get('/api/wallet'));
  const still = [...(waiting.pending ?? []), ...(waiting.history ?? [])].find(o => o.id === operation.id);
  assert.ok(still, 'the proposal still exists');
  assert.notEqual(still.status, 'failed', 'and was not failed by the log being unavailable');

  // The log comes back, and the same payment completes.
  await db.query('ALTER TABLE evidence_unavailable RENAME TO evidence');
  const sent = await signAndSendV2(env, alex, operation.id);
  assert.ok(sent.txid, 'the retry succeeds');

  const { summary } = ok(await alex.get(`/api/operations/${operation.id}/evidence`));
  assert.equal(summary.authorizationGranted, true, 'and the evidence is there this time');
  assert.equal(summary.broadcastAccepted, true);
});

/* ========================================================= secrets never reach the log */

test('no secret reaches the evidence log, whatever happens', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  const { operation } = await paidOnce(env, alex);
  const db = await env.app.db();

  const { rows } = await db.query('SELECT * FROM evidence');
  const whole = JSON.stringify(rows);

  // The actual key material this vault holds, not a pattern that might match one.
  for (const secret of [
    alex.key.toString('hex'), alex.key.toString('base64'),
    Buffer.from(alex.attestation.secretKey).toString('base64'), alex.unlock,
  ]) {
    assert.ok(secret && !whole.includes(secret), 'no key material in the log');
  }
  assert.ok(!/"(mnemonic|privateKey|seed|secretKey|unlock|sealedKey)"/.test(whole), 'and no secret field');

  // Payloads are the allowlisted fields from src/events.js and nothing else.
  for (const row of rows) {
    for (const field of Object.keys(JSON.parse(row.payload))) {
      assert.ok(!/mnemonic|privateKey|secret|seed|unlock|password/i.test(field), field);
    }
  }
  assert.ok(operation.id);
});

/* ============================================ an outsider can check it, offline */

test('the exported bundle verifies with no database and no application', async t => {
  const env = await start(t);
  const alex = await signedIn(env, 'sub-alex');
  await walletFor(env, alex);
  await paidOnce(env, alex);

  const { bundle } = ok(await alex.get('/api/evidence'));
  assert.equal(bundle.format, EVIDENCE_FORMAT);
  assert.equal(bundle.complete, true);

  const file = path.join(os.tmpdir(), `quvault-bundle-${crypto.randomBytes(6).toString('hex')}.json`);
  fs.writeFileSync(file, JSON.stringify(bundle));
  t.after(() => fs.rmSync(file, { force: true }));

  /*
   * The script, as an operator or an auditor would run it: a separate process, given only the
   * file. If this needed the database it would not be independent evidence.
   */
  const root = path.dirname(new URL('.', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
  const out = execFileSync(process.execPath, ['scripts/verify-evidence.js', file], {
    cwd: root, encoding: 'utf8',
  });
  assert.match(out, /chain {7}intact/);
  assert.match(out, /signed|broadcast/);
  // The script states the limit of what a pass means, so nobody reads it as more.
  assert.match(out, /does NOT mean the log is complete/);

  // And it exits non-zero on a tampered bundle, so a pipeline notices.
  const broken = JSON.parse(JSON.stringify(bundle));
  broken.entries[0].payload = { tampered: true };
  fs.writeFileSync(file, JSON.stringify(broken));
  assert.throws(
    () => execFileSync(process.execPath, ['scripts/verify-evidence.js', file], { cwd: root, encoding: 'utf8', stdio: 'pipe' }),
    /./,
    'a tampered bundle exits non-zero',
  );
});
