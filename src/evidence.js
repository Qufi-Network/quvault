/*
 * The evidence log: what happened, in an order nobody can quietly change.
 *
 * Until now security events went to a log line and nothing else, so a process restart lost
 * them — Phase A finding F4. An institutional treasury has to be able to answer, months later
 * and to somebody who does not trust the operator, "what was approved, by whom, under which
 * rules, and what did the system actually do about it".
 *
 * WHAT MAKES THIS TAMPER EVIDENT, AND WHAT DOES NOT
 *
 * Each entry commits to its predecessor, so editing one entry invalidates every entry after
 * it. That detects a targeted edit — someone changing one approval, or removing one rejection —
 * without anyone needing a prior copy of the log.
 *
 * It does NOT stop an administrator who can write to the whole database. They can rewrite
 * every entry and recompute the chain from the genesis onward, and the result verifies. A hash
 * chain is tamper EVIDENT against partial edits, not tamper PROOF against a privileged
 * operator, and this file will not pretend otherwise. What defends against that is holding a
 * dated export somewhere the operator does not control, and comparing: an earlier export that
 * disagrees with the live log is the proof. See `EVIDENCE.md`.
 *
 * ORDERING AND CONCURRENCY. The chain is the order. `seq` exists so a reader can page through
 * cheaply, and is deliberately NOT part of the hash — the predecessor link already fixes the
 * sequence, and leaving seq out means a hash can be computed before the database assigns one,
 * which is what lets an entry be written in a single statement. Two writers racing for the
 * same predecessor are resolved by a uniqueness constraint on it, not by a lock: one wins, the
 * other sees the conflict and retries against the new head.
 */
import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical.js';

/** The export format. A verifier refuses a bundle whose version it does not know. */
export const EVIDENCE_FORMAT = 'quvault-evidence-1';

/**
 * What the first entry commits to.
 *
 * A literal rather than NULL: Postgres permits many NULLs in a unique index, so a nullable
 * predecessor would let two genesis entries exist and the chain would fork silently.
 */
export const GENESIS = 'quvault-evidence-genesis';

/*
 * The taxonomy.
 *
 * Requirement: an attempt, an authorisation, a rejection, a signature, a broadcast and a
 * confirmation are six different facts and none of them may be inferred from another. A
 * payment with `signature.produced` and no `broadcast.accepted` is a payment whose outcome is
 * unknown — that is a true and useful statement, and collapsing these into one "status" field
 * is exactly how it would be lost.
 */
export const EVIDENCE = {
  PROPOSAL_CREATED: 'proposal.created',
  AUTHORIZATION_ATTEMPTED: 'authorization.attempted',
  AUTHORIZATION_GRANTED: 'authorization.granted',
  AUTHORIZATION_REJECTED: 'authorization.rejected',
  SIGNATURE_PRODUCED: 'signature.produced',
  BROADCAST_ACCEPTED: 'broadcast.accepted',
  BROADCAST_REFUSED: 'broadcast.refused',
  TRANSACTION_CONFIRMED: 'transaction.confirmed',
  DIGEST_MISMATCH: 'transaction.digest_mismatch',
  SCANNER_UNAVAILABLE: 'scanner.unavailable',
  PAD_FAILURE: 'scanner.pad_failure',
  BIOMETRIC_FAILURE: 'scanner.biometric_failure',
  CUSTODY_MIGRATION: 'custody.migration',
  RATE_LIMITED: 'request.rate_limited',
};

const KNOWN_KINDS = new Set(Object.values(EVIDENCE));
export const isKnownKind = kind => KNOWN_KINDS.has(kind);

/**
 * The bytes an entry's hash is taken over.
 *
 * Canonical JSON from `src/canonical.js` — the same serialisation the transaction digest uses,
 * so there is one answer to "what are the bytes of this object" in the codebase rather than
 * two that might disagree. `seq` is absent on purpose; see the header.
 */
export function evidenceBytes(entry) {
  return canonicalJson({
    v: EVIDENCE_FORMAT,
    id: entry.id,
    at: entry.at,
    kind: entry.kind,
    actor: entry.actor ?? null,
    // Null today. The column exists so an organisation identifier can be recorded later
    // without rewriting entries that predate organisations — see EVIDENCE.md.
    scope: entry.scope ?? null,
    subjectKind: entry.subjectKind ?? null,
    subjectId: entry.subjectId ?? null,
    payload: entry.payload ?? {},
    prev: entry.prev,
  });
}

export const evidenceHash = entry =>
  createHash('sha256').update(evidenceBytes(entry), 'utf8').digest('base64url');

/** Builds the entry and its hash. Pure: the caller decides whether it is ever written. */
export function sealEntry(entry) {
  if (!isKnownKind(entry.kind)) throw new Error(`Unknown evidence kind: ${entry.kind}`);
  if (!entry.prev) throw new Error('An evidence entry must commit to a predecessor.');
  const sealed = {
    id: entry.id,
    at: entry.at,
    kind: entry.kind,
    actor: entry.actor ?? null,
    scope: entry.scope ?? null,
    subjectKind: entry.subjectKind ?? null,
    subjectId: entry.subjectId ?? null,
    payload: entry.payload ?? {},
    prev: entry.prev,
  };
  return { ...sealed, hash: evidenceHash(sealed) };
}

/* ------------------------------------------------------------------ verification */

/**
 * Checks a chain of entries, in the order given.
 *
 * Reports every problem it finds rather than the first, because an investigator needs to know
 * the shape of the damage. Never throws: a malformed bundle is an answer, not an error.
 */
export function verifyChainOfEvidence(entries, { expectGenesis = true } = {}) {
  const problems = [];
  if (!Array.isArray(entries)) return { ok: false, problems: ['the bundle has no entries'], length: 0, head: null };

  let previous = null;
  for (const [index, entry] of entries.entries()) {
    const where = `entry ${index}${entry?.id ? ` (${entry.id})` : ''}`;
    if (!entry || typeof entry !== 'object') {
      problems.push(`${where} is not an entry`);
      continue;
    }
    if (!isKnownKind(entry.kind)) problems.push(`${where} has an unknown kind "${entry.kind}"`);

    // The hash has to be the hash of the contents, or the contents were changed after the fact.
    const recomputed = evidenceHash(entry);
    if (recomputed !== entry.hash) problems.push(`${where} does not hash to its recorded hash`);

    // And it has to commit to the entry before it, or the order was changed.
    const expectedPrev = previous ? previous.hash : GENESIS;
    if (index === 0 && !expectGenesis) {
      // A partial export: the first entry may legitimately point at something not included.
    } else if (entry.prev !== expectedPrev) {
      problems.push(index === 0
        ? `${where} is not the start of the chain`
        : `${where} does not follow ${previous.id}`);
    }
    previous = entry;
  }
  return {
    ok: problems.length === 0,
    problems,
    length: entries.length,
    head: previous?.hash ?? null,
  };
}

/* ---------------------------------------------------------------------- export */

/** The bundle an independent verifier is given. Everything needed, nothing live. */
export function buildBundle({ entries, exportedAt, subjectId = null, complete = true }) {
  return {
    format: EVIDENCE_FORMAT,
    exportedAt,
    // Says plainly whether this is the whole log or a slice, because the chain check differs.
    complete,
    subjectId,
    genesis: GENESIS,
    count: entries.length,
    head: entries.length ? entries.at(-1).hash : null,
    entries,
  };
}

/**
 * Verifies a bundle on its own terms, with no database and no application.
 *
 * This is what makes the evidence independently checkable: the bundle carries the format, the
 * genesis constant, the entries and the head, and everything else is recomputed here.
 */
export function verifyBundle(bundle) {
  if (bundle?.format !== EVIDENCE_FORMAT) {
    return { ok: false, problems: [`unknown bundle format "${bundle?.format}"`], length: 0, head: null };
  }
  const result = verifyChainOfEvidence(bundle.entries, { expectGenesis: bundle.complete !== false });
  const problems = [...result.problems];
  if (bundle.count !== bundle.entries?.length) problems.push('the bundle miscounts its own entries');
  if (bundle.head !== result.head) problems.push('the bundle head is not the head of its chain');
  if (bundle.genesis !== GENESIS) problems.push('the bundle names a different genesis');
  return { ...result, ok: problems.length === 0, problems };
}

/**
 * What a bundle establishes about one payment, without inferring anything.
 *
 * Each fact is present or it is not. A payment that was signed and whose broadcast is not
 * recorded is reported exactly that way, because "signed, outcome unknown" is the truth and
 * guessing at it is how an audit trail becomes fiction.
 */
export function summarisePayment(entries, subjectId) {
  const mine = entries.filter(e => e.subjectId === subjectId);
  const has = kind => mine.some(e => e.kind === kind);
  return {
    subjectId,
    events: mine.length,
    proposed: has(EVIDENCE.PROPOSAL_CREATED),
    authorizationAttempted: has(EVIDENCE.AUTHORIZATION_ATTEMPTED),
    authorizationGranted: has(EVIDENCE.AUTHORIZATION_GRANTED),
    authorizationRejected: has(EVIDENCE.AUTHORIZATION_REJECTED),
    signatureProduced: has(EVIDENCE.SIGNATURE_PRODUCED),
    broadcastAccepted: has(EVIDENCE.BROADCAST_ACCEPTED),
    broadcastRefused: has(EVIDENCE.BROADCAST_REFUSED),
    confirmed: has(EVIDENCE.TRANSACTION_CONFIRMED),
    // Stated so a reader is never left to assume a sensor was involved. There is no scanner
    // in this build; where one exists the granting entry carries what it measured.
    sensorMeasurement: mine.some(e => e.payload?.sensorEvidence === 'measured'),
  };
}
