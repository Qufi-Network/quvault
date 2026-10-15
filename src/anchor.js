/*
 * Anchoring the evidence log somewhere its operator does not control.
 *
 * THE CONSTRAINT THAT SHAPES ALL OF THIS. A checkpoint is signed with the owner's ML-DSA key,
 * which exists only in their browser. The server cannot sign one — that is precisely why a
 * checkpoint is worth anything, and it means **a server-side schedule cannot produce
 * checkpoints**. It can only decide that one is *due* and say so; a browser signs it when one
 * is next available. Anything that calls itself "scheduled checkpointing" and implies the
 * server does the signing is describing a weaker system than this one.
 *
 * What the server CAN do on a schedule is forward a checkpoint it already has to an external
 * sink. That half is ordinary server work and is where the external anchor comes from.
 *
 * THREE TIERS, AND ONLY ONE OF THEM IS A DURABLE EXTERNAL ANCHOR:
 *
 *   the hash chain        in the evidence table.    Detects a partial edit.
 *                                                   Defeated by a full rewrite.
 *
 *   the browser's copy    in IndexedDB.             Detects a full rewrite, including one
 *                                                   where the checkpoint rows were deleted.
 *                                                   **NOT a durable external anchor**: it is
 *                                                   one device's local memory, it dies with
 *                                                   cleared site data, and a verifier cannot
 *                                                   fetch it. It is a tripwire, not a record.
 *
 *   an external sink      somewhere the operator    The durable anchor. A verifier retrieves
 *                         does not control.         a checkpoint from it without asking this
 *                                                   application anything, and compares.
 *
 * A deployment with no sink configured has no durable external anchor. `createNullSink` says
 * so and the status route reports it; nothing here will describe that state as anchored.
 */

/** What a sink can tell us about a forwarding attempt. */
export const ANCHOR = {
  STORED: 'STORED',               // the sink took it
  REFUSED: 'REFUSED',             // the sink answered, and said no
  UNREACHABLE: 'UNREACHABLE',     // we could not ask
  NOT_CONFIGURED: 'NOT_CONFIGURED', // there is no sink
};

/**
 * How long, and how much, may go unanchored.
 *
 * Two thresholds rather than one, because they call for different responses. `due` means a
 * browser should sign a checkpoint at its next opportunity; it is the normal state of a system
 * that is being used. `overdue` means the unanchored tail has grown past what this deployment
 * is willing to leave unprotected, and that is a condition to surface loudly.
 *
 * The defaults assume a treasury somebody signs into most days. A vault used monthly will sit
 * overdue between uses, which is accurate rather than a bug — the tail really is unanchored —
 * and is the argument for a deployment raising the limits deliberately rather than pretending.
 */
/*
 * The floor on the unanchored tail, and why it cannot be zero.
 *
 * Signing a checkpoint itself writes evidence — that it was signed, and what the external sink
 * said about it. Those entries come AFTER the head being committed to, by construction: a
 * checkpoint cannot cover a record of its own creation without a cycle. So immediately after a
 * successful checkpoint the tail is two entries, not none, and a policy with a threshold at or
 * below two is permanently due no matter how diligently a deployment checkpoints.
 *
 * Stated as a constant because it is a property of the design rather than a tuning choice, and
 * because two tests tripped over it before it was written down.
 */
export const CHECKPOINT_SELF_COST = 2;

export const ANCHOR_POLICY = Object.freeze({
  dueAfterSeconds: 6 * 3600,
  dueAfterEntries: 50,
  overdueAfterSeconds: 24 * 3600,
  overdueAfterEntries: 250,
});

/**
 * Where the log stands relative to its last checkpoint.
 *
 * `unanchoredEntries` is the number of entries written since the last checkpoint — the tail a
 * rewrite could alter without contradicting any commitment. That number, not the elapsed time,
 * is what an auditor actually cares about.
 */
export function anchorWindow({ lastCheckpointAt, lastCheckpointCount, entryCount, now, policy = ANCHOR_POLICY }) {
  // A threshold below the self-cost can never be satisfied; say so rather than reporting a
  // permanent alarm that an operator will learn to ignore.
  if (policy.dueAfterEntries <= CHECKPOINT_SELF_COST) {
    throw new Error(`dueAfterEntries must exceed ${CHECKPOINT_SELF_COST}: checkpointing writes that many entries itself.`);
  }
  const anchoredCount = lastCheckpointCount ?? 0;
  const unanchoredEntries = Math.max(0, entryCount - anchoredCount);
  const age = lastCheckpointAt == null ? null : Math.max(0, now - lastCheckpointAt);

  // Nothing to anchor yet is not a problem; an empty log has no tail to rewrite.
  if (unanchoredEntries === 0) {
    return { state: 'anchored', unanchoredEntries, age, reason: null };
  }
  const overdue = unanchoredEntries >= policy.overdueAfterEntries
    || (age != null && age >= policy.overdueAfterSeconds)
    // Never checkpointed at all, with entries present: overdue by definition.
    || lastCheckpointAt == null;
  if (overdue) {
    return {
      state: 'overdue',
      unanchoredEntries,
      age,
      reason: lastCheckpointAt == null
        ? 'this log has never been checkpointed, so none of it is anchored'
        : `${unanchoredEntries} entries and ${Math.round(age / 3600)}h since the last checkpoint`,
    };
  }
  const due = unanchoredEntries >= policy.dueAfterEntries
    || (age != null && age >= policy.dueAfterSeconds);
  return {
    state: due ? 'due' : 'anchored',
    unanchoredEntries,
    age,
    reason: due ? 'a checkpoint should be signed at the next opportunity' : null,
  };
}

/* ------------------------------------------------------------------- the sinks */

const REQUIRED = ['name', 'describe', 'store', 'fetchLatest'];

export function assertSink(sink) {
  const missing = REQUIRED.filter(name => sink?.[name] === undefined);
  if (missing.length) throw new Error(`An anchor sink is missing: ${missing.join(', ')}.`);
  // A sink that could sign is not a sink: it would be another thing the operator controls.
  for (const forbidden of ['sign', 'signCheckpoint', 'key', 'secret']) {
    if (sink[forbidden] !== undefined) throw new Error(`An anchor sink must not hold signing material: ${forbidden}.`);
  }
  return sink;
}

/**
 * The sink used when none is configured. It stores nothing and says so.
 *
 * Deliberately not a silent no-op: a deployment with no external anchor is in a materially
 * weaker position, and every status it reports must make that visible rather than reading as
 * success.
 */
export function createNullSink() {
  return assertSink({
    name: 'none',
    describe: () => ({
      configured: false,
      external: false,
      reason: 'No external checkpoint sink is configured, so no checkpoint is retained outside '
        + 'this deployment. A rewrite of the whole database would leave nothing to contradict it '
        + 'except a browser that happens to remember, which is not a durable record.',
    }),
    store: async () => ({ result: ANCHOR.NOT_CONFIGURED, ref: null }),
    fetchLatest: async () => ({ result: ANCHOR.NOT_CONFIGURED, checkpoint: null }),
  });
}

/**
 * A sink over plain HTTP, which is what an external retention service looks like.
 *
 * The URL and credential belong to whoever is retaining the evidence — the customer, their
 * auditor, a write-once bucket — **not** to whoever runs QuVault. If the same party controls
 * both, this is not an external anchor and `describe()` will not claim it is.
 *
 * It never sends anything secret: a checkpoint is a vault address, a hash, a count, a time, a
 * nonce and a signature. No key material, and nothing about a payment's contents.
 */
export function createHttpSink({ url, token = null, fetchImpl = globalThis.fetch, operatorControlled = false, timeoutMs = 10_000 }) {
  if (!url) throw new Error('An HTTP anchor sink needs a URL.');
  const headers = {
    'content-type': 'application/json',
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };

  return assertSink({
    name: 'http',
    describe: () => ({
      configured: true,
      // Stated by the operator and taken at face value, because nothing here can verify it.
      // A deployment that lies to itself about this gets a status that agrees with the lie.
      external: !operatorControlled,
      reason: operatorControlled
        ? 'A sink is configured but this deployment controls it, so it is a backup rather than '
          + 'an independent anchor. Point it at a store the operator cannot write to.'
        : 'Checkpoints are forwarded to a sink outside this deployment.',
    }),

    async store(checkpoint) {
      try {
        const response = await fetchImpl(url, {
          method: 'POST',
          headers,
          body: JSON.stringify(checkpoint),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) {
          return { result: ANCHOR.REFUSED, ref: null, detail: `the sink answered ${response.status}` };
        }
        /*
         * A reference the sink gives back. Useful for an operator chasing a record, and NOT
         * evidence of anything — the operator could invent one. The proof is a verifier
         * fetching from the sink themselves.
         */
        const body = await response.json().catch(() => ({}));
        return { result: ANCHOR.STORED, ref: body?.id ?? body?.ref ?? null };
      } catch {
        return { result: ANCHOR.UNREACHABLE, ref: null, detail: 'the sink could not be reached' };
      }
    },

    /** What the sink holds, for a verifier or for recovery. */
    async fetchLatest(vaultId) {
      try {
        const response = await fetchImpl(`${url.replace(/\/$/, '')}/latest/${encodeURIComponent(vaultId)}`, {
          headers,
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) return { result: ANCHOR.REFUSED, checkpoint: null };
        return { result: ANCHOR.STORED, checkpoint: await response.json() };
      } catch {
        return { result: ANCHOR.UNREACHABLE, checkpoint: null };
      }
    },
  });
}

/* -------------------------------------------------- what a rewrite looks like */

/**
 * Compares a checkpoint retrieved from outside against the log a deployment is showing.
 *
 * This is the question an independent verifier is actually asking, and it has three distinct
 * failure answers that must not be collapsed:
 *
 *   REWRITTEN    the log has an entry at that position, and it is a different entry.
 *   TAIL_MISSING the log is shorter than the checkpoint covers — entries were removed.
 *   MATCHES      the log passed through the committed head at the committed count.
 *
 * `entries` is the chain in order, as exported. The checkpoint's signature is verified
 * separately; this function answers only whether the log agrees with it.
 */
export function compareAgainstExternal(entries, checkpointRecord) {
  const count = checkpointRecord?.count;
  const head = checkpointRecord?.head;
  if (!Number.isInteger(count) || !head) {
    return { verdict: 'UNUSABLE', reason: 'the external checkpoint names no head and count' };
  }
  if (entries.length < count) {
    return {
      verdict: 'TAIL_MISSING',
      reason: `the external checkpoint covers ${count} entries and this log has ${entries.length}: `
        + `${count - entries.length} are missing from the end`,
      expectedCount: count,
      foundCount: entries.length,
    };
  }
  const at = entries[count - 1];
  if (at?.hash !== head) {
    return {
      verdict: 'REWRITTEN',
      reason: `the external checkpoint commits to a different entry at position ${count}: `
        + 'this log has been rewritten',
      expectedHead: head,
      foundHead: at?.hash ?? null,
      atCount: count,
    };
  }
  return {
    verdict: 'MATCHES',
    reason: `the log passed through the committed head at ${count} entries`,
    atCount: count,
    // Everything after the committed point is not covered by THIS checkpoint.
    unanchoredTail: entries.length - count,
  };
}
