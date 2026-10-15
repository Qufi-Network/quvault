# The evidence log

What happened, in an order nobody can quietly change — and an honest account of who can still
change it.

Before this, security events reached a log line and nothing else, so a process restart lost
them. That was finding F4 of the Phase A report. An institutional treasury has to be able to
answer, months later and to somebody who does not trust the operator: *what was approved, by
whom, under which rules, and what did the system actually do about it?*

---

## 1. What is recorded

One row per fact, in `evidence`. Fourteen kinds, grouped:

| Group | Kinds |
|---|---|
| The payment's life | `proposal.created`, `authorization.attempted`, `authorization.granted`, `authorization.rejected`, `signature.produced`, `broadcast.accepted`, `broadcast.refused`, `transaction.confirmed` |
| What went wrong | `transaction.digest_mismatch`, `request.rate_limited` |
| What a sensor said | `scanner.unavailable`, `scanner.pad_failure`, `scanner.biometric_failure` |
| Custody | `custody.migration` |

### Six facts, never inferred from each other

This is the design rule that matters most. An attempt, a grant, a signature, a broadcast, a
refusal and a confirmation are **six separate facts**, and no reader may derive one from
another.

A payment with `signature.produced` and no `broadcast.accepted` means *"it was signed, and the
log does not say whether it reached the network."* That is a true and useful statement, and it
is exactly what a single mutable `status` column destroys. `summarisePayment` reports each fact
as present or absent and the verifier prints the gap in words.

In particular: **a broadcast is not a confirmation.** `transaction.confirmed` is a distinct
kind and nothing in this build writes it yet — confirmation tracking is not implemented, which
the Phase A report lists as absent. The kind exists so that when it is implemented it is a
recorded fact rather than an inference from a txid.

### What a granting entry carries

`authorization.granted` records the proposal, the canonical transaction digest, the policy
version digest, the threshold and the approval count, the receipt version, the attestation key
epoch, the network and chain, and the verification outcome.

It also carries `sensorEvidence`, copied verbatim from the receipt. **In this build that value
is always `none`**, because there is no palm-vein scanner. The log never implies a physical
measurement occurred. Where a scanner exists one day, the value becomes `measured` and the
granting entry says which class of device and which capture — see `SCANNER-TRUST-BOUNDARY.md`.

### What is never recorded

Payload fields pass through the allowlist in `src/events.js`: 22 permitted names, everything
else dropped, and phrase-shaped or key-shaped values scrubbed **even on a permitted field**.
No recovery phrase, private key, unlock secret, biometric template, access token or credential
can reach the log, and there is a test that checks the vault's *actual* key material against
every stored row rather than relying on a pattern.

The caller's IP address is deliberately not recorded: it is personal data, and the policy name
plus the actor is enough to act on.

---

## 2. Integrity: what the construction does and does not buy

Each entry commits to its predecessor. `hash` is SHA-256 over the canonical JSON of the
entry's contents plus `prev` — the same canonical serialisation the transaction digest uses, so
the codebase has one answer to "what are the bytes of this object".

**`seq` is deliberately not part of the hash.** The predecessor link already fixes the order, and
leaving `seq` out is what lets an entry be hashed before the database assigns one — which is
what lets it be written in a single statement, with no two-phase write to get wrong.

### Three distinct claims, kept apart

**Claim 1 — the application cannot edit or delete committed evidence. TRUE AND ENFORCED.**
A `BEFORE UPDATE OR DELETE` trigger raises an exception. This is not the application declining
to write; it is the database refusing. It holds for every connection this application makes,
in Postgres and in PGlite, and there is a test that attempts both and requires the refusal.

**Claim 2 — a targeted edit is detectable without a prior copy. TRUE.**
Change one entry and it no longer hashes to its recorded hash; remove one from the middle and
the next entry points at something absent. Both are reported, per entry, by
`verifyChainOfEvidence`. There is a test that drops the trigger, edits a granting entry, and
requires the verdict to flip.

**Claim 3 — the log is immune to a privileged operator. FALSE. It is not claimed anywhere.**
Someone who can write the whole database can drop the trigger, rewrite every entry, recompute
the chain from the genesis onward, and the result verifies. A hash chain is tamper **evident**
against partial edits, not tamper **proof** against the operator.

### The threat model, stated plainly

| Attacker | Can they alter the log undetectably? |
|---|---|
| An application bug, or any code path in this app | **No.** The trigger refuses UPDATE and DELETE. |
| A compromised application server, with the app's database credentials | **Depends on the grant.** With `UPDATE`/`DELETE` privileges on `evidence` they can drop the trigger and rewrite. **Mitigation available today and not yet configured: grant the application role `INSERT` and `SELECT` on `evidence` and nothing else.** See §5. |
| A database administrator or anyone with superuser | **Yes, but not undetectably.** They can rewrite history and recompute the chain; they cannot produce a checkpoint matching the new head. See Claim 4. Without checkpoints, undetectable. |
| Anyone, against an exported bundle held elsewhere | **No.** They would have to alter the copy they do not hold. |

**So what actually defends against the operator?** Holding dated exports somewhere the operator
does not control, and comparing. An earlier export that disagrees with the live log is the
proof — not the chain. That is why the export format exists and why §4 is not optional.

### Claim 4 — a FULL rewrite is detectable, by a key the server has never held. IMPLEMENTED.

A **checkpoint** is a signed commitment to a head the log passed through:

```
{ v: 1, context: 'QUVAULT-EVIDENCE-CHECKPOINT-V1', vaultId, head, count, at, nonce }
```

signed in the owner's browser with the same ML-DSA-65 attestation key that signs authorisation
receipts — derived from the recovery phrase, never sent anywhere. **The server cannot make one.**

So the privileged operator of the table above can still rewrite every entry and recompute the
chain — and the result will fail against any checkpoint, because producing a matching one would
mean forging a post-quantum signature under a key they do not have. There is a test that
performs exactly that attack, resealing every entry so the chain verifies perfectly, and
requires the checkpoint to catch it.

```bash
GET  /api/evidence/checkpoint     # the head to commit to
POST /api/evidence/checkpoint     # the signed commitment
```

A checkpoint naming a head this log does not hold is refused, as is one signed by a key the
vault has not registered. One checkpoint per head; a repeat is the same commitment, not an
error.

**No circularity.** A checkpoint commits to a head that already exists. The entry recording that
a checkpoint was signed is covered by the *next* checkpoint, never the one just made, so the two
structures never depend on each other.

**It is not an authorisation.** Separate signing context, separate verification function, and no
field in it says anything about a palm. Keeping it apart from the receipt is what stops anyone
reading a checkpoint as evidence that a human or a sensor did anything.

### Claim 5 — a rewrite is detectable locally, immediately, with no configuration. IMPLEMENTED.

Claim 4 has a hole, and it is the word *externally*. Checkpoints live in the same database the
operator controls. An operator who rewrites the log can also drop the checkpoint trigger and
delete every row, and then nothing in the database contradicts them.

So the browser keeps its own note of what it committed to: `{ head, count, at }` in IndexedDB.
`GET /api/evidence/checkpoint` reports the heads the server *now* claims at each committed count
— recomputed from the live log, never read back from the checkpoint rows, so a rewrite shows up
— and `checkpointDisagreement` compares on login. There is a test that performs the complete
attack (reseal every entry, perfect the chain, delete the checkpoints) and requires the browser
to notice.

**This is a tripwire, not the durable external anchor, and the earlier version of this document
was wrong to present it as answering "externally retained".** The browser copy lives on one
device, dies with cleared site data, cannot be fetched by an auditor, and attests to nothing
cryptographically — it is a memory, not a record. What it uniquely gives is detection with *no
configuration at all*, at the moment somebody next signs in.

A log that merely **grew** is not a disagreement. Only a different history at a count already
committed to is.

### Claim 6 — a rewrite is provable to an outsider. IMPLEMENTED, when a sink is configured.

The durable anchor is a checkpoint forwarded to a store the operator does not control, which a
verifier retrieves themselves:

```bash
npm run verify:evidence -- bundle.json --external checkpoint-from-the-sink.json
```

Three verdicts, kept apart: `MATCHES`, `REWRITTEN`, and `TAIL_MISSING` — the last being the one
a hash chain can never produce, because a truncated chain verifies perfectly and only an
externally held *count* reveals that entries are gone.

Checkpoints are forwarded as soon as they are signed; a sink outage leaves them waiting rather
than losing them, and every attempt is recorded, including the failures. **Unconfigured, there is
no durable external anchor and the status says so in those words.**

Full design, the bounded window, failure behaviour and recovery: [CHECKPOINTING.md](CHECKPOINTING.md).

**What this still needs from the operator:** a sink, pointed at a party that is not them; and
payments, since a checkpoint is signed at the end of one and an idle vault drifts.

---

## 3. Concurrency, idempotency and failure

### Ordering without a lock

`prev_hash` is `UNIQUE`. Two requests racing to append after the same entry both try to claim
it as their predecessor; one wins, the other sees the conflict, re-reads the head and retries,
up to four attempts. No advisory lock, no ambiguity about order, and no possibility of a fork —
there is a test that raises six proposals concurrently and requires one unbroken chain with no
two entries sharing a predecessor.

`GENESIS` is a literal string rather than `NULL`, because Postgres permits many `NULL`s in a
unique index and a nullable predecessor would let two genesis entries exist and the chain fork
silently.

### Idempotency

The key is `kind : subjectId : digest-of-payload`, unique in the database. The same logical fact
written twice — a retried request, a serverless invocation replaying the same path — lands once.
A genuinely different fact about the same subject differs in its payload and lands separately.
There is a test that replays a completed broadcast and requires the row count not to move.

### Failure behaviour: fail closed, except where that is impossible

The three gates follow from one question — **is this step still reversible?** If it is, refusing
costs a retry and nothing else, so the evidence is required. If it is not, no refusal can undo
it, so the evidence is best-effort and the outcome is reconciled afterwards.

| Fact | Reversible when written? | Behaviour if it cannot be written |
|---|---|---|
| `authorization.granted` | yes — nothing has left the building | **refuse (503)**. No grant is acted on without a durable record of it. |
| `signature.produced` | yes — an unsent signature is inert | **refuse (503)**. The caller retries and signs again. |
| `broadcast.attempted` | yes — the last moment before the network | **refuse (503)**. Carries the txid, which is known here. |
| `broadcast.accepted` | **no** — already on the network | record best-effort, then reconcile. §3a |

So **a transaction cannot reach the network without durable evidence of the authorisation and
the policy that permitted it.** The 503 says explicitly that nothing has changed and the caller
should try again; it is not a 409, because the request was never the problem.

### 3a. Reconciling an uncertain outcome

The one state a crash can still leave: `broadcast.attempted` with no acceptance or refusal
after it. `summarisePayment` reports this as `outcomeUnknown` — not a guess about what happened,
a statement that nobody knows.

The attempt carries the txid, so the question has an authority that is not this application:

```bash
curl -X POST --cookie "$COOKIE" https://host/api/operations/$ID/reconcile
```

| What the chain says | What is recorded |
|---|---|
| it has the transaction | `broadcast.accepted`, marked `outcome: reconciled` |
| it has never seen it | `broadcast.refused`, marked `outcome: reconciled` |
| **could not ask** | **nothing.** The outcome stays open, which is the truth. |

The third row is the one that matters. "We could not reach the chain" is not "it did not
happen", and writing either outcome there would be a guess recorded permanently in an
append-only log. Reconciliation is idempotent and safe to run on a schedule.

---

## 4. Export and independent verification

```bash
# the whole log for this vault
curl -s --cookie "$COOKIE" https://host/api/evidence > bundle.json

# one payment
curl -s --cookie "$COOKIE" https://host/api/operations/$ID/evidence > payment.json

# check it, with no database and no running application
npm run verify:evidence -- bundle.json
npm run verify:evidence -- bundle.json --json     # for a pipeline
```

The bundle carries the format, the genesis constant, the entries, the count and the head.
`scripts/verify-evidence.js` recomputes every hash from each entry's own contents, checks each
commits to the one before, and takes nothing on trust from the exporting system. It exits
non-zero on a broken chain, so a pipeline notices.

A bundle for one payment is a **slice** and says `complete: false`; the verifier then does not
report a false break for the first entry not reaching the genesis. A whole-log export says
`complete: true` and is checked back to the genesis.

The script prints the limit of what a pass means, in those words, so nobody reads it as more.

**Retention is the operator's job and the part that matters.** Export on a schedule, store the
bundles outside the operator's own control, and keep them dated. The chain detects edits; only
an independent copy detects a rewrite.

---

## 5. Hardening available today and not yet configured

**Grant the application role `INSERT` and `SELECT` on `evidence`, and nothing else.**

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON evidence FROM quvault_app;
GRANT INSERT, SELECT ON evidence TO quvault_app;
```

That turns Claim 2 in §2 into something a compromised application server cannot defeat even by
dropping the trigger, because dropping a trigger needs ownership of the table. It requires two
database roles — one owning the schema, one the application connects as — which this deployment
does not yet have. It is the single highest-value change to the evidence layer and it is
configuration, not code.

---

## 6. Limitations

- **A privileged operator can rewrite the log.** §2. Mitigated only by external exports.
- **The application role is not yet restricted** to insert-and-select. §5.
- **`broadcast.accepted` is still best-effort**, necessarily — the transaction is on the network
  before it can be written. Mitigated by reconciliation, which needs running. §3a.
- **A checkpoint is signed at the end of a payment, not on a schedule.** The signing key is in
  the browser, so no server job can produce one. An idle vault accumulates an unanchored tail
  indefinitely, and a rewrite confined to that tail passes every check. `/api/evidence/anchor`
  reports how large it is. See [CHECKPOINTING.md](CHECKPOINTING.md) §3.
- **The external sink must be configured, and by the right party.** Unconfigured, there is no
  durable anchor. Operator-controlled, it is a backup. Both are reported as such.
- **The browser's retained head is a tripwire, not a record.** One device, lost with site data,
  not fetchable by a verifier.
- **`transaction.confirmed` is never written.** Confirmation tracking is not implemented, so a
  reconciled acceptance reports whether the chain has it, not how deeply.
- **Receipts do not yet carry an evidence anchor**, so a receipt cannot be associated with a
  position in the log independently. Designed in `AUTHORIZATION-V3-DESIGN.md`, not built.
- **No organisation scope yet.** The `scope` column exists and is always null. It is there so an
  organisation identifier can be recorded later without rewriting entries that predate
  organisations — which is the forward-compatibility this phase was asked to leave room for,
  and the RBAC migration itself is deliberately not started.
- **Quorum spends carry no per-signer receipt**, so a granting entry for one names only the
  owner's attestation key. Unchanged by this phase.
- **Evidence is not yet surfaced in the interface.** The routes exist; there is no audit screen.
