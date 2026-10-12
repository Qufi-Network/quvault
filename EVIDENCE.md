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
| A database administrator or anyone with superuser | **Yes.** They can rewrite history and recompute the chain. Nothing inside the database stops this. |
| Anyone, against an exported bundle held elsewhere | **No.** They would have to alter the copy they do not hold. |

**So what actually defends against the operator?** Holding dated exports somewhere the operator
does not control, and comparing. An earlier export that disagrees with the live log is the
proof — not the chain. That is why the export format exists and why §4 is not optional.

### What would make this stronger, and is not implemented

The owner's browser signs ML-DSA-65 receipts with a key the server has never held. If a receipt
also committed to the evidence head at signing time, the log would be anchored to a key the
operator cannot forge, and rewriting history would require forging a signature instead of
recomputing a hash. **This is not implemented**: it changes the receipt format, and this phase
was explicitly scoped to leave signing behaviour unchanged. It is the natural next strengthening.

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

### Failure behaviour, and the trade it makes

An append is awaited. A failure is logged and **swallowed**: the request proceeds.

This is deliberate, and it has a cost worth naming. Refusing to broadcast because the audit log
is unavailable would make the log an availability dependency for spending. For
`broadcast.accepted` it would be pointless anyway — the transaction is on the network before the
entry is written and cannot be recalled.

What this buys instead: because no fact is ever inferred from another, a missing entry leaves a
**visible gap** rather than a false claim. "Signed, outcome unrecorded" is what a reader gets,
and that is the honest reading. There is a test that drops the `evidence` table mid-payment and
requires the payment to complete.

An operator who needs fail-closed semantics does not have them today. That is a limitation, not
a feature, and it is listed in §6.

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
- **Failure is fail-open.** A payment completes even if its evidence cannot be written. §3.
- **`transaction.confirmed` is never written.** Confirmation tracking is not implemented.
- **Receipts do not commit to the evidence head**, so the log is not anchored to a key the
  operator lacks. §2.
- **No organisation scope yet.** The `scope` column exists and is always null. It is there so an
  organisation identifier can be recorded later without rewriting entries that predate
  organisations — which is the forward-compatibility this phase was asked to leave room for,
  and the RBAC migration itself is deliberately not started.
- **Quorum spends carry no per-signer receipt**, so a granting entry for one names only the
  owner's attestation key. Unchanged by this phase.
- **Evidence is not yet surfaced in the interface.** The routes exist; there is no audit screen.
