# Bounded checkpointing

How much of the evidence log is unanchored, what closes that window, and what an outsider can
establish when the operator is hostile.

---

## 1. The constraint everything follows from

**A checkpoint is signed with the owner's ML-DSA key, which exists only in their browser. The
server cannot sign one.**

That is why a checkpoint is worth anything — an operator who could mint one could rewrite the
log and re-commit to the result. It also means something that reads as a limitation and is
actually the point:

> **A server-side schedule cannot produce checkpoints.** It can decide one is *due* and say so.
> Only a browser, with the owner present, can sign it.

So "scheduled checkpointing" here means a **bounded window with a scheduled demand**, not a
cron job that signs things. Anything that signed on a schedule would be holding the key where
the server can reach it, which is the property being protected.

### Where a checkpoint actually gets signed

Signing needs the phrase, which needs the unlock secret, which the server releases **only after
a palm approval**. A page load therefore cannot produce a checkpoint without demanding a palm
scan for bookkeeping — which would make checkpointing compete with spending for the one thing
the owner must be physically present for.

So a checkpoint is signed **at the end of a payment**, with the unlock that payment already
holds. On login the browser does the two things that need no key:

| On login | Needs a key? |
|---|---|
| compare the server's claimed history against this browser's record | no |
| report the unanchored window | no |
| retry forwarding checkpoints a sink outage left waiting | no |
| **sign a checkpoint** | **yes — so it happens at the next payment instead** |

**The unanchored window closes at the next palm-approved action, not on a clock.** For a
treasury in use that is frequent. For an idle vault the tail grows, and the status says so.

---

## 2. The three tiers, and which one is the anchor

| Tier | Where | Detects | Does not survive |
|---|---|---|---|
| Hash chain | `evidence` table | a partial edit, with no prior copy needed | a full rewrite with the chain recomputed |
| **Browser copy** | IndexedDB | a full rewrite, even with the checkpoint rows deleted | cleared site data; cannot be fetched by a verifier |
| **External sink** | a store the operator does not control | a full rewrite, a truncation, and database destruction | not being configured |

### The browser copy is a tripwire, not the anchor

This is a correction to how it was described in the previous phase. The browser's stored
`{head, count}` lives in **one device's** IndexedDB. It dies when site data is cleared, it is
not retrievable by an auditor, and it attests to nothing cryptographically — it is a memory,
not a record.

It is genuinely useful: it is the only tier that works with no configuration at all, and it
catches a rewrite immediately, at the moment somebody logs in. But **it is not the durable
external trust anchor and this document will not call it one.** `GET /api/evidence/anchor`
returns `browserCopyIsNotAnAnchor: true` for the same reason.

### The external sink is the anchor

```bash
QUVAULT_ANCHOR_URL=https://evidence.the-customers-auditor.example/anchors
QUVAULT_ANCHOR_TOKEN=…
# Set this if the sink is somewhere YOU control. It is then a backup, not an anchor,
# and the status will say so rather than claiming external retention.
QUVAULT_ANCHOR_OPERATOR_CONTROLLED=false
```

The URL must belong to **whoever is retaining the evidence** — the customer, their auditor, a
write-once bucket under their key — not to whoever runs QuVault. Nothing in the code can verify
that, so the operator declares it, and a deployment that declares `operatorControlled` is
reported as having no external anchor.

A checkpoint carries a vault address, a hash, a count, a time, a nonce and a signature. **No key
material and nothing about a payment's contents**, so the sink learns that a log existed at a
size, and nothing about the money.

---

## 3. The bounded window

Two thresholds, because they call for different responses.

| | Default | Meaning |
|---|---|---|
| `dueAfterEntries` | 50 | a browser should checkpoint at its next payment |
| `dueAfterSeconds` | 6 h | same |
| `overdueAfterEntries` | 250 | the unanchored tail is larger than this deployment accepts |
| `overdueAfterSeconds` | 24 h | same |

**The measure is the unanchored tail — the number of entries written since the last checkpoint —
not the time since a job ran.** That number is what an auditor cares about: it is exactly how
much could be altered without contradicting any commitment.

A log with entries and no checkpoint at all is **overdue by definition**. None of it is anchored,
and reporting that as merely "due" would understate it.

### The floor: the tail is never zero

Signing a checkpoint writes two evidence entries of its own — that it was signed, and what the
sink said. Those necessarily come **after** the head being committed to, because a checkpoint
cannot cover a record of its own creation without a cycle.

So the tail immediately after a successful checkpoint is **two entries, not none**, and a policy
with a threshold at or below two is permanently due however diligent the deployment. `anchorWindow`
rejects such a policy rather than raising an alarm an operator would learn to ignore.
`CHECKPOINT_SELF_COST` names it.

---

## 4. Failure behaviour

| What fails | What happens | Why |
|---|---|---|
| **Sink unreachable** | the checkpoint is stored locally, the attempt is recorded, the checkpoint waits | losing it would be the one unrecoverable outcome, so it is the one thing that cannot happen |
| **Sink refuses** | same, recorded as `REFUSED` | distinct from unreachable: one is a configuration problem, the other an outage |
| **No sink configured** | recorded as `NOT_CONFIGURED`, status reports no external anchor | silence here would read as success |
| **Window overdue** | reported in `/api/evidence/anchor`, surfaced in the page | see below |
| **Checkpoint signing fails** | the payment is unaffected | it is bookkeeping about a payment that already completed and must never make it look failed |

### Why overdue does not block spending

An unanchored tail is a weaker audit position, not an unauthorised payment. The three gates
from the previous phase already guarantee that **no payment reaches the network without durable
evidence of its authorisation**; anchoring is about whether that evidence can later be proven
un-rewritten.

Blocking spending on an anchor sink would make a third party's uptime a prerequisite for moving
your own money, and the sink is deliberately a party QuVault does not control. A deployment that
wants fail-closed semantics should say so explicitly; it is not the default and is not
implemented.

**Every failed attempt is itself recorded in the evidence log.** An audit trail that forgot it
had been briefly unprotected would be worse than one that never claimed protection.

---

## 5. Recovery after missed checkpoints

Nothing is lost by missing one; the tail simply grows.

1. **Forwarding missed** (sink was down) — `POST /api/evidence/anchor/retry` forwards every
   checkpoint with no successful anchor. Needs no key, so it runs unattended, and is what the
   page calls on login when it sees work waiting. Idempotent.
2. **Signing missed** (nobody logged in, or no payment was made) — the next payment
   checkpoints. The window closes in one step regardless of how long it was open, because a
   checkpoint commits to a head, not to an interval.
3. **The gap is permanent and that is correct.** A checkpoint signed today commits to today's
   head. It says nothing about whether the tail was honest *while* it was unanchored, and
   nothing can retroactively anchor that period. The window is a measure of exposure, not a
   debt that gets repaid.

---

## 6. How an independent verifier identifies a rewritten or missing tail

With a checkpoint fetched from the sink themselves — not from the deployment:

```bash
npm run verify:evidence -- bundle.json --external checkpoint-from-the-sink.json
```

Three distinct answers, deliberately not collapsed:

| Verdict | What it means |
|---|---|
| `MATCHES` | the log passed through the committed head at the committed count. Reports the size of the tail after it, which **no checkpoint covers yet** |
| `REWRITTEN` | the log has an entry at that position and it is a different entry |
| `TAIL_MISSING` | the log is **shorter** than the checkpoint covers — entries were removed from the end |

`TAIL_MISSING` is the one a hash chain can never produce. A truncated chain verifies perfectly;
only something that knows how long the log used to be can notice, and that is precisely what an
externally held count is.

The signature is checked against the vault's public attestation key, which travels in the
bundle — so the whole comparison needs no call back to the deployment being audited.

### What a verifier should conclude

- `MATCHES`, signature valid → **the strongest statement available.** A key the deployment has
  never held commits to this exact history. The operator could rewrite the database and still
  not match this file.
- `MATCHES` with a large tail → the committed prefix is sound; the tail is unproven.
- `REWRITTEN` or `TAIL_MISSING` → **an incident, not a reporting problem.**
- No external checkpoint at all → the chain proves no partial edit, and nothing more.

---

## 7. Limitations

- **The sink must be configured, and by the right party.** Unconfigured, there is no durable
  external anchor; operator-controlled, it is a backup. Both are reported; neither is claimed
  as anchoring.
- **Nothing anchors the tail.** Entries after the last checkpoint are protected only by the
  chain, and a rewrite confined to them would pass every check. The window bounds how large
  that is; it cannot be zero.
- **An idle vault drifts.** No payments means no checkpoints, so a vault nobody uses accumulates
  an unanchored tail indefinitely. The status reports it; nothing fixes it without the owner.
- **The sink's acknowledgement is not evidence.** `ref` is a convenience for chasing a record —
  this deployment could invent one. The proof is a verifier fetching from the sink.
- **A checkpoint proves a log existed, not that it was true.** It commits to a head. If a
  payment was recorded dishonestly *before* being checkpointed, the checkpoint faithfully
  commits to the dishonest record.
- **No fail-closed mode.** An overdue window does not block spending. §4.
- **Bitcoin or transparency-log anchoring is not implemented.** An OP_RETURN or a public append
  only log would remove the need to trust any single retention party. The sink interface is
  where that would go.
