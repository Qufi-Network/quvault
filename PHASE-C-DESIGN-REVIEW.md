# Phase C design review — tenant isolation and authorization V3

Two designs are complete and neither is implemented. This document is what they need before
anyone starts: the risks that are specific to *this* codebase rather than to multi-tenancy in
general, and the migration requirements each one imposes.

Read with `TENANT-ISOLATION-DESIGN.md` and `AUTHORIZATION-V3-DESIGN.md`. Those say what to
build. This says what it will cost and what can go wrong.

**Nothing here is a recommendation to begin.** §5 states the entry conditions, two of which are
not met.

---

## 1. What is being decided

| | Tenant isolation | Authorization V3 |
|---|---|---|
| Changes the database | yes, extensively | no |
| Changes what the browser signs | no | yes |
| Changes custody | **no** | **no** |
| Reversible after deployment | partly — see R4 | **no** — see R9 |
| Blocks the other | **yes** — V3 may need an organisation id | no |
| Size | large: every query, every route | small, except `fee-flexible` |

The ordering follows from one row: **V3's record shape depends on whether an organisation
identifier has to be in it.** Build V3 first and the answer gets guessed. Build tenancy first
and it is known. So tenancy is first, and the part of V3 that does not depend on it
(the policy descriptor and the evidence anchor) can be built alongside.

---

## 2. Tenant isolation — implementation risks

Ordered by what they cost if they go wrong, not by likelihood.

### T1 — The long step is step 4, and it is the one with the bugs — HIGH

`TENANT-ISOLATION-DESIGN.md` §5 step 4 is "add the scope to every query, one route at a time".
There are **44 routes, 40 of them authenticated** — the four that are not are config, login
start, login finish and logout — and a missed scope on any one of the 40 is a cross-tenant read.

The design's R3 — scope at the query, not after it — makes a *missed* scope return nothing
rather than everything, which turns the failure from a disclosure into a visible bug. That is
the single most valuable rule in the document and it only works if it is followed everywhere.

**What reduces it:** a test per route, as §7.1 requires, written as "organisation B asks for
organisation A's row" rather than "organisation A asks for its own". The second kind passes on
a route with no scope at all.

**What does not reduce it:** code review. A missing `WHERE` clause is invisible in a diff that
adds twenty of them.

### T2 — `scope` is in an append-only table — HIGH, and permanent

Evidence entries cannot be corrected. An entry written with a scope before the queries use it,
or with the wrong scope, is in the chain forever: changing it changes its hash, which breaks the
chain, which is the chain working correctly.

This is why step 8 is last. It is also the one step whose mistake cannot be fixed by a later
migration, which makes it the most expensive cheap step in the plan.

**What reduces it:** doing it last, and a test asserting that a scoped write cannot happen while
any route still reads unscoped.

### T3 — Separation of duties has no safe default — MEDIUM, and a product decision

Today a proposer can always approve their own proposal. For a one-person treasury that is
correct and necessary; for an institution it voids the control entirely. R6 makes it a policy
field precisely because **neither value is safe to hardcode**, and that means someone has to
decide the default for each tier of customer.

That decision is not a code decision and should not be made by whoever writes the migration.

### T4 — Backfilling one organisation per user is the irreversible part — MEDIUM

Steps 1–3 are additive and can be rolled back. The moment step 4 lands on even one route, the
application reads a column the old code does not write, and rolling back means rolling back the
deployment, not the schema.

**What reduces it:** steps 1–3 deployed and left running for a release before step 4 begins, so
the backfill is proven under real traffic while nothing depends on it.

### T5 — A removed member's pending approval — MEDIUM, and currently undecided

§7.8. A user removed mid-proposal must stop counting toward its quorum — or must not, and right
now the system has not decided.

What it does today: `operations.required` is a snapshot column written when the proposal is
raised, `approvalsOf` joins `approvals` to `users` and not to `members`, and `applyPolicy` prunes
the roster without touching proposals in flight. So a proposal is judged against the threshold
that was in force when it was raised, by the people who approved it at the time, even if one of
them is no longer a signer when it completes.

**That is defensible and it is not a bypass.** Removing a signer is itself a palm-approved policy
change at the current quorum, and the approval it invalidates was genuinely granted by a
then-current member. "Approvals stand under the policy in force when the proposal was raised" is
a coherent rule. The problem is that nobody chose it — it is what the snapshot column happens to
produce.

Tenancy makes the choice urgent rather than academic. Today a signer leaves only through a whole
policy replacement, which is rare. With roles, revoking someone's Approver role will be a routine
administrative act, and the question "does their pending approval still count?" will be asked by
a customer rather than by a test.

**What this needs:** a decision, then §7.8 pinning it down in both directions.

### T6 — Scoped evidence exports are slices, and a slice proves less — LOW, but must be stated

With one chain per deployment, an export scoped to one organisation cannot be walked back to the
genesis. `complete: false` and the verifier already handle it, so nothing breaks — but an
auditor's bundle becomes *internally consistent over a range* rather than *complete*, and that
is a weaker statement than the one they get today.

The alternative — a chain per organisation — costs a genesis, a head, a checkpoint series and
`UNIQUE (scope, prev_hash)` per tenant, to isolate a log that is never read across tenants. The
design chooses the slice, and the cost is disclosure, not strength.

### T7 — Roles checked in the page instead of the server — LOW probability, HIGH impact

R5. Named because it is the mistake every admin UI makes once: the page hides a button and the
route stays open. Every role check belongs on the route, and the page's version of it is a
convenience with no security value.

---

## 3. Tenant isolation — migration requirements

What must exist before step 1, and what each step requires to be called done.

| | Requirement | Status today |
|---|---|---|
| M1 | The eight steps of §5 run in order, each deployable alone | design complete |
| M2 | Steps 1–3 run one full release before step 4 | not started |
| M3 | A per-route cross-tenant refusal test for all 40 authenticated routes | not started |
| M4 | `organisation_id` NOT NULL only after nothing writes null (step 5) | not started |
| M5 | Every existing user becomes a one-person organisation whose behaviour is **unchanged** | not started |
| M6 | Existing evidence entries keep `scope = null` and are **never** backfilled | enforced by the append-only trigger |
| M7 | Roles default to Owner + Approver, then narrow deliberately | not started |
| M8 | Migration is idempotent and versioned under the existing advisory lock | pattern established, v18 |
| M9 | The 208-test suite stays green at every step, with no test weakened | baseline established |
| M10 | Testnet4 only; no network gains the ability to send | holds today, must be re-asserted |

**M3 is the one that determines whether this is finished or merely working.** Forty routes × one
test is the bulk of the work, and skipping it means the isolation is untested on exactly the
paths where it matters.

---

## 4. Authorization V3 — implementation risks

### V1 — `fee-flexible` changes what a signature authorises — HIGH

Everything else in V3 adds fields. `intentBinding: 'fee-flexible'` changes the meaning of the
signature: the server becomes free to construct a transaction the approver never saw, within a
ceiling.

The ceiling is what makes it safe, and the ceiling is the whole risk. A missing, defaulted,
unbounded or server-chosen ceiling turns "flexible on the fee" into "authorised to send an
unbounded amount to miners". It must be chosen by the approver, shown in the statement they
approve, and covered by the signature.

**The design's own §6.1 says not to build this until a treasury needs it**, and that is the
right call. Until then `intentBinding` is always `strict` and V3 is V2 plus two readable
fields — which carries almost none of this risk.

### V2 — `policyDigest` fixes a serialisation forever — HIGH, and silent

`policyDigest` is taken over the canonical form of the policy descriptor. Change how the
descriptor serialises later — add a field, reorder a nested object, change a null to an absent
key — and **every V3 receipt ever signed stops verifying.** There is no migration for this; the
records are signed.

This is not hypothetical in this codebase. A defect fixed in this phase was exactly this class:
`canonicalJson` emitted the bare token `undefined`, so a record with one absent field hashed one
way when signed and another after a round trip through a database. It is fixed and tested, and
the lesson generalises: **before the first V3 record is signed, the descriptor's canonical form
must be frozen and tested against a round trip.**

### V3 — The evidence anchor must point backwards, and only backwards — MEDIUM

`AUTHORIZATION-V3-DESIGN.md` §3 resolves this: the receipt commits to a head that already
existed, the evidence entry commits to the receipt, nothing commits forward.

The risk is not the design, it is the implementation. The anchor must be read **before** the
grant entry is appended, and the ordering in `src/app.js` already appends the grant with
`required: true` before signing — so the anchor has to be captured earlier in that sequence than
it feels natural to capture it. A cycle here would not be subtle: it would make the entry's hash
depend on itself and fail immediately. That is the good case.

### V4 — Three versions of `whatItProves` — MEDIUM

V1, V2 and V3 all keep verifying, and `whatItProves` reports per-version capability. The risk is
that a caller checks a *record* rather than asking what the record proves — reading
`policyDescriptor` off a V2 record, finding undefined, and treating absence as permission.

`expected.minVersion` exists for a caller that needs V3 guarantees. Any new call site that
depends on a V3-only field must set it.

### V5 — `biometricVerified` must stay forbidden — LOW probability, severe if wrong

V1 asserted it unconditionally and without a sensor. V2 forbids it. V3 must forbid it, and
`verification.sensorEvidence: 'none'` must stay a recorded value rather than an omission, so a
reader can tell "nothing measured" from "field not present".

There is no scanner in this build. A V3 record asserting a measurement would be the single most
damaging thing this system could produce, because it would be cryptographically signed.

---

## 5. Authorization V3 — migration requirements

| | Requirement | Status today |
|---|---|---|
| N1 | V1 and V2 records keep verifying, unchanged | holds; covered by the suite |
| N2 | No historical record becomes stronger | `whatItProves` is per-version |
| N3 | `expected.minVersion` default stays unset | holds |
| N4 | The policy descriptor's canonical form is frozen and round-trip tested **before** the first V3 signature | **not done** |
| N5 | `quvault-evidence-1` is named in the anchor, and a future format changes the name | design complete |
| N6 | `intentBinding` is `strict` until a fee-adjustment requirement exists | **decision outstanding** |
| N7 | V3 is not signed until the organisation identifier question is answered (T/§6) | **blocked on Phase C** |
| N8 | No V3 record may assert `biometricVerified` or a measurement without attestation | structural check exists for V2, extends to V3 |

**N4 and N7 are the two that block.** N7 is the reason this document puts tenancy first.

---

## 6. What neither design changes

Stated explicitly because a large migration is where invariants quietly go.

- **Custody.** Keys stay in the owner's browser. An organisation is a policy and membership
  boundary, not a custodian, and does not get a key.
- **Testnet4 only.** No network gains the ability to send.
- **One phrase per browser.** A person in several organisations still has one recovery phrase.
- **The evidence chain.** No committed entry changes, for any reason.
- **The server cannot sign.** Not an authorisation, not a checkpoint. `ATTACK 17` enforces it.
- **No scanner, no PAD, no measured biometric entropy.** Unchanged by either design.

---

## 7. Entry conditions for Phase C

| | Condition | Met |
|---|---|---|
| E1 | Tenant isolation design reviewed and accepted | **awaiting review** |
| E2 | Authorization V3 design reviewed and accepted | **awaiting review** |
| E3 | Separation-of-duties default decided per customer tier (T3) | **NOT MET — product decision** |
| E4 | Fee-adjustment requirement known (N6) | **NOT MET — product decision** |
| E5 | 208-test baseline green | MET |
| E6 | Evidence layer durable, externally anchorable, independently verifiable | MET — `CHECKPOINTING.md` |
| E7 | Appetite for 40 route tests confirmed (M3) | **awaiting decision** |
| E8 | Fate of a removed approver's pending approval decided (T5) | **NOT MET — product decision** |

E3, E4, E7 and E8 are decisions, not work. None of them can be made by whoever writes the
migration, and all four change what gets built.

E8 is the one that is easy to miss, because the system already has an answer and nobody chose
it.
