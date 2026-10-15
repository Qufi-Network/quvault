# Phase C design review — tenant isolation and authorization V3

Two designs are complete and neither is implemented. This document is what they need before
anyone starts: the risks that are specific to *this* codebase rather than to multi-tenancy in
general, and the migration requirements each one imposes.

Read with `TENANT-ISOLATION-DESIGN.md` and `AUTHORIZATION-V3-DESIGN.md`. Those say what to
build. This says what it will cost and what can go wrong.

**The four decisions this document asked for are made** — recorded in §0 and applied throughout.
The schema and migration sequence they imply is `PHASE-C-SCHEMA-AND-MIGRATION.md`; the route
inventory and isolation matrix is `PHASE-C-ROUTE-ISOLATION-MATRIX.md`. No Phase C code is
written.

---

## 0. The decisions, as made

Recorded verbatim in effect, because three of them changed what gets built and one of them
changed what does not.

### E3 — Separation of duties: **maker-checker by default**

Institutional treasury accounts default to maker-checker. **A proposer cannot approve their own
transaction.** Higher-risk transactions require configurable additional approvers and stronger
quorum policies. Single-owner exceptions must be explicit and must not silently weaken
institutional policies. Policy changes must not allow a single actor to reduce their own
controls.

→ T3 below is resolved. Schema and the `weakens()` rule: `PHASE-C-SCHEMA-AND-MIGRATION.md` §4.

### E4 — Fee flexibility: **not in the initial institutional release**

Approval binds the **exact** transaction — inputs, outputs, amounts, fees and change. Any
material change requires fresh approval. Fee flexibility stays a documented future capability.

→ V1 below drops from HIGH to not-applicable. `intentBinding` is always `strict`.

### E7 — Tenant isolation: **all 40 authenticated routes, both directions**

A route inventory and reusable test harness covering reads, writes, exports, nested resources,
approvals and administrative actions. A user from organisation B must never access or modify
organisation A's data by changing an identifier, request parameter or resource relationship.
Both positive authorisation and negative isolation cases.

→ M3 becomes a hard requirement. `PHASE-C-ROUTE-ISOLATION-MATRIX.md`.

### E8 — Removed approver: **revocation is immediate**

Immediate effect for new and pending authorisation. Invalidate that member's outstanding
approvals on pending proposals and recalculate the valid quorum. **Never lower a threshold
silently to preserve a proposal.** If valid quorum is lost, require fresh approval. Preserve
historical evidence of earlier approvals but distinguish their historical validity from current
authority to sign.

→ T5 below is resolved, and it is the decision with the sharpest constraint: the evidence is
append-only, so "invalidate" cannot mean "amend". `PHASE-C-SCHEMA-AND-MIGRATION.md` §5.

---

## 1. What is being decided

| | Tenant isolation | Authorization V3 |
|---|---|---|
| Changes the database | yes, extensively | no |
| Changes what the browser signs | no | yes |
| Changes custody | **no** | **no** |
| Reversible after deployment | partly — see R4 | **no** — see R9 |
| Blocks the other | **yes** — V3 may need an organisation id | no |
| Size | large: every query, every route | **small**, now that `fee-flexible` is deferred (E4) |

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

### T3 — Separation of duties — **DECIDED (E3)**, and the residual risk moved

Maker-checker is the institutional default: a proposer cannot approve their own transaction.
That settles what to build. What it does **not** settle, and where the risk now lives, is the
two places a default like this gets undone in practice:

**The permissive value must never be reachable by omission.** A descriptor missing
`selfApproval` must be *rejected*, not defaulted — a field that falls back to `'permitted'` when
absent is a maker-checker control that disappears whenever somebody forgets it. The structural
check enforces presence.

**The single-owner exception must not become a route to weakening an institutional policy.**
Existing one-person vaults are migrated with `selfApproval: 'permitted'` because otherwise they
could never spend their own money — correct, and required to be explicit. The risk is that the
exception travels: an organisation that starts `single_owner` and later becomes institutional
must not carry the permission with it. `PHASE-C-SCHEMA-AND-MIGRATION.md` §4 answers this by
exempting policy *weakening* from the self-approval permission entirely, whatever the policy
says.

The third part of E3 — a policy change must not let one actor reduce their own controls —
required making "weaken" a decidable function rather than a judgement. Seven conditions, §4 of
the schema document. W7 is the non-obvious one: removing approvers until the pool is smaller
than a rule's threshold does not lower the threshold, it makes that tier unspendable.

### T4 — Backfilling one organisation per user is the irreversible part — MEDIUM

Steps 1–3 are additive and can be rolled back. The moment step 4 lands on even one route, the
application reads a column the old code does not write, and rolling back means rolling back the
deployment, not the schema.

**What reduces it:** steps 1–3 deployed and left running for a release before step 4 begins, so
the backfill is proven under real traffic while nothing depends on it.

### T5 — A removed member's pending approval — **DECIDED (E8)**, and harder than it reads

The decision is that revocation takes effect immediately, outstanding approvals are invalidated,
the quorum is recalculated, the threshold is never lowered to preserve a proposal, and historical
evidence is kept but distinguished from current authority to sign.

What the system does *today*, for contrast: `operations.required` is a snapshot column,
`approvalsOf` joins `approvals` to `users` and not to `members`, and `applyPolicy` prunes the
roster without touching proposals in flight. So a stale approval currently keeps counting. That
was defensible — removing a signer is itself palm-approved, and the approval was granted by a
then-current member — but nobody chose it, and E8 now chooses otherwise.

**The constraint that makes this the hardest of the four: the evidence log is append-only, so
"invalidate" cannot mean "amend".** The entry saying a person approved something is permanent and
remains true. What changes is whether it counts. So the two facts are stored in different places
with different mutability:

| | Where | Can change? |
|---|---|---|
| **Historical validity** — they did approve, then | `evidence` entry | **never** |
| **Current authority** — it counts now | `approvals.invalidated_at` + live role | yes |

`historicallyValid` is never false. If a thing is in the evidence log it happened, and the log
does not acquire a way to say otherwise.

The residual risks: a cached quorum on any route that computed one before the revocation landed
(matrix case N7), and the temptation to lower `required` to rescue a proposal that can no longer
reach it. `operations.required` is therefore **never written to** after the proposal is raised —
§5 of the schema document states it as an invariant rather than a convention.

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

Now finalised as nine schema versions and four code phases in
`PHASE-C-SCHEMA-AND-MIGRATION.md` §7. What each one requires to be called done:

| | Requirement | Status |
|---|---|---|
| M1 | v19–v27 and code phases 1–4 run in order, each deployable alone | **design complete** |
| M2 | v19–v24 run one full release before code phase 2 begins | not started |
| M3 | Both directions per route, all 40 authenticated routes; negative test written **first** and observed to fail | **matrix complete**, tests not written |
| M4 | `organisation_id` NOT NULL only after nothing writes null (v25) | not started |
| M5 | Every existing vault becomes a one-person organisation whose behaviour is **unchanged** | not started |
| M6 | Existing evidence entries keep `scope = null` and are **never** backfilled | enforced by the append-only trigger |
| M7 | Roles backfill to `owner` + `approver`, then narrow deliberately | not started |
| M8 | Migration idempotent and versioned under the existing advisory lock | pattern established, at v18 |
| M9 | The 211-test suite stays green at every step, with no test weakened | baseline established |
| M10 | Testnet4 only; no network gains the ability to send | holds today, re-asserted in §11 |
| **M11** | `organisation_id` denormalised **and** guarded by a composite FK, so a child cannot claim another tenant | **VERIFIED in PGlite** |
| **M12** | The two append-only tables derive their organisation; no column, because backfilling one is impossible | **VERIFIED in PGlite** |
| **M13** | Isolation matrix run on a **migrated v18 database with existing rows**, not only a fresh one | not started |
| **M14** | Rollback rehearsed: migrate forward, roll back to v18 with old code, matrix still passes | not started |
| **M15** | `ctx.org` derived at the single choke point; ATTACK 21 forbids a handler reading a tenant from a request | not started |

**M3 and M13 are the two that decide whether this is finished or merely working.** Forty routes
× two directions is the bulk of the work; M13 is the half-page that proves it holds for data that
existed before the migration, which a fresh-database test cannot show because every row in it was
created afterwards.

M11 and M12 were promoted from "approach" to "requirement" because both were tested against the
engine rather than assumed — see §2 and §2's last subsection of the schema document. M11 in
particular converts cross-tenant *corruption* from a discipline problem into a database-level
impossibility.

---

## 4. Authorization V3 — implementation risks

### V1 — `fee-flexible` — **NOT BEING BUILT (E4)**, and the risk goes with it

`intentBinding: 'fee-flexible'` was the only part of V3 that changed what a signature
*authorises*: the server would become free to construct a transaction the approver never saw,
within a fee ceiling. The ceiling was what made it safe, and the ceiling was the whole risk — a
missing, defaulted, unbounded or server-chosen one turns "flexible on the fee" into "authorised
to send an unbounded amount to miners".

E4 defers it. **Approval binds the exact transaction: inputs, outputs, amounts, fee and change.
Any material change requires fresh approval.** `intentBinding` is always `strict`, which is V2's
existing behaviour, so V3 reduces to V2 plus two readable fields and carries essentially none of
this risk.

Two consequences worth being honest about, since this is a deferral rather than a rejection:

- **A stuck transaction cannot be fee-bumped without a fresh palm.** That is the cost of the
  decision, it is a real operational cost for a treasury, and it is the right trade for a first
  institutional release.
- **The field stays in the design, unimplemented.** `intentBinding` is written and validated as
  `'strict'` only; a record carrying any other value is refused rather than ignored. A field that
  silently accepted an unimplemented mode would be worse than no field.

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
| N6 | `intentBinding` is `strict`, and any other value is **refused** rather than ignored | **DECIDED (E4)** — fee-flexible deferred |
| N7 | V3 is not signed until the organisation identifier question is answered (T/§6) | **blocked on Phase C** |
| N8 | No V3 record may assert `biometricVerified` or a measurement without attestation | structural check exists for V2, extends to V3 |
| **N9** | The policy descriptor is the one in `PHASE-C-SCHEMA-AND-MIGRATION.md` §4, and `policies.digest` is taken over exactly those bytes | design complete |

**N4 and N7 are the two that still block.** N7 is the reason this document puts tenancy first.

N4 gained a deadline from the schema work rather than from the V3 work: `policies.digest` is
written from v22, which is **before** any V3 record is signed. So the descriptor's canonical form
is frozen by the first migrated policy row, not by the first receipt. If the serialisation is
wrong at v22, every digest written between then and the discovery is wrong, and the rows are
immutable. The round-trip test N4 asks for therefore has to land with v22.

That is not a hypothetical class of bug here: the previous phase fixed a `canonicalJson` defect
in which an absent field hashed one way when signed and another after a database round trip.

---

## 6. What neither design changes

Stated explicitly because a large migration is where invariants quietly go.

- **Custody.** Keys stay in the owner's browser. An organisation is a policy and membership
  boundary, not a custodian, and does not get a key.
- **Testnet4 only.** No network gains the ability to send.
- **One phrase per browser.** A person in several organisations still has one recovery phrase.
- **The evidence chain.** No committed entry changes, for any reason.
- **The server cannot sign.** Not an authorisation, not a checkpoint. `ATTACK 17` enforces it,
  and `ATTACK 21` joins it for tenant context.
- **No scanner, no PAD, no measured biometric entropy.** Unchanged by either design.
  `sensorEvidence: 'none'` stays a recorded value rather than an omission.
- **No terminal and no protected signing boundary exist.** Neither design creates one, and
  nothing in Phase C may describe one as existing. Signing happens in browser JavaScript, which
  remains the dominant limitation of the whole system.
- **Approval binds the exact transaction** (E4) — inputs, outputs, amounts, fee and change.
- **Scope stays within institutional Bitcoin treasury management on testnet4.** No other chain
  gains the ability to send, and fee-flexible approval is not built.

---

## 7. Entry conditions for Phase C

| | Condition | Met |
|---|---|---|
| E1 | Tenant isolation design reviewed and accepted | **MET** |
| E2 | Authorization V3 design reviewed and accepted | **MET** |
| E3 | Separation of duties decided (T3) | **MET** — maker-checker by default, §0 |
| E4 | Fee flexibility decided (N6) | **MET** — deferred, `strict` only, §0 |
| E5 | Test baseline green | **MET** — 211 tests, 211 pass |
| E6 | Evidence layer durable, externally anchorable, independently verifiable | **MET** — `CHECKPOINTING.md` |
| E7 | Cross-tenant test scope decided (M3) | **MET** — all 40 routes, both directions, §0 |
| E8 | Fate of a removed approver's pending approval decided (T5) | **MET** — immediate revocation, §0 |
| **E9** | Schema and migration sequence finalised before coding | **MET** — `PHASE-C-SCHEMA-AND-MIGRATION.md` |
| **E10** | Route inventory and isolation matrix exist | **MET** — `PHASE-C-ROUTE-ISOLATION-MATRIX.md` |

**All entry conditions are met. Phase C is ready to implement and has not been started.**

Two things the decisions did not settle, carried forward rather than silently resolved:

- **N4's deadline moved earlier.** The policy descriptor's canonical form is frozen by v22, not
  by the first V3 receipt, because `policies.digest` is written at v22 and those rows are
  immutable. The round-trip test has to land with that migration.
- **N7 still blocks V3 itself.** Whether a V3 record needs an organisation identifier is
  answerable only once tenancy exists. Tenancy first, V3 after — unchanged, and now with a
  reason that is settled rather than assumed.
