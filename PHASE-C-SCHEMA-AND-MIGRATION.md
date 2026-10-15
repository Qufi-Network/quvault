# Phase C — finalised schema and migration sequence

**v19–v24 are implemented.** §12 records where the build departed from the plan below and why.

The later stages — scoping authenticated routes, assigning evidence scope, roles, revocation and
Authorization V3 — are **not started**.

The four decisions are made (`PHASE-C-DESIGN-REVIEW.md` §7). This document turns them into a
schema, a migration order, and the semantics that have to hold at every step — including the
ones that are physically impossible in this database and therefore had to be designed around
rather than planned for.

Three claims below were verified against the engine rather than assumed. They are marked
**VERIFIED** where they appear.

---

## 1. The conflation to break

Today the tenant key **is a user id**. Every tenant-owned table hangs off `wallet_user_id`,
which is the owner's row in `users`:

```
users.id ──┬── wallets.user_id            (PRIMARY KEY)
           ├── accounts.wallet_user_id
           ├── operations.wallet_user_id
           ├── invites.wallet_user_id
           ├── members.wallet_user_id
           ├── evidence_checkpoints.wallet_user_id
           └── evidence_anchors.wallet_user_id
```

That is a consistent single path, which is why this migration is tractable at all. It is also
the thing Phase C must break: **an organisation has to be able to outlive, and exceed, any one
user.** A treasury whose identity is its founder's account cannot survive that person leaving,
and cannot hold two owners.

So `organisations.id` is its own value, generated, never a user id. The backfill gives every
existing vault an organisation of its own, and from then on the two are separate things.

---

## 2. The scoping decision, and why it is not the obvious one

Two rules from `TENANT-ISOLATION-DESIGN.md` pull in opposite directions:

- **R1** — one foreign-key path to the organisation, so there is only ever one answer to "whose
  is this?"
- **R3** — scope at the query (`WHERE organisation_id = $1`), so a *missed* scope returns
  nothing rather than everything.

Satisfying R1 alone means putting `organisation_id` on `wallets` only and reaching it by join
everywhere else. Then a forgotten join returns **every tenant's rows** — the exact failure R3
exists to prevent. Satisfying R3 alone means copying `organisation_id` onto every table, and two
copies of a fact eventually disagree.

**Both, via a composite foreign key.** The column is denormalised onto every tenant-owned table,
and a composite FK makes disagreement impossible *in the database*:

```sql
-- the parent key the children point at
ALTER TABLE wallets ADD CONSTRAINT wallets_org_user UNIQUE (organisation_id, user_id);

-- the child cannot claim an organisation its parent is not in
ALTER TABLE accounts ADD CONSTRAINT accounts_in_org
  FOREIGN KEY (organisation_id, wallet_user_id) REFERENCES wallets (organisation_id, user_id);
```

**VERIFIED** against PGlite, which is what the tests and local runs use:

| Attempt | Result |
|---|---|
| child row agreeing with its parent | accepted |
| child row naming **another** organisation | **refused** — `violates foreign key constraint` |
| moving an existing child to another organisation | **refused** |
| child row with a NULL organisation | accepted — so the additive migration step works |

This is the single most valuable line in the schema. Cross-tenant *corruption* stops being a
discipline problem and becomes a database-level impossibility; a cross-tenant *read* is still a
code problem, which is what §7's route matrix is for.

### Where the column goes, and where it deliberately does not

| Table | `organisation_id` | Why |
|---|---|---|
| `wallets` | **column**, FK to `organisations` | the root of each tenant tree |
| `accounts` | **column** + composite FK | queried directly, must scope directly |
| `operations` | **column** + composite FK | same, and the IDOR surface (§7) |
| `approvals` | **column** + composite FK via `operations` | same |
| `invites` | **column** + composite FK | same |
| `members` | **column** + composite FK | the signer roster — see the naming note below |
| `policies` | **column**, FK to `organisations` | new table, §5 |
| `evidence` | **`scope`, already exists** | append-only; §6 |
| `evidence_checkpoints` | **none — derived** | append-only; see below |
| `evidence_anchors` | **none — derived** | append-only; see below |

### The two tables that cannot have the column

`evidence_checkpoints` and `evidence_anchors` carry `BEFORE UPDATE OR DELETE` triggers. A column
can be added to them — DDL does not fire a row trigger — but **it can never be populated for
existing rows.** **VERIFIED:**

```
ADD COLUMN on an append-only table: allowed
INSERT:                             allowed
BACKFILL UPDATE:                    REFUSED — the evidence log is append only: UPDATE is not permitted
```

A column there would be permanently half-populated: null for every historical row, set for every
new one, with no way to close the gap short of dropping the guarantee the table exists to
provide. **Half-populated is worse than absent**, because a query that scopes on it silently
omits history.

So both tables reach their organisation by derivation through `wallet_user_id → wallets`. This
also happens to be R1-correct: one path, no second copy to disagree.

### A naming hazard worth one line

`members` already exists and means **the per-vault signer roster**. The organisation membership
table in `TENANT-ISOLATION-DESIGN.md` §1 is a different thing. It is called `org_members` here,
not `memberships`, so that nobody reads one for the other at a glance. `members` keeps its
current meaning and gains a scope like any other tenant-owned table.

---

## 3. The schema

New tables first, then the columns added to existing ones.

```sql
CREATE TABLE IF NOT EXISTS organisations (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  -- 'institutional' defaults to maker-checker; 'single_owner' is the explicit exception (§4).
  kind            TEXT NOT NULL DEFAULT 'institutional'
                    CHECK (kind IN ('institutional', 'single_owner')),
  created_at      BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_members (
  organisation_id TEXT NOT NULL REFERENCES organisations(id),
  user_id         TEXT NOT NULL REFERENCES users(id),
  label           TEXT NOT NULL,
  added_by        TEXT REFERENCES users(id),
  added_at        BIGINT NOT NULL,
  -- E8: revocation is a timestamp, not a deletion. A deleted membership loses the audit of who
  -- was ever in the organisation, and the evidence log would then be the only record of a
  -- person the operational tables deny ever existed.
  revoked_at      BIGINT,
  revoked_by      TEXT REFERENCES users(id),
  PRIMARY KEY (organisation_id, user_id)
);
CREATE INDEX IF NOT EXISTS org_members_user ON org_members (user_id)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS org_member_roles (
  organisation_id TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN
                    ('owner', 'administrator', 'operator', 'approver', 'auditor', 'viewer')),
  granted_by      TEXT REFERENCES users(id),
  granted_at      BIGINT NOT NULL,
  PRIMARY KEY (organisation_id, user_id, role),
  -- One path to the organisation: a role reaches it THROUGH the membership, never beside it.
  -- Revoking the membership therefore cannot leave a role behind.
  FOREIGN KEY (organisation_id, user_id)
    REFERENCES org_members (organisation_id, user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policies (
  id               TEXT PRIMARY KEY,
  organisation_id  TEXT NOT NULL REFERENCES organisations(id),
  wallet_user_id   TEXT NOT NULL REFERENCES users(id),
  network          TEXT NOT NULL,
  version          INTEGER NOT NULL CHECK (version >= 1),
  -- Canonical JSON. `digest` is taken over exactly these bytes and is what a V3 receipt names,
  -- so the serialisation is frozen the moment the first row is written (PHASE-C-DESIGN-REVIEW V2).
  descriptor       TEXT NOT NULL,
  digest           TEXT NOT NULL,
  effective_from   BIGINT NOT NULL,
  created_by       TEXT NOT NULL REFERENCES users(id),
  -- The palm-approved operation that produced this version. Null only for the backfilled v1,
  -- which records the policy that was already in force before policies were versioned.
  operation_id     TEXT REFERENCES operations(id),
  UNIQUE (organisation_id, wallet_user_id, network, version)
  -- An earlier draft of this document also had UNIQUE (organisation_id, digest, version). It is
  -- WRONG and was not built: two accounts in one organisation with identical rules produce an
  -- identical descriptor and therefore an identical digest, which is correct and must be
  -- allowed. The constraint would have rejected the second account. See §12.
);
-- Versions are immutable: a change writes a new row. Same guard as the evidence tables.
CREATE TRIGGER policies_are_immutable
  BEFORE UPDATE OR DELETE ON policies
  FOR EACH ROW EXECUTE FUNCTION quvault_evidence_is_append_only();
```

Columns on existing tables:

```sql
-- the root
ALTER TABLE wallets  ADD COLUMN IF NOT EXISTS organisation_id TEXT REFERENCES organisations(id);
ALTER TABLE wallets  ADD CONSTRAINT wallets_org_user UNIQUE (organisation_id, user_id);

-- the children, each with the composite FK of §2
ALTER TABLE accounts   ADD COLUMN IF NOT EXISTS organisation_id TEXT;
ALTER TABLE operations ADD COLUMN IF NOT EXISTS organisation_id TEXT;
ALTER TABLE invites    ADD COLUMN IF NOT EXISTS organisation_id TEXT;
ALTER TABLE members    ADD COLUMN IF NOT EXISTS organisation_id TEXT;
ALTER TABLE approvals  ADD COLUMN IF NOT EXISTS organisation_id TEXT;

-- a proposal names the policy VERSION in force when it was raised, not the policy
ALTER TABLE operations ADD COLUMN IF NOT EXISTS policy_id TEXT REFERENCES policies(id);

-- E8: an approval that no longer counts, without losing that it happened
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS invalidated_at     BIGINT;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS invalidated_by     TEXT REFERENCES users(id);
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS invalidated_reason TEXT
  CHECK (invalidated_reason IS NULL OR invalidated_reason IN
    ('approver_revoked', 'role_removed', 'policy_changed', 'plan_changed'));
```

Indexes, added **with** the columns and not after, so that step 4's rewritten queries never
land on a table scan:

```sql
CREATE INDEX IF NOT EXISTS wallets_org    ON wallets    (organisation_id);
CREATE INDEX IF NOT EXISTS accounts_org   ON accounts   (organisation_id, network);
CREATE INDEX IF NOT EXISTS operations_org ON operations (organisation_id, status);
CREATE INDEX IF NOT EXISTS invites_org    ON invites    (organisation_id, status);
CREATE INDEX IF NOT EXISTS approvals_org  ON approvals  (organisation_id, operation_id);
CREATE INDEX IF NOT EXISTS members_org    ON members    (organisation_id);
CREATE INDEX IF NOT EXISTS policies_live  ON policies   (organisation_id, wallet_user_id, network, version DESC);
```

---

## 4. Maker-checker (E3)

> Institutional treasury accounts default to maker-checker. A proposer cannot approve their own
> transaction. Higher-risk transactions require configurable additional approvers and stronger
> quorum. Single-owner exceptions must be explicit and must not silently weaken institutional
> policies. Policy changes must not allow a single actor to reduce their own controls.

### The policy descriptor

The frozen canonical shape. `digest` is taken over this and a V3 receipt names it, so the field
set and its serialisation cannot change afterwards without invalidating every receipt.

```js
{
  v: 1,
  // The amount ladder, as today, with two additions per step.
  rules: [
    { upToSats: 100_000,  approvals: 1, requiredRoles: ['approver'] },
    { upToSats: 5_000_000, approvals: 2, requiredRoles: ['approver'] },
    { upToSats: null,     approvals: 3, requiredRoles: ['approver', 'owner'] },
  ],
  // E3, and the field that must never acquire a permissive default.
  selfApproval: 'forbidden',          // 'forbidden' | 'permitted'
  // What a receipt needs to re-derive the requirement with no database.
  approverCount: 4,
  // The quorum required to change THIS policy. Generalises the existing `requiredToChange`.
  requiredToChange: 3,
}
```

`requiredRoles` is how "higher-risk transactions require additional approvers" is expressed
beyond a count: the top step can demand that one of the approvals comes from an Owner, not
merely that three people scanned.

### The default, and the explicit exception

A new organisation is `kind = 'institutional'` and gets `selfApproval: 'forbidden'`. There is no
code path that produces a permissive value by omission — a descriptor without the field is
rejected by the structural check, not defaulted.

A one-person treasury genuinely needs self-approval, or it can never spend. That is the
**explicit exception**: `kind = 'single_owner'` **and** `selfApproval: 'permitted'`, both stated,
both recorded in evidence at the moment they are set, and both visible in the V3 receipt's
`policyDescriptor`. A reader of a receipt can therefore see that a payment was self-approved and
that the policy permitted it — which is the difference between a disclosed exception and a
silent one.

### Which changes "weaken", and the rule that follows

"Policy changes must not allow a single actor to reduce their own controls" needs *weaken* to be
a decidable function, not a judgement. `weakens(from, to)` is true if any of:

| | Change |
|---|---|
| W1 | any rule's `approvals` is lower |
| W2 | any rule's `upToSats` is higher — the same approval count now covers more money |
| W3 | a rule is removed, so a larger amount falls to a weaker step |
| W4 | `selfApproval` goes `forbidden` → `permitted` |
| W5 | `requiredToChange` is lower |
| W6 | a `requiredRoles` entry is removed from any rule |
| W7 | `approverCount` falls below any rule's `approvals` — the quorum became unreachable |

**A weakening change can never be self-approved, whatever `selfApproval` says, and needs the
quorum `requiredToChange` of the policy being replaced — never of the one replacing it.**

Both halves matter. Taking the *new* policy's `requiredToChange` would let a single actor
propose a policy that requires one approval and approve it themselves, which is the whole attack.
And exempting policy changes from the self-approval override is what stops a `single_owner`
organisation being used as a route to weaken an institutional one it later becomes.

W7 is the one that is easy to omit and is a real foot-gun: removing approvers until the pool is
smaller than a rule's threshold does not lower the threshold, it makes that tier unspendable.
Refusing it at proposal time is better than discovering it at payment time.

---

## 5. Revocation (E8)

> Revocation takes immediate effect for new and pending authorization. Invalidate that member's
> outstanding approvals on pending proposals and recalculate the valid quorum. Never lower a
> threshold silently. If valid quorum is lost, require fresh approval. Preserve historical
> evidence of earlier approvals but distinguish their historical validity from current authority
> to sign.

This is the decision with the sharpest constraint, because **the evidence is append-only and the
operational state is not.** The approval evidence cannot be amended; it says a person approved,
and that remains true. What has to change is whether it still counts.

So the two are separated explicitly:

| | Where it lives | Can it change? | What it means |
|---|---|---|---|
| **Historical validity** | `evidence` entry | **never** | this person did approve this, then |
| **Current authority** | `approvals.invalidated_at` + live role | yes | whether it counts toward the quorum now |

### What revocation does, in one transaction

1. `org_members.revoked_at` is set. The row is kept — deleting it would erase who was ever in the
   organisation, leaving the evidence log as the only record of a person the operational tables
   deny existed.
2. `ON DELETE CASCADE` on `org_member_roles` is *not* what ends their authority — the roles stay
   and the **revocation timestamp** is what every check reads. Keeping the roles preserves what
   they were able to do, which an investigation wants.
3. Every `approvals` row for that user on an operation still `collecting` or `running` gets
   `invalidated_at`, `invalidated_by`, `invalidated_reason = 'approver_revoked'`.
4. The quorum of each affected operation is recalculated (below).
5. Evidence is appended: `MEMBER_REVOKED`, one `APPROVAL_INVALIDATED` per approval, and
   `QUORUM_RECALCULATED` per affected operation — all with `required: true`, because a revocation
   that was not durably recorded did not happen.

### Recalculating a quorum

An approval counts toward a quorum only if **all** of:

- `status = 'approved'`
- `invalidated_at IS NULL`
- the approver's `org_members.revoked_at IS NULL`
- the approver currently holds a role the operation's policy version requires
- the approver is not the proposer, unless that policy version permits self-approval

```
valid = count of approvals meeting all five
required = operations.required            -- the snapshot, never recomputed downward
if valid < required:  status -> 'collecting', fresh approval needed
```

**`operations.required` is never written to.** The threshold is a snapshot of the policy version
in force when the proposal was raised, and lowering it to preserve a proposal is precisely the
silent weakening the decision forbids. If the valid count falls below it, the proposal reopens
and needs a fresh palm. A proposal that cannot reach its threshold any more stays open until it
expires, and the status says why.

### What a reader sees

The operation view, and the evidence payload, carry both facts side by side rather than one
derived number:

```js
approvals: [
  { approver: 'u-a', approvedAt: …, historicallyValid: true, currentlyCounts: true },
  { approver: 'u-b', approvedAt: …, historicallyValid: true, currentlyCounts: false,
    reason: 'approver_revoked', revokedAt: … },
]
quorum: { required: 2, valid: 1, satisfied: false, note: 'fresh approval required' }
```

`historicallyValid` is never false. If a thing is in the evidence log it happened; the log does
not acquire a way to say otherwise.

---

## 6. Evidence scope, and the one ordering that cannot be undone

> Ensure scope is assigned correctly before appending immutable evidence.

`evidence.scope` exists and is null on every row. Three rules, and the third is the whole reason
the sequence in §7 is ordered as it is.

1. **Existing entries keep `scope = null` and are never backfilled.** Not a tidiness gap — a fact
   about history. Entries written before organisations existed belong to the single implicit
   tenant. Changing one would change its hash and break the chain, which is the chain working.
2. **A new entry's scope is derived from `ctx.org`** (§8), the same server-side value every query
   is scoped by. Never from a request.
3. **No entry is written with a scope until every query reads the scope.** An entry carrying a
   scope the queries do not yet use is a half-finished migration recorded permanently in an
   append-only table. This is the only step in the sequence whose mistake no later migration can
   repair, which is why it is last.

One chain per deployment, with `scope` per entry, as `TENANT-ISOLATION-DESIGN.md` §4 settles. A
scoped export is therefore a slice and reports `complete: false`; the verifier already handles
that, and a neighbour's entries are neither disclosed nor needed.

Checkpoints stay per vault and are unaffected: an organisation with several vaults has several
checkpoint series, each an independent commitment to the same log.

---

## 7. The migration sequence

Nine schema versions and four code phases, interleaved. Every schema step is idempotent and runs
under the existing `pg_advisory_xact_lock(4970)`. Every step leaves the system working.

### Schema steps

| v | What | Reads it yet? |
|---|---|---|
| **v19** | `organisations`, `org_members`, `org_member_roles` | nothing |
| **v20** | backfill: one organisation per existing vault owner, that user as `owner` + `approver` | nothing |
| **v21** | `organisation_id` on the six tables, **nullable**, with the composite FKs and the indexes of §3; populate from v20 | nothing |
| **v22** | `policies`; backfill each account's current policy as version 1 | nothing |
| **v23** | `operations.policy_id`; populate pending operations with the version 1 row | nothing |
| **v24** | `approvals` invalidation columns | nothing |
| **v25** | `organisation_id` → **NOT NULL**, once code phase 2 proves nothing writes null | yes |
| **v26** | `org_members.revoked_at` checks wired into the quorum queries | yes |
| **v27** | evidence `scope` set on new entries — **after** code phase 3 | yes |

v20's backfill is the step that decides what existing users experience:

```
organisation per existing wallet owner
  kind          = 'single_owner'         -- what they actually are
  descriptor    = their current policy, with selfApproval: 'permitted'
  roles         = owner + approver
```

`selfApproval: 'permitted'` is correct and required here: today a one-person vault's owner
approves their own withdrawals, and migrating them to `forbidden` would leave them unable to
spend their own money. Per E3 it is written **explicitly**, with `kind = 'single_owner'`, and an
evidence entry records that the exception was taken at migration — not inherited silently. New
organisations created after v19 default to `institutional` and `forbidden`.

### Code phases

| | What | Gate to the next |
|---|---|---|
| **1** | `ctx.org` derived server-side at the single choke point (§8). Nothing uses it. | the grep test of §8 passes |
| **2** | Scope every query, route by route, with the isolation test per route written **first** | all 40 routes covered, §9 |
| **3** | Roles, maker-checker (§4), revocation (§5) | the matrix in §9 passes both ways |
| **4** | Evidence scope on new entries (v27) | — |

Phase 2 is the bulk of the work and the one with the bugs. The order within it is fixed: the test
that organisation B cannot reach organisation A's row is written before the scope is added, and
is observed to fail first. A test written afterwards passes against a route with no scope at all.

### Deploy spacing

**v19–v24 ship and run for one full release before code phase 2 begins.** They are additive,
nothing reads them, and the backfill gets proven under real traffic while nothing depends on it.
This is the cheapest risk reduction available and it costs one release.

---

## 8. Tenant context, and the one place it comes from

> Tenant context must be established server-side from authenticated membership, never trusted
> from a client-supplied organization ID alone.

There is already exactly one place where a request becomes a user — `src/app.js:3077`:

```js
const user = route.auth ? await requireUser(cookies) : null;
const ctx = { params: route.params, cookies, body: …, user };
```

`ctx.org` is derived there, from `org_members` for that `user.id`, and nowhere else. The design
follows from one property of that line: **`ctx` is the only thing a handler receives.** So if
`ctx.org` is the only organisation a handler can see, a handler *cannot* take one from a request
even by mistake.

- A client-supplied organisation identifier is **an input to be checked against membership**, and
  only on the routes where a user legitimately selects among several. It is never a source of
  authority. Where it appears, the check is `ctx.org` membership first, then equality.
- A handler must not read an organisation from `body` or `params`. That is enforceable rather
  than aspirational, and it belongs in `test/attacks.test.js` next to ATTACK 17, which already
  greps server code for forbidden imports and calls:

  > **ATTACK 21 — no handler takes its tenant from the request.** Scan every handler for
  > `body.organisation*`, `body.org*`, `params.organisation*`; the only permitted reads are
  > inside the membership check itself.

- A revoked membership yields **no** organisation: `ctx.org` is null and the route refuses. This
  is how E8's "immediate effect" reaches every route at once instead of route by route.
- A user in several organisations selects one; the selection is validated against membership and
  held in the session, not in each request.

---

## 9. Cross-tenant testing (E7)

Full inventory and matrix: **`PHASE-C-ROUTE-ISOLATION-MATRIX.md`**. Summary of what it commits to:

- **40 authenticated routes**, every one covered. 11 take an identifier from the path, 12 from
  the body, 17 from the session alone.
- **Both directions per route.** A positive case (A reaches its own) and a negative case (B,
  authenticated, cannot reach A's) — because a negative-only test passes against a route that
  returns nothing to anybody, and a positive-only test passes against a route with no scope.
- **Reads, writes, exports, nested resources, approvals and administrative actions**, as E7
  requires, which is what the matrix's category column is for.
- **Before and after migration.** The same matrix runs against a v18 database migrated forward
  with real rows in it, so isolation is proven on **existing** records and not only on rows
  created after the migration.
- **Failure recovery and rollback.** §10.

---

## 10. Rollback constraints

What can be undone, and the doors that only open one way.

| Step | Reversible? | What rollback means |
|---|---|---|
| v19–v24 | **yes** | additive; nothing reads them. Dropping the tables and columns restores v18 exactly. |
| code phase 1 | yes | `ctx.org` is computed and unused |
| code phase 2 | **deployment only** | the schema stays; the *code* rolls back. Once a route reads `organisation_id`, the old code is what you return to, not the old schema. |
| v25 (NOT NULL) | yes, mechanically | but only while no code depends on it |
| code phase 3 | **deployment only** | roles and revocation are behavioural, not structural |
| **v27 (evidence scope)** | **NO** | a scope written into an append-only entry is permanent. §6.3. |
| **v20 backfill** | partly | the organisations can be dropped, but any evidence written *about* the backfill cannot be |

Two one-way doors, and they are the reason for the ordering:

1. **Evidence scope (v27).** No migration repairs a wrongly scoped immutable entry. It goes last,
   after every query reads the scope.
2. **Evidence about the migration.** The `CUSTODY_MIGRATION`-style entries recording that an
   organisation was created and that a single-owner exception was taken are themselves permanent.
   That is correct — a migration that left no trace would be worse — but it means the backfill's
   *decisions* are final even where its *rows* are not.

Rollback rehearsal is part of the phase, not a contingency: the matrix in §9 runs against a
database that has been migrated forward **and** against one rolled back to v18 with the old code,
proving that a rollback leaves a working single-tenant system rather than a half-scoped one.

---

## 11. What Phase C must not break

Re-asserted because a migration this size is where invariants quietly go.

- **Testnet4 only.** No network gains the ability to send.
- **Custody.** Keys stay in the owner's browser. An organisation is a policy and membership
  boundary, **not a custodian**, and does not get a key.
- **One phrase per browser.** A person in three organisations still has one recovery phrase and
  derives a per-vault signing key from it.
- **The evidence chain.** No committed entry changes, for any reason.
- **The server cannot sign** — not an authorisation, not a checkpoint. ATTACK 17 enforces it and
  ATTACK 21 joins it.
- **No scanner, no PAD, no measured biometric entropy.** `sensorEvidence: 'none'` stays a
  recorded value. Nothing in Phase C creates a protected signing boundary or a terminal, and
  nothing may describe one as existing.
- **Browser JavaScript signing remains the dominant limitation.** Tenancy does not touch it.
- **No fee-flexible authorization** (E4). `intentBinding` is `strict`: approval binds the exact
  transaction — inputs, outputs, amounts, fee and change — and any material change requires a
  fresh approval.
- **Nothing certified.** No audit, no certification, no regulatory approval has occurred.

---

## 12. What was built, and where it departed from this document

v19–v24 are implemented. Six things turned out differently from the plan above, five of them
because the engine or the data said so. Each is a correction to this document, not a shortcut.

### D1 — `wallets.organisation_id` moved from v21 to v20

The plan had v20 create organisations and v21 link them. Nothing connects the two: at v21 the
only way to find a wallet's organisation would be "the one whose sole owner-roled member is this
wallet's user" — unambiguous only because v20 had just created them — or a provenance column
that a later reader could mistake for an authorisation path. Creating and linking in one step
removes the question. The five child tables follow in v21 exactly as planned.

### D2 — `organisations.kind` has three values, not two

`CHECK (kind IN ('institutional', 'single_owner', 'migrated'))`.

Every migrated organisation keeps `selfApproval: 'permitted'`, because today a proposer can
approve their own proposal in any vault and writing `'forbidden'` would not tighten a control —
it would make existing vaults **unspendable**. Three members with a three-approval rule cannot
reach three if the proposer is excluded.

But a grandfathered three-member vault is not `single_owner`. Reusing that value to avoid adding
one would put a false statement in the data, and the decision requires exceptions to be explicit.
So a one-member vault migrates as `single_owner` and a multi-member one as `migrated`, and
"which organisations still have grandfathered self-approval?" is one query.

### D3 — `UNIQUE (organisation_id, digest, version)` was wrong and is not built

Two accounts in one organisation with identical rules produce an identical descriptor and
therefore an identical digest. That is correct behaviour; the constraint would have rejected the
second account. Verified: a two-account fixture with matching ladders digests to
`i41xDbKssBxSvEgHi3IQhiaqNsz0QlL--5hwBtpcgTs` for both.

### D4 — `ADD CONSTRAINT` has no `IF NOT EXISTS`, so every one is guarded

The whole schema array re-runs on every cold start, and the second run would fail on a
constraint the first added. Each is wrapped in a `DO` block that checks `pg_constraint` first —
the `addConstraint` helper in `src/db.js`. Without it the migration is a one-shot, which for a
serverless deployment that cold-starts constantly means permanently broken.

### D5 — the migration runner now accepts computed steps

Two backfills cannot be a SQL string: v20 needs a fresh random id per wallet plus three
dependent inserts that all name it, and v22 has to compute a SHA-256 over a canonical JSON
descriptor and **refuse to write at all** if that serialisation has moved. `migrate()` therefore
runs a step that is either SQL text or a function `q => …`, in the same transaction under the
same advisory lock. Everything expressible as one set-based statement still is one — a function
step is for computation, never for looping over work the database could do itself.

`backfillPolicyVersions` is exported and takes its guard as a parameter, so the claim "the guard
runs before anything is persisted" is a test rather than a comment.

### D6 — rollback has a forced order, and partial un-linking is impossible

Two properties found by trying to write the rollback test the obvious way, both consequences of
the composite-key web and both better than what the plan assumed:

- **A linked wallet cannot be un-linked while any child references its organisation.** Each
  child refuses in turn — `accounts`, then `members`, and so on — so there is no order in which
  a wallet quietly loses its tenant while rows still point at it. §10's "partly reversible" is
  therefore stronger than stated: the half-scoped state is not reachable.
- **Dropping the tenancy must go in reverse dependency order.** `DROP TABLE policies` is refused
  while `operations.policy_id` references it, and `operations` cannot lose `organisation_id`
  while `approvals_in_org` points at it. Taking it out of order fails loudly instead of leaving
  a half-scoped database. `CASCADE` would paper over both refusals and is the wrong instinct: it
  drops whatever else has come to depend on the object by then, unseen.

The working order, verified end to end:

```
approvals.organisation_id                        -- child of operations
accounts | operations | invites | members .organisation_id   -- children of wallets
operations.policy_id                             -- references policies
DROP TABLE policies
approvals.invalidated_at | _by | _reason
wallets.organisation_id                          -- the root
DROP TABLE org_member_roles, org_members, organisations
```

### And one thing the plan got right that is worth restating

A `policies` row **cannot be deleted**, so rollback of v22 is never by `DELETE` — only by
`DROP TABLE`. §10's one-way doors stand: the immutable rows are immutable, and once a later
stage writes evidence *about* the migration, no rollback reaches it.

---

## 13. Unresolved after v19–v24

Carried into the next stage rather than left implicit. None of these blocks the additive stage;
all of them are things the scoping stage must not assume away.

### U1 — the composite key prevents disagreement, not absence

`organisation_id` is nullable everywhere in this stage, so a child row with **no** organisation
is accepted even under a scoped parent. Verified, and asserted as a test so nobody over-reads
the guarantee. v25's NOT NULL is what closes it, and v25 is not in this stage.

The consequence for the next stage: a query of the form `WHERE organisation_id = $1` will not
return an unscoped row, which is the safe direction — but code that assumes every row has a
tenant will be wrong until v25.

### U2 — the backfill runs at boot, so a wallet created afterwards has no organisation until the next start

The v20 step runs during migration, which happens on a cold start. A vault created after that
start is unscoped until the process restarts. Harmless now — nothing reads the column — and
proven to be picked up on the next start.

**The scoping stage must create the organisation at wallet-creation time** rather than leaning on
the backfill, which exists for rows that predate tenancy and for nothing else.

### U3 — the migration writes nothing to the evidence log, including the single-owner exception

The plan said v20 should record in evidence that a single-owner exception had been taken. It does
not, deliberately: an entry written now would carry `scope = null` **permanently**, before the
scope mechanism exists, and §6.3 is explicit that an entry cannot gain one later. Writing
evidence from a step that re-runs on every cold start would also put a new failure mode in the
boot path.

So the exception is explicit in the **data** — `organisations.kind` and
`descriptor.selfApproval` — and absent from the **evidence log**. That satisfies "explicit, not
silent"; it does not yet satisfy "recorded in evidence". The entry belongs to the stage that
assigns evidence scope, and should be written then with the scope it deserves.

### U4 — the descriptor serialisation is frozen from the first real deployment

The guard protects against the form moving unnoticed. It cannot protect against the form having
been *wrong* to begin with. Once a production `policies` row exists, adding a field to the
descriptor means a version 2 descriptor, not an edit — the rows are immutable and the digest is
over exactly these bytes.

Anything the descriptor will need later — per-rule time locks, beneficiary allowlists, velocity
limits — is cheaper to decide before the first deployment runs this migration than after.

### U5 — `requiredRoles: ['approver']` on every backfilled rule is a forward-looking default

No role is enforced yet, so the field is inert. When roles land, every migrated rule will require
the `approver` role — which the backfill granted to every existing signer, so the two agree
today. They can drift: a signer added later without the role, or a role narrowed deliberately,
could make a tier unreachable. That is W7 of §4 and the check belongs with the role work.

### U6 — verified in PGlite, not against Postgres

Everything above was tested against PGlite, which is what the suite and local runs use. The
hosted deployment is Neon Postgres. Composite foreign keys, partial indexes, `DO` blocks and
`information_schema` are all core Postgres and the risk is low, but **it is not zero and has not
been run against Neon.**

Closing it needs one command against a real database, and no credential for one was supplied:

```bash
QUVAULT_DATABASE_URL="postgres://…" node --test test/organisations.test.js
```

Until that runs, treat "the constraints hold" as proven on PGlite and expected on Postgres.
