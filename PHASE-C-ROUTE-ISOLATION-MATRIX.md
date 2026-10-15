# Phase C — route inventory and cross-tenant isolation matrix

**E7. Design only; no tests written yet.** This is the inventory the decision asked for, and the
shape of the harness that covers it.

The inventory below was **extracted from `src/app.js`, not written by hand.** That matters: a
hand-written route list is out of date the day a route is added, and a route missing from this
table is a route with no isolation test. Phase C regenerates it and fails if the count moves.

---

## 1. Why both directions, always

E7 asks for "both positive authorization and negative isolation cases". The reason is that each
kind of test passes on its own against a differently broken route:

| Test | Passes against |
|---|---|
| negative only — *B cannot read A's row* | a route that returns nothing to **anybody** |
| positive only — *A can read A's row* | a route with **no scope at all** |

So every route gets both, and the negative test is written **first and observed to fail** before
the scope is added. A negative test written after the fix passes without ever having been
capable of failing.

---

## 2. The harness

One helper, two organisations, used by every case. The point is that adding a route means adding
one line, not writing a test from scratch — which is what makes 40 routes tractable rather than
a thing that gets half-done.

```js
// test/tenancy.js
export async function twoOrganisations(env) {
  // Organisation A: a funded vault, an account, a pending proposal, an invite, an approval,
  // a policy version and some evidence. Everything a route could reach for.
  const a = await org(env, { label: 'A', fund: true, propose: true, invite: true });
  // Organisation B: a different owner, its own vault, and no relationship to A whatsoever.
  const b = await org(env, { label: 'B', fund: true });
  return { a, b };
}

/**
 * The whole matrix in one shape.
 *
 * `reach` is called with the identifiers of the organisation under test. Called with A's own
 * identifiers while authenticated as A it must succeed; called with A's identifiers while
 * authenticated as B it must be refused — and refused with 403 or 404, never 200 with an
 * empty body, because an empty 200 is indistinguishable from a route that is simply broken.
 */
export async function isolates(t, { a, b }, { name, category, reach, mutates = false }) { … }
```

Three properties the harness enforces, each of which is a real failure mode:

1. **A refusal is a status, not an empty body.** `200 {}` passes a naive assertion and leaks
   nothing today, but it means the route found no row rather than refused — and the next
   change makes it find one.
2. **A mutating route is checked for having done nothing.** For `mutates: true` cases it is not
   enough that B got a 403: A's row is re-read afterwards and must be byte-identical. A write
   that was refused *after* taking effect is still a cross-tenant write.
3. **Evidence is checked for not having grown.** A refused cross-tenant attempt may append a
   `RATE_LIMITED` or security entry, but it must never append an entry **scoped to A** while
   acting as B. A permanent, append-only mis-scoped entry is the one error §6.3 of
   `PHASE-C-SCHEMA-AND-MIGRATION.md` says cannot be repaired.

---

## 3. The inventory — 40 authenticated routes

44 routes in total. The four unauthenticated ones are `GET /api/config`, `POST /api/login/start`,
`POST /api/login/finish` and `POST /api/logout`; they hold no tenant data and are out of scope
for isolation, though login remains in scope for `ctx.org` derivation (§8 of the schema
document).

**Identifier from** is where a caller can name a resource, and therefore where a cross-tenant
attempt comes from: 11 from the path, 12 from the body, 17 from the session alone.

| # | Method | Path | Handler | Identifier from | Category | Rate |
|---|---|---|---|---|---|---|
| 1 | GET | `/api/price` | `getPrice` | session only | none — no tenant data | upstream |
| 2 | GET | `/api/scanner` | `getScanner` | session only | none — no tenant data | — |
| 3 | GET | `/api/evidence` | `exportAllEvidence` | session only | **export** | upstream |
| 4 | POST | `/api/operations/:id/reconcile` | `reconcileOne` | **path** | **write** | unlock |
| 5 | GET | `/api/evidence/checkpoint` | `checkpointTarget` | session only | read | upstream |
| 6 | POST | `/api/evidence/checkpoint` | `registerCheckpoint` | session only | write | write |
| 7 | GET | `/api/evidence/anchor` | `anchorStatus` | session only | read | upstream |
| 8 | POST | `/api/evidence/anchor/retry` | `retryAnchors` | session only | write | write |
| 9 | GET | `/api/operations/:id/evidence` | `exportEvidence` | **path** | **export** | upstream |
| 10 | GET | `/api/random` | `getRandom` | session only | none — no tenant data | upstream |
| 11 | GET | `/api/wallet` | `getWallet` | session only | read | — |
| 12 | POST | `/api/wallet/approval` | `requestWallet` | session only | approval | palm |
| 13 | POST | `/api/wallet/register` | `registerWallet` | body: `operationId` | **write** | write |
| 14 | POST | `/api/wallet/upgrade/approval` | `requestUpgrade` | session only | approval | palm |
| 15 | POST | `/api/wallet/upgrade` | `completeUpgrade` | body: `operationId` | **write** | unlock |
| 16 | POST | `/api/invites/approval` | `requestInvite` | body: `network` | approval | palm |
| 17 | GET | `/api/invites` | `listInvites` | session only | read | — |
| 18 | POST | `/api/invites/cancel` | `cancelInvite` | body: `code` | **admin** | write |
| 19 | POST | `/api/invites/join` | `requestJoin` | body: `code` | **admin** | palm |
| 20 | POST | `/api/accounts/lock` | `requestLock` | session only | write | spend |
| 21 | POST | `/api/signing-key/approval` | `requestSigningKey` | session only | approval | palm |
| 22 | POST | `/api/signing-key/register` | `registerSigningKey` | body: `operationId` | **write** | write |
| 23 | POST | `/api/attestation/approval` | `requestAttestationRotation` | session only | approval | palm |
| 24 | POST | `/api/attestation/register` | `registerAttestationKey` | body: `operationId` | **admin** | write |
| 25 | POST | `/api/wallet/reset/approval` | `requestReset` | session only | approval | palm |
| 26 | POST | `/api/wallet/reset` | `completeReset` | body: `operationId` | **admin** | unlock |
| 27 | POST | `/api/operations/:id/unlock` | `unlockFor` | **path** | **write** | unlock |
| 28 | POST | `/api/operations/:id/broadcast` | `broadcastSigned` | **path** | **write** | unlock |
| 29 | POST | `/api/operations/:id/signature` | `addSignature` | **path** | **write** | unlock |
| 30 | GET | `/api/operations/:id/receipt` | `getReceipt` | **path** | **export** | — |
| 31 | POST | `/api/policy` | `requestPolicy` | body: `network` | **admin** | palm |
| 32 | POST | `/api/recovery` | `requestRecovery` | session only | **admin** | palm |
| 33 | POST | `/api/accounts/approval` | `requestAccount` | body: `network` | approval | palm |
| 34 | POST | `/api/accounts/register` | `registerAccount` | body: `operationId` | **write** | write |
| 35 | POST | `/api/withdrawals` | `requestWithdrawal` | body: `to` | **write** | spend |
| 36 | POST | `/api/operations/:id/approval` | `joinOperation` | **path** | **approval** | palm |
| 37 | POST | `/api/operations/:id/cancel` | `cancelOperation` | **path** | **write** | write |
| 38 | GET | `/api/approvals/:id` | `readApproval` | **path** | read | — |
| 39 | POST | `/api/approvals/:id/palm` | `startPalm` | **path** | **approval** | palm |
| 40 | POST | `/api/approvals/:id/cancel` | `cancelApproval` | **path** | **write** | write |

Four routes carry no tenant data at all (1, 2, 10, and 5 in part). They still get a case,
asserting that they **remain** tenant-free — because the cheapest way for a leak to appear is for
somebody to add a convenience field to a route nobody is watching.

---

## 4. The nine highest-risk routes

Not a ranking of likelihood — a ranking of what a successful cross-tenant call achieves.

| Route | What B gains if it works |
|---|---|
| 27 `operations/:id/unlock` | **the unlock secret for A's pending operation** — the single worst outcome on this list |
| 28 `operations/:id/broadcast` | pushes A's signed transaction, or a substituted one, to the network |
| 29 `operations/:id/signature` | adds a signature to A's multisig proposal |
| 36 `operations/:id/approval` | **joins A's quorum** — a cross-tenant approver defeats maker-checker entirely |
| 39 `approvals/:id/palm` | starts a palm request against A's approval |
| 26 `wallet/reset` | destroys A's vault |
| 32 `recovery` | begins A's recovery ceremony |
| 3, 9, 30 evidence and receipts | reads A's history, approvers and policy descriptors |
| 31 `policy` | **rewrites A's controls** — and by §4 of the schema document, cannot be self-approved |

Routes 27, 36 and 31 are the ones to write first. They are also the ones where a positive-only
test is most dangerously reassuring.

---

## 5. Cases beyond one-route-one-check

E7 names "nested resources and resource relationships". Those are not covered by calling each
route with a foreign id, because the interesting failures are in the *joins*.

| | Case | What it catches |
|---|---|---|
| N1 | an `approvals` id from A used on a route that reaches it **through** `operations` | a scope applied to the outer table and not the join |
| N2 | an `operationId` in the **body** of a register route (13, 15, 22, 24, 34) belonging to A | the body identifier being trusted after the session was checked |
| N3 | an invite `code` from A redeemed by a member of B (19) | an invite is a deliberate cross-user object, so its tenant check is the only thing that bounds it |
| N4 | A's `network` named by B (16, 31, 33) | a composite key `(wallet_user_id, network)` scoped on only one half |
| N5 | B proposes, A's member approves | the approver's membership being checked against the wrong organisation |
| N6 | a user genuinely in **both** A and B | the one case where "refuse everything foreign" is wrong, and the session's selected organisation is what decides |
| N7 | A's member revoked, then their approval replayed | E8's immediate effect reaching a route that cached a quorum |
| N8 | B supplies `organisation_id: A` in a body that has no such field | silent acceptance of an unexpected field; ATTACK 21 |

N6 is the case that makes this harder than "reject anything from another tenant". A person
legitimately in two organisations must reach both, one at a time, and the boundary is their
selected organisation — not their membership set. A harness that only ever uses single-tenant
users never exercises it.

---

## 6. Before and after the migration

E7 asks for isolation proven "including existing records". Three runs of the same matrix:

| Run | Database | Proves |
|---|---|---|
| **R1** | fresh, created at the final schema | the steady state |
| **R2** | a **v18** database with real rows, migrated forward | isolation on **existing** records, which R1 cannot show because every row in it was created after the migration |
| **R3** | migrated forward, then rolled back to v18 with the old code | a rollback leaves a working single-tenant system, not a half-scoped one |

R2 is the one that matters and the one that is easy to skip. `test/migrate.test.js` already
replays every historical schema version with rows in the tables, so the mechanism exists; Phase C
extends it to run the isolation matrix at the end of the replay rather than only checking that the
schema lands.

---

## 7. What this does not cover

- **Rate limiting is per user, not per organisation.** B exhausting a limit does not reach A's
  data, but on a shared deployment it can affect A's service. Out of scope for isolation testing
  and worth stating rather than discovering.
- **Timing and existence.** A 404 for a foreign id and a 404 for a nonexistent id are the same
  response, which is correct, but response *timing* may still distinguish them. Not addressed.
- **The evidence chain is shared.** One chain per deployment means a scoped export is a slice.
  Tenants do not learn each other's entries, but they do share an ordering, and a count of
  entries is a weak signal about another tenant's activity. Accepted, per
  `TENANT-ISOLATION-DESIGN.md` §4.
- **No scanner.** Palm routes exercise the Veyns approval path, not a sensor. Nothing here tests
  biometric isolation because nothing here measures a biometric.
