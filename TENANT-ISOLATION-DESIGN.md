# Tenant isolation — the model Phase C has to implement

**Design only. The organisation migration is deliberately not started.**

Today the model is one user, one wallet, and nothing is scoped to anything. This is what has to
change, and — more importantly — what has to stay true while it changes.

---

## 1. The shape

```
  ORGANISATION ───────┬──────────────┬───────────────┬──────────────┐
    id, name          │              │               │              │
    created_at        │              │               │              │
                      ▼              ▼               ▼              ▼
                 MEMBERSHIP     TREASURY        POLICY         BENEFICIARY
                  user_id        ACCOUNT         version        label
                  role           asset           rules          address
                  added_by       network         effective      verified_at
                      │          wallet ref          │              │
                      │              │               │              │
                      └──────┬───────┴───────┬───────┘              │
                             ▼               ▼                      │
                          SIGNER          PROPOSAL ◄────────────────┘
                        user_id           account ref
                        key_index         intent
                        public_key        plan
                        enrolled_at       policy version ref
                             │            state
                             └──────┬─────────┘
                                    ▼
                               APPROVAL
                              proposal ref
                              approver ref
                              decision ref
                                    │
                                    ▼
                            EVIDENCE  (scope = organisation id)
```

### The entities, and what each one owns

| Entity | Belongs to | Key fact |
|---|---|---|
| **Organisation** | nothing | the isolation boundary. Every other row below reaches it by exactly one path. |
| **Membership** | organisation + user | a user may belong to several organisations with a different role in each. |
| **Treasury account** | organisation | one asset, one network, one wallet. An organisation has many. |
| **Policy** | organisation, applied to accounts | **versioned and immutable**; a change writes a new version. |
| **Signer** | organisation + user, enrolled per account | the public key; the private half never leaves the owner's browser. |
| **Beneficiary** | organisation | a label for an address. The label never substitutes for the address. |
| **Proposal** | treasury account | names the policy *version* in force when it was raised. |
| **Approval** | proposal + approver | one palm decision settles one approval. |
| **Evidence** | organisation (via `scope`) | append-only; see §4. |

---

## 2. The isolation rules

These are the ones that get broken in practice, so they are stated as rules rather than left
implicit in a schema diagram.

**R1 — One path to the organisation.** Every scoped row reaches its organisation by exactly one
foreign-key path. Two paths mean two answers to "whose is this?", and eventually they disagree.

**R2 — The organisation is never taken from the request.** It is derived from the authenticated
session's membership, server-side. A client-supplied organisation identifier is an input to be
checked against membership, never a source of authority. This is the single most common
multi-tenant failure and it is a one-line mistake.

**R3 — Every query is scoped at the query, not after it.** `WHERE organisation_id = $1` in the
statement, not a filter applied to results in JavaScript. A missing scope then returns nothing
rather than everything.

**R4 — An identifier is not an authorisation.** Knowing a proposal id must not grant access to
it. Every read of a scoped object re-checks membership. Guessable identifiers are not the
defence; the check is.

**R5 — A role is checked server-side on every route.** Not in the page, not once at login.

**R6 — Separation of duties is a policy, not a convention.** Whether a proposer may approve
their own proposal is a per-organisation setting. A single-person treasury needs it permitted;
an institutional one needs it refused. **Neither is a safe default to hardcode**, which is why
it is a policy field. Today a proposer can always approve their own proposal — correct for a
personal wallet, unacceptable for an institution, and currently not even expressible.

**R7 — An administrator cannot bypass a quorum.** Changing a policy, adding a signer or removing
an approver is itself palm-approved at the strongest quorum the *current* policy requires. An
admin who could edit the rules to lower them has no quorum at all. The existing
`requiredToChange` already implements this for the single-wallet case and generalises directly.

---

## 3. Roles

| Role | May | May not |
|---|---|---|
| **Organisation Owner** | everything below, plus membership and role changes | bypass a quorum |
| **Treasury Administrator** | accounts, policies, beneficiaries, signer enrolment | approve a payment unless also an Approver |
| **Treasury Operator** | raise proposals, cancel their own | approve |
| **Approver** | approve or reject | raise a proposal, unless also an Operator |
| **Auditor** | read everything including evidence, export bundles | change anything, approve anything |
| **Read Only Viewer** | read balances, accounts, history | read evidence exports, change anything, approve |

Two notes that matter more than the table:

**Approver is not implied by any other role.** An Owner who should be able to approve is
explicitly also an Approver. Making approval implicit in administration is how separation of
duties quietly disappears.

**Auditor reads evidence; Viewer does not.** An evidence bundle carries approver identifiers and
policy descriptors. That is appropriate for an auditor and more than a viewer needs.

---

## 4. Evidence under tenancy

The `scope` column exists today and is always null. This is what it is for, and the rules are
different from every other table because evidence is append-only.

**Existing entries stay null and are never backfilled.** Rewriting a committed entry to add a
scope would change its hash and break the chain — which is the chain working correctly. Entries
written before organisations existed belong to the single implicit tenant, and that is a fact
about history, not a gap to be tidied.

**One chain, or one per organisation?** One chain per deployment, with `scope` on each entry.

- A single chain means a cross-tenant ordering exists, which an incident investigation wants.
- Per-organisation chains would need per-organisation genesis entries, heads and checkpoints,
  and the `prev_hash` uniqueness constraint that orders concurrent writers would have to become
  `UNIQUE (scope, prev_hash)` — workable, but it buys isolation of a log nobody reads across
  tenants anyway.
- The cost of one chain: **an export scoped to one organisation is a slice**, so it cannot be
  checked back to the genesis. The bundle already handles this — `complete: false` — and the
  verifier already adjusts. The entries of other tenants are not disclosed; the chain simply
  cannot be walked past them.

**Checkpoints are per vault and stay per vault.** They are signed by a vault's attestation key,
and an organisation has several vaults. So an organisation has several checkpoint series, each
covering the whole log up to a point. That is fine and arguably better: several independent
commitments to the same history, each requiring a different key to forge.

**Scoped exports must not leak a neighbour's entry.** A slice filtered by `scope` returns only
that organisation's entries, and the gaps in `prev_hash` continuity are visible and expected.
A verifier told `complete: false` reports the slice as consistent without needing the
intervening entries — and therefore without being given them.

---

## 5. Migration order

The order matters because each step must leave the system working.

1. **Organisation and membership tables.** Nothing reads them yet.
2. **Backfill one organisation per existing user**, owning their existing wallet, with that user
   as Owner and Approver. Every current user becomes a one-person organisation that behaves
   exactly as it does today.
3. **Add `organisation_id` to the scoped tables, nullable.** Populate from the backfill. Still
   nothing reads it.
4. **Add the scope to every query**, one route at a time, with a test per route proving a
   neighbour's row is not returned. This is the long step and the one where the bugs are.
5. **Make `organisation_id` NOT NULL** once nothing writes a null.
6. **Introduce roles**, defaulting every existing member to Owner + Approver so behaviour does
   not change, then narrow deliberately.
7. **Make separation of duties expressible** (R6), defaulting to permitted so single-person
   treasuries keep working.
8. **Set `scope` on new evidence entries.** Not before: an entry written with a scope the
   queries do not yet use is a half-migration recorded permanently in an append-only table.

Step 8 last is the point of ordering this way.

---

## 6. What this must not break

- **Testnet4 only**, and no network gains the ability to send.
- **The custody model.** Keys stay in the owner's browser; an organisation does not get a key.
  An organisation is a policy and membership boundary, not a custodian.
- **One phrase per browser.** A person in three organisations still has one recovery phrase and
  derives a per-vault signing key from it, as `m/48'/1'/0'/2'/0/{index}` already does.
- **The evidence chain.** No committed entry changes, for any reason.
- **The receipt formats.** V1 and V2 keep verifying. If V3 lands first it carries `subject` and
  `accountId` and may need an organisation identifier; see `AUTHORIZATION-V3-DESIGN.md` §6.

## 7. Tests Phase C needs before it can be called done

Not a wish list — these are the specific failures that multi-tenant systems ship with:

1. Read another organisation's wallet, proposal, policy, beneficiary, signer, evidence — each
   refused, each its own test.
2. Supply another organisation's id in a request body while authenticated elsewhere. Refused.
3. A proposal id from organisation A used on organisation B's route. Refused.
4. An Operator attempting to approve. Refused.
5. An Approver attempting to raise a proposal. Refused.
6. An Administrator attempting to lower a policy without the current quorum. Refused.
7. A proposer approving their own proposal — permitted or refused **according to the policy**,
   tested both ways.
8. A user removed from an organisation mid-proposal: their pending approval no longer counts.
9. An evidence export scoped to one organisation containing no other organisation's entries,
   and still verifying as a slice.
10. A role change taking effect without re-login.
