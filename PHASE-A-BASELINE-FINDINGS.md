# Phase A — baseline and security findings

Established by inspection and execution against the actual repository, not from the existing
security documents. Where a document and the code disagreed, the code wins and the disagreement
is recorded.

## Baseline

| | |
|---|---|
| Working copy | `C:\veynswallet` (a second copy exists at `C:\ubtc\quvault`; both are kept deliberately) |
| Commit | `de6e8ea` |
| Working tree | clean — no uncommitted user work was at risk, nothing was overwritten |
| Branch | `main`, 2 commits ahead of `origin/veyns-wallet` (`2ed5f4c` rate limiting, `de6e8ea` docs) |
| Node | v24.17.0; `engines: 24.x` |
| Package | `quvault` 0.1.0 |
| Scripts | `start test keygen check build:client audit inventory` |
| Runtime dependencies | 9 — `@noble/{curves,hashes,post-quantum}`, `@scure/{base,bip32,bip39,btc-signer}`, `pg`, `qrcode` |
| `npm run audit` | **passes**, exit 0 |
| `npm run check` | **not a usable gate** — it is a live-deployment probe and fails `ECONNREFUSED` without a running target |
| Tables | `users sessions login_nonces wallets members operations approvals accounts invites rate_limits` |

The test suite result is recorded in the Phase A test section below. Note that this machine has
accumulated background Node processes from earlier work in this session, and a full run that
normally takes ~80 seconds has taken up to 20 minutes; that is environmental, not a code defect.

## What the specification asks for that does not exist at all

These are **absent features**, not defects. They are the bulk of the institutional product and
belong to Phases C–E. Listed first because their absence frames every finding below.

| Requirement | Status | Evidence |
|---|---|---|
| Organizations (§4.1) | **NOT IMPLEMENTED** | zero occurrences of `organisation`/`organization`/`org_id`/`tenant` across `src/`, `public/app.js`, `client/`. The model is one user → one wallet. |
| Roles and RBAC (§9) | **NOT IMPLEMENTED** | the entire role model is `members.is_owner BOOLEAN`. No role table, no permission checks by role. |
| Proposal state machine (§3.2) | **NOT IMPLEMENTED** | `operations.status` has 5 values (`collecting running done failed cancelled`) against the 12 required, and there is **no transition validation anywhere** — zero matches for any transition guard. |
| Append-only evidence store (§4.5) | **NOT IMPLEMENTED** | no events/audit table exists. Security events from Phase 1.5 go to a log sink and are **not persisted at all**. |
| Beneficiary directory (§4.3) | **NOT IMPLEMENTED** | zero occurrences of beneficiary/payee/address book. |
| Confirmation tracking (§7) | **NOT IMPLEMENTED** | the only height data is per-UTXO in `src/chain.js:51`. No per-transaction confirmation state is stored or polled. |
| Separation of duties (§9) | **NOT IMPLEMENTED** | nothing excludes a proposer from approving their own proposal. Correct and necessary for a one-person wallet; unacceptable for institutional use, and currently not even expressible. |
| Idempotency on proposal creation (§10) | **NOT IMPLEMENTED** | idempotency keys exist only on the outbound Veyns approval request (`src/app.js:568`). |

## Findings, ranked by severity

Severity is judged against the institutional threat model in this specification, not against a
single-user testnet wallet.

---

### F1 — HIGH — No authorization receipt can establish the policy that governed the payment

**Files:** `src/authorization.js`, `src/app.js` (`expectedAuthorization`), `client/wallet.js`

§3.1 requires the authorization to cover the spend policy and policy version. §15 requires that
an independent verifier can determine the policy a transaction was authorized under.

The V1 receipt — the only receipt anything produces — carries exactly these fields:

```
v, vaultId, accountId, transactionHash, statementDigest, approvalMethod,
biometricVerified, approvals, approvedBy, decisionIds, approvedAt, keyEpoch
```

**No policy version. No policy digest. No threshold as a number** — `approvals` is the display
string `"1 of 1"`, which a verifier cannot check programmatically. No chain or network readable
from the record. No proposal identifier. No expiry.

A V2 record exists and does carry `policyVersion`. **It cannot be produced.** Phase 1 gated
`signAuthorizationV2` on scanner evidence where every check is an explicit `PASSED`, and the
only scanner provider in this build returns `NOT_AVAILABLE` to everything. So:

> V1 cannot prove the policy. V2 can, but nothing can emit it. **Today no receipt can prove the
> policy a payment was authorized under.**

This is a design error introduced in Phase 1 of this project: it conflated two orthogonal
concerns — *which rules governed this payment* and *what a biometric sensor measured* — and
gated the first on the second. Institutional policy binding does not require a scanner.

**Risk:** a completed payment's permanent evidence cannot answer "how many approvals were
required, and under what rules?" except by trusting mutable database rows — which §3.1
explicitly rejects.

---

### F2 — MEDIUM — The receipt verification shown to users is circular

**File:** `src/app.js`, `getReceipt`

```js
verified: verifyAuthorization(authorization, publicKey,
  { transactionHash: authorization.record.transactionHash })
```

The expected digest is read **out of the record being verified**. This proves the ML-DSA
signature is valid over the record; it does **not** prove the record is about the operation
being viewed. Any internally-consistent record would be reported as `verified`.

**Not currently exploitable:** `broadcastSigned` validates against `expectedAuthorization(op,
wallet)` before storing, so a stored authorization is genuinely bound to its operation. The
defect is that the verdict presented to a human proves materially less than it appears to, and
§3.1 requires independent validation *at every trust boundary* — this boundary does not perform
one.

---

### F3 — MEDIUM — Approval threshold is not independently verifiable from the evidence

**File:** `src/authorization.js`

`approvals: "2 of 3"` is a human-readable string. An independent verifier per §15 must
establish the required threshold and that it was met. It cannot parse intent from a label, and
`approvedBy` gives a count but not the requirement. Folded into F1's remedy.

---

### F4 — MEDIUM — Security events are not persisted, so there is no audit trail to export

**File:** `src/events.js`

Phase 1.5 added nine security events with an enforced field allowlist and value scrubbing —
that part is sound. But emission writes to `log.log` or an injected sink. **Nothing reaches the
database.** §4.5 requires an append-only, tamper-evident history and §15 requires exporting a
transaction's authorization history. Neither is possible: after a process restart the events are
gone.

---

### F5 — LOW — `npm run check` is presented as a gate but cannot run offline

It is a live-deployment probe requiring a reachable target, and fails `ECONNREFUSED` against
`localhost:4970`. Not a defect in the application; a defect in the release process if anyone
treats a green `check` as meaningful without a running deployment.

---

## Security invariants the existing code does enforce

Verified by reading the implementation, not the documents. These are to be **preserved**.

| Invariant | Where | Verified |
|---|---|---|
| A spend is bound to a canonical digest, re-derived by the signer | `src/canonical.js`, `client/wallet.js` `signPlan` | the browser recomputes and refuses on mismatch |
| The server cannot forge an approval receipt | `src/authorization.js` | ML-DSA-65 key derived from the owner's phrase; server holds only the public half |
| The server holds no spending key for a current wallet | `src/app.js` | one `openSealed` of `sealed_key`, migration-only, behind a separate absent `QUVAULT_LEGACY_SEED` |
| No new server-custody wallet can be created | `src/app.js` | the `insertWallet` query has **0 call sites** |
| A legacy wallet cannot spend | `requestWithdrawal`, `runOperation` | refused before approvals are collected |
| A forged operation row cannot release a legacy key | `assertSweepAuthorization` | digest recomputed, quorum recomputed from policy, every approval re-verified upstream with Veyns |
| One palm decision settles one approval | `approvals.proof_id UNIQUE`, `claimApproval` | atomic conditional update |
| An unlock is single-use and time-boxed | `unlockFor` | `markUnlocked`, `op.txid` check, `UNLOCK_SECONDS` |
| A transaction broadcasts once | `startRunning`, `finishOperation` | conditional updates; covered by tests |
| An approved plan is immutable | schema + queries | **verified: no query mutates `operations.payload` or `operations.details` after creation.** So §3.2's "invalidate approvals if a material field changes" is satisfied by there being no change path. |
| Rate limits are shared, not per-instance | `src/rate-limit.js`, `rate_limits` table | Postgres-backed, because in-memory is meaningless on serverless |
| No secret reaches an API response | tests | checked against the vault's *actual* key material, not a regex |

## Specification conflicts worth recording

- **§11 fail-open.** The limiter fails open by design. The specification permits this: *"Rate
  limiting must not replace authorization. Operations that release secrets… must retain their
  authorization safeguards when the rate limit store is unavailable."* They do — authorization is
  independent of the limiter. No change required; recorded because it looks like a conflict.
- **§8 multi-asset.** Ethereum, Tron, Solana and Stellar derive addresses from the same phrase
  and all carry `canSend: false`. This satisfies "do not fabricate spending support", but the UI
  does surface those accounts, so §8's "do not present a derived address as proof of operational
  support" needs a UI check in a later phase.
- **Brand/name split.** Package, database namespace and repository are `quvault`; the customer
  surface is `Veyns — Human Gated Security`. Matches §1. The README now states this.

## Phase B plan

Taking the two findings that are genuine defects in existing behaviour rather than absent
features, both in evidence integrity, both explicitly required by §3.1 and §15:

1. **F1 + F3** — make the receipt able to prove the policy and threshold. Decouple institutional
   binding from scanner evidence so a usable versioned record exists, without manufacturing
   biometric evidence.
2. **F2** — verify a receipt against the operation it belongs to, not against itself.

F4 (persisting the audit trail) is the natural Phase E item and is larger than a correction.

---

# Phase B — critical security corrections

Two findings addressed. Both are evidence-integrity defects in existing behaviour, not absent
features; the absent features remain for Phases C–E.

## F1 — the receipt can now establish its own policy

**Files:** `src/authorization.js`, `src/app.js`, `client/wallet.js`, `test/harness.js`

**What changed.** Version 2 of the authorisation record was restructured so that institutional
binding no longer depends on scanner evidence. It now always carries:

| Field | Why |
|---|---|
| `policyVersion` | the rules in force, as a digest |
| `threshold` | the requirement, as an **integer** — V1 carried `"1 of 1"`, which a verifier cannot check |
| `approvalCount` | the distinct approvers, counted |
| `proposalId` | the proposal it belongs to |
| `chain`, `network` | readable without recomputing the digest |
| `subject` | an opaque digest of the owner's identity, not the identity |
| `expiresAt` | when the authorisation stopped being usable |
| `verification` | what a sensor measured — `sensorEvidence: 'none'` in this build, **recorded rather than omitted** |

**Why it had to change rather than be added alongside.** The earlier V2 required scanner
evidence in which every check was an explicit PASS. The only provider in this build returns
`NOT_AVAILABLE` to everything, so V2 could never be emitted — and V1 could not carry a policy.
The net effect was that **no receipt could prove the policy at all.** That was a design error
from Phase 1 of this project: it coupled *which rules governed this payment* to *what a palm
sensor saw*, and those are independent. No V2 record had ever been produced, so nothing
historical was reinterpreted.

**The property that was preserved.** A record may never *claim* a measurement it does not have.
`checkV2` refuses a record that reports a pass while saying nothing was measured, that claims a
measurement without an attestation, capture, scanner class or passed verdicts, or whose evidence
is bound to another transaction. Saying "nothing was measured" must also be said consistently —
a record claiming `none` while carrying an attestation is refused.

**Produced, not merely possible.** `client/wallet.js` now signs V2 on the real browser path and
throws rather than falling back to V1 if the server omits a field — a silent downgrade would
turn a missing field into weaker evidence that still looked valid.

**V1 is not reinterpreted.** It still verifies. Every verification now returns a `proves` block
stating which questions the record can answer; for V1 `policy`, `threshold`, `chain` and
`proposal` are all `false`.

**A gap in the fix, found by its own test.** The first version of this change released the
policy version to the browser but did not verify the returned record carried the same one — so a
record naming `policy-of-my-choosing` was accepted. `expectedAuthorization` now derives its
expectations from `authorizationDescriptor`, the same function that tells the browser what it is
signing, so the statement and the check cannot drift apart.

## F2 — the receipt verdict is no longer circular

**File:** `src/app.js`, `getReceipt`

The expected digest was read out of the record being verified, which proved the signature was
valid over the record but not that the record was about the payment being viewed. It now
expects the digest from the **operation**, plus the statement digest, vault, proposal and
threshold. A correctly-signed record describing a different transaction is now reported
unverified; there is a test that inserts exactly that into the database and checks the verdict
flips.

## Tests

| | |
|---|---|
| Baseline | 166 pass, 0 fail (verified by execution, 458s) |
| Added | `test/evidence.test.js` — 5 tests, end to end through the API |
| Rewritten | 2 tests in `test/boundary.test.js` became 3 |
| Removed or weakened | **none** |

One rewritten test previously asserted *"a version 2 authorisation cannot be made, because
nothing can measure one"*. That property was deliberately removed — it was the defect — so the
test was replaced by one asserting the new behaviour, and the invariant that survives (a record
may not claim a measurement it does not have) is asserted in the forgery test that follows it.
Both are called out in the test file so the change is not silent.

## What this does not fix

- F4, persisting the audit trail, is unchanged: security events still reach only a log sink.
- No organizations, roles, proposal state machine, beneficiaries or confirmation tracking.
- The multisig per-signer receipt gap is unchanged: a quorum spend finished by co-signers still
  carries no receipt, because only the vault owner holds an attestation key.
- Browser JavaScript signing remains the dominant limitation.
