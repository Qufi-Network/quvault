# Phase 1.6 — production readiness gate

An audit and closure exercise. No feature development, no scanner work, no cryptography added.

**Commit at start:** `81886c8`
**Tests:** 157 passing, 0 failing (156 before; one added — see §Tests)
**Audit:** `npm run audit` exits 0
**Production database:** not supplied. `QUVAULT_ADMIN_DATABASE_URL` is unset in this
environment, so every production-dependent finding below is **BLOCKED**, not assumed.

---

## 1. Production legacy custody inventory

**BLOCKED — production database access not supplied.**

No production query was attempted and no production number appears anywhere in this document.

### Tooling review

`npm run inventory` runs one statement — `INVENTORY_SQL` in `src/legacy-inventory.js` — which
is the same query `test/legacy-closure.test.js` checks against a live database. A test against
a copy would prove nothing about the query the operator runs; this is why the SQL lives in a
module rather than inside the script.

Counts identified:

| Required by the brief | Reported | Notes |
|---|---|---|
| total wallets | `totals.wallets` | |
| client custody | `totals.custodyClient` | |
| server custody | `totals.custodyServer` | |
| active server custody | `totals.serverActive` | `sealed_key IS NOT NULL` |
| inactive server custody | `totals.serverInactive` | server custody, no sealed key — a halted migration |
| server custody **with balances** | `totals.serverWithBalances` = **`null`** | **Cannot be established from the database.** Coins are on the chain and this command does not talk to it. Reported as null rather than guessed. |
| server custody with pending operations | `totals.serverWithPendingOperations` | `collecting` or `running` |
| migration eligibility | `totals.migratableAutomatically` | active legacy rows with ≥1 member who can approve |
| migration exceptions | `totals.requiringManualRecovery` | active legacy rows with nobody who can approve |

### Safety review

The SELECT projects `user_id, address, custody, (sealed_key IS NOT NULL) AS holds_key,
created_at`, and three counts. **`holds_key` is a boolean, not the value** — no column
carrying key material is selected at all, so the command cannot print one even if it tried.

Verified it cannot output: private keys, mnemonics, `WALLET_SEED`, `QUVAULT_LEGACY_SEED`, or
decrypted wallet material. It does not read either seed variable.

Wallets are named `W-` + 12 hex characters of SHA-256 over the address: stable between runs,
not reversible. Full addresses only with `--addresses`.

It requires `QUVAULT_ADMIN_DATABASE_URL` and refuses a bare `DATABASE_URL` — deliberate, since
on a development machine that variable commonly belongs to a different project and would
produce a confident answer about the wrong database.

**Change made in this phase:** added `--help`, which §15 of the brief requires to be runnable.
It answers without a database, so the command and the meaning of its counts can be reviewed
before anyone points it at production.

### The exact command, once credentials exist

```bash
QUVAULT_ADMIN_DATABASE_URL="postgres://…" npm run inventory -- --json
```

Then, for condition 3 of the deletion gate, which needs the chain as well:

```bash
QUVAULT_ADMIN_DATABASE_URL="postgres://…" npm run inventory -- --addresses
```

and query each legacy address for confirmed and unconfirmed balances.

---

## 2. Legacy server signing closure

**READY WITH LIMITATION.** No normal request path can reach a legacy key. Only migration and
recovery tooling can, and only under four independent conditions.

### Every occurrence, classified

| Location | Occurrence | Class |
|---|---|---|
| `src/app.js:200` | `legacySeed = ''` option | MIGRATION (configuration) |
| `src/app.js:293, 300` | `legacyVault()` — refuses when unset | MIGRATION |
| `src/app.js:751–790` | `assertSweepAuthorization` | MIGRATION (the gate) |
| `src/app.js:792–830` | `sweepLegacyVault` | MIGRATION |
| `src/app.js:809` | `openSealed(wallet.sealed_key, legacyVault())` | MIGRATION — **the only full private key on the server** |
| `src/app.js:1739` | sweep call in `completeReset` → `POST /api/wallet/reset` | **RECOVERY** |
| `src/app.js:2003` | sweep call in `completeUpgrade` → `POST /api/wallet/upgrade` | MIGRATION |
| `src/app.js:63` | `insertWallet` query | **OBSOLETE** — called from nowhere |
| `src/app.js:1095, 1102, 1106, 1156` | `openSealed(…unlockSealed…, vault())` | NORMAL — unlock secrets, not keys |
| `src/app.js` ×8 | `CUSTODY.LEGACY` / `!== CUSTODY.BROWSER` branches | ADMINISTRATIVE — these are the refusals |
| `server.js:28`, `api/handler.js:38` | `legacySeed: env.QUVAULT_LEGACY_SEED \|\| ''` | MIGRATION (configuration) |
| `src/db.js:27, 93` | `sealed_key` column | MIGRATION (schema) |
| `test/harness.js:256, 264, 302, 307` | `legacyWallet`, `startWithMigration` | TEST |
| `test/legacy-closure.test.js`, `boundary.test.js`, `upgrade.test.js`, `reset.test.js` | legacy assertions | TEST |

**Worth stating plainly:** `src/app.js:1739` is a **recovery** path, not a migration path. It
is how an owner who does not want to migrate still gets their coins out. That distinction
matters for the deletion gate — deleting `sweepLegacyVault` removes the escape hatch, not just
the migration.

### Can a normal request reach the legacy signer?

**No.** Three independent refusals, each verified by test:

1. `requestWithdrawal` refuses a legacy wallet **before** any palm approvals are collected.
2. `runOperation` throws if anything else reaches the point of moving coins.
3. `broadcastPlan` — the general server-side spending function — was deleted in Phase 1.

And four conditions before line 809 executes, none of which is a database row:

1. `QUVAULT_LEGACY_SEED` configured (absent by default);
2. `actionDigest(statement, details) === op.digest`;
3. quorum recomputed from the policy, not read from `op.required`;
4. **every approval re-verified against Veyns upstream.**

`sweepLegacyVault` also cannot become a spending path by construction: no amount, no output
list, no externally supplied plan. It builds the plan from the chain immediately before
signing and can only send everything to one address.

**Target state reached for normal signing:**
`authorization → Signer → signing boundary → signature`.

---

## 3. Legacy deletion gate

See [LEGACY-CUSTODY-DELETION-GATE.md](LEGACY-CUSTODY-DELETION-GATE.md).

**BLOCKED.** One of ten conditions met. The four states are kept apart: nothing is at D
(deletable), because C (production data no longer requires it) is entirely unknown.

The gate proposes a **two-stage deletion** — code first, column later after a stated quiet
period — because dropping `sealed_key` is not reversible from the application, and restoring
a backup would roll back every wallet created since.

It also records a dependency easy to miss: **`QUVAULT_LEGACY_SEED` must be retained for as long
as any backup containing `sealed_key` exists**, or that backup is unreadable.

---

## 4. WALLET_SEED dependency map

See [WALLET-SEED-DEPENDENCY-MAP.md](WALLET-SEED-DEPENDENCY-MAP.md).

**READY WITH LIMITATION — the root is still required.**

The central distinction, which the brief asked for explicitly and which holds:

> `WALLET_SEED` protects an unlock secret and anchors an attestation root. **It is not, and has
> never been, the wallet's spending key.**

An unlock secret is one of two inputs to `HKDF(unlockSecret, salt, 'quvault device key v1')`.
The other is the AES-GCM blob in the owner's browser. The seed alone opens nothing.

| Class | Sites | Required by the final architecture? |
|---|---|---|
| SIGNING (indirect) | `unlockFor:1106`, `quorumUnlock:1156` | **Yes today** — every spend opens an unlock secret |
| AUTHORIZATION | **none** | It plays no part in authorising anything |
| ATTESTATION | `attestationOf:431`, `registerWallet:1203`, `registerAttestationKey:1832`, `completeUpgrade:2018` | Yes, but as an **HMAC key**, and separable onto a lower-privilege root |
| MIGRATION | `prepareUpgrade:652`, `unlockFor:1102`; and `legacyVault:300`, `sweep:809` under the **separate** legacy seed | Only until the legacy population is zero |
| TEST | 5 sites | n/a |
| CONFIGURATION | `getConfig:929` (a boolean), 2 entry points | Reveals nothing |

**Verified facts:**

- **Never used during login** — no `vault()`, `sealRoot` or `rootSealMatches` call appears in
  `loginStart`, `loginFinish`, `logout` or `requireUser`.
- No seed reaches the browser; no configuration endpoint reports one; no seed is written to a
  log. All three are tested.
- It lives for the process lifetime as a JavaScript string and **cannot be erased**.

**Fundamental or inherited?** Both, in different places. The attestation anchor is *inherited*
and separable. The unlock path is fundamental to the *current* design and not to the *target*
one — a palm-derived key-encryption capability displaces it — but removing it is a data
migration (re-wrapping every `unlock_sealed`) plus a capability that does not exist. It is not
a code change and must not be attempted as one.

---

## 5. Palm architecture boundary — nothing falsely implemented

Verified by execution, not by reading:

| Stage | Status | Evidence |
|---|---|---|
| NIR capture | **NOT IMPLEMENTED** | `capture()` throws `ScannerUnavailable`; `discover()` returns `[]` |
| Quality assessment | **NOT IMPLEMENTED** | no such concept in code |
| PAD | **NOT IMPLEMENTED** | `getPADResult()` → `NOT_AVAILABLE`, `performed: false` |
| Biometric feature extraction | **NOT IMPLEMENTED** | no such concept in code |
| Biometric verification | **NOT IMPLEMENTED** | `getBiometricResult()` → `NOT_AVAILABLE` |
| Fuzzy extraction | **NOT IMPLEMENTED** | deliberately deferred |
| Palm-derived key-encryption capability | **NOT IMPLEMENTED** | deliberately deferred |
| Scanner attestation | **NOT IMPLEMENTED** | `getAttestation()` → `NOT_AVAILABLE` |
| Hardware signing | **NOT IMPLEMENTED** | `IMPLEMENTED_ISOLATION` has one entry, and it is `none:browser-javascript` |

`SCANNER.PASSED` **is not returned anywhere in `src/scanner.js`** — verified by pattern search
over the module source, not by inspection. `/api/scanner` reports `available: false` and
`authorizationVersion: 1`.

The abstractions and documents are preparation. They are not evidence, and this document does
not treat them as evidence.

---

## 6. Portable wallet invariant

**READY.**

> A compatible scanner change must not create a different wallet identity for the same enrolled
> user.

The core wallet secret is derived from: browser CSPRNG + server randomness + ceremony jitter →
HKDF → BIP39 → BIP84. **No scanner serial number, USB device ID, sensor ID, scanner-specific
random seed or physical device identity is an input, because no scanner value is reachable
from the derivation at all.**

Enforced, with tests:

- `client/wallet.js` does not import `src/scanner.js`, and contains no scanner reference in
  code — asserted by a test that strips comments first.
- Restoring the same phrase twice, with different device records, unlock secrets and salts,
  yields the same address and the same public key.
- `assertProvider` refuses a provider exposing `deriveKey`, `unwrapKey`, `getKey`,
  `getPrivateKey`, `getSecret`, `getTemplate`, `getImage` or `getRawCapture`.

**Future attestation may establish "this is an approved scanner". It may not establish "this
scanner owns this wallet."** The trust anchor is a *class* of device, and a device identifier
may appear in an authorisation record as evidence about a capture — never in anything the
wallet key depends on.

*One precision:* scanner **constants** do reach the browser bundle, because
`src/authorization.js` imports `SCANNER` and `evidenceIsUsable` for dormant V2, and the wallet
module imports `authorization.js`. Nothing in key derivation consults a scanner, so the
invariant holds — but "no scanner code is in the bundle" would be false and is not claimed.

---

## 7. Secure signer readiness

**READY WITH LIMITATION.** Verified by execution:

| Requirement | Result |
|---|---|
| Private-key export impossible through the interface | `assertSigner` refuses `getPrivateKey`, `exportKey`, `exportPrivateKey`, `exportSeed`, `getSecretKey`, `getSecret`, `decryptWallet` — each confirmed to throw |
| Mnemonic export impossible | refuses `getMnemonic`, `mnemonic`, `getSeed`, `seed`, `reveal`, `dump` — confirmed |
| Arbitrary signing without authorization impossible | `signTransaction({})` and `signTransaction(undefined)` both reject |
| Exact transaction digest required | all 8 `AUTHORIZATION_FIELDS` must match, then the digest is recomputed from the plan |
| Authorization identity checked | `authorizationId`, `walletId`, `policyVersion`, `authorizationVersion`, `network`, `chain`, `bindingNonce` |
| Unsupported isolation levels rejected | `IMPLEMENTED_ISOLATION` = `['none:browser-javascript']`; every other level throws |
| `hardware-signer` is canonical | confirmed — corrected from `hardware-wallet` in `81886c8` |
| `none:browser-javascript` the only implemented level | confirmed |

### Gap found and closed in this phase

The brief asks whether a caller can claim `transactionBinding = RECOMPUTED_DIGEST` **without
actually implementing verification**. They could: `assertSigner` checks the *declaration*, and
a structural check cannot see inside a function.

Added `probeTransactionBinding(signer, authorization)` — a behavioural conformance probe that
asks a signer to sign a request disagreeing with its authorisation in each field and requires a
refusal. It is safe against a live signer, because a conforming one refuses before deriving
anything. A test asserts that the real signer passes and that a signer which merely *declares*
the binding is caught.

**`assertSigner` checks the claim; the probe checks the behaviour. Neither alone is
sufficient, and this document does not present the declaration as proof.**

### Explicit classification

**Secure hardware signing: NOT IMPLEMENTED.** Browser signing is not hardware secure and is
not described as such anywhere in the codebase. `describeIsolation` returns *"Signing runs in
browser JavaScript, in the same realm as the page. Script running in this origin can reach the
key while it is in use. This is not a secure element, a TEE, an HSM or a hardware wallet."*

---

## 8. Browser secret exposure

**READY WITH LIMITATION — the limitation is JavaScript itself.**

`public/app.js`, all twelve search terms:

| Term | Count | Term | Count |
|---|---|---|---|
| `privateKey` | **0** | `openSealed` | **0** |
| `private_key` | **0** | `getPrivateKey` | **0** |
| `mnemonic` | 4 | `exportSeed` | **0** |
| `WALLET_SEED` | 1 | `getSecret` | **0** |
| `QUVAULT_LEGACY_SEED` | **0** | `decryptWallet` | **0** |
| `sealed_key` | **0** | | |

- `mnemonic` ×4 — two are comments; two are the restore pass-through (`:591–593`) and the
  reveal modal (`:1548–1549`). Both irreducible: somebody must type a phrase in and read one
  out. **LEGITIMATE.**
- `WALLET_SEED` ×1 — the setup message telling an operator to run `npm run keygen`.
  **UI METADATA.**

Storage and transport sinks:

| Sink | Finding |
|---|---|
| `localStorage` | **zero uses anywhere in the repository** |
| `sessionStorage` | one key, holding `{ state, verifier }` — the OIDC PKCE pair, not wallet material |
| IndexedDB | `{ blob, salt, address, publicKey, attestationRootKeyId, createdAt }` — the blob is AES-256-GCM ciphertext; the phrase is never stored |
| URLs / query strings | no secret |
| DOM attributes | no secret; the reveal modal puts words in text nodes and clears them on close |
| Event payloads | no secret |
| Logs | **no logging at all** in `public/app.js` or `client/wallet.js` |

**JavaScript strings cannot be reliably zeroized, and no claim to the contrary is made
anywhere in this repository.** Typed arrays are zeroed — 18 `fill(0)` sites in
`client/wallet.js`, including on throwing paths. Strings are not, and cannot be.

> **Browser JavaScript signing remains the dominant security limitation until an isolated
> signing boundary exists.**

---

## 9. API response security

**READY.** Verified by material leak tests, not by regex alone.

`test/signing-boundary.test.js` drives a real vault through create → withdraw → broadcast →
receipt → unlock and asserts that **the exact private key and ML-DSA secret key that test
vault holds** appear in none of the response bodies from `/api/config`, `/api/wallet`,
`/api/random`, `/api/scanner`, `/api/invites`, the receipt route, the withdrawal result and
the unlock.

This is a material check, deliberately: an ML-DSA-65 public key is 1952 bytes of base64 and
defeats shape heuristics — an earlier WIF-shaped regex false-positived on exactly that.

Negative tests exist for the one endpoint introduced since Phase 1: `/api/scanner` is asserted
to report `available: false`, `authorizationVersion: 1`, and never `PASSED`; and
`test/legacy-closure.test.js` asserts it carries no seed and no seed-named field.

No endpoint can return a private key, mnemonic, seed, decrypted wallet secret, raw biometric
material, raw scanner capture or biometric template — the last three because no such data
exists anywhere in the system.

---

## 10. Security event audit

**READY.**

Enforcement is structural, not procedural:

1. **Field allowlist** — 22 names; every other key is dropped. No allowlisted name refers to a
   secret, and a test asserts that by pattern over the list itself.
2. **Value scrubbing** — a phrase-shaped value (twelve lowercase words) or key-shaped value
   (long hex or base64) is replaced **even on an allowed field**. Objects become `[object]`.
   Values are capped at 120 characters.
3. **Never fatal** — emission is wrapped so an event cannot fail the security decision that
   produced it.

Tested: a `redact()` call handed `mnemonic`, `privateKey`, `seed` and `unlock` keeps none of
them; `reason` set to a phrase becomes `[redacted: phrase-shaped]`; `reason` set to 160 hex
characters becomes `[redacted: key-shaped]`. Live event streams from a refusal, a success and
a migration are each asserted to contain no secret field.

Events cannot contain biometric templates, raw palm data or raw scanner capture because no such
data exists and no allowlisted field could carry it.

---

## 11. Database biometric boundary

**READY.**

The schema contains **no** palm images, raw NIR captures, biometric templates, palm secret,
reconstructed biometric material, private keys (outside legacy `sealed_key`) or plaintext
mnemonic.

Every palm-related column is an opaque reference to a decision made elsewhere:

| Column | Contents |
|---|---|
| `wallets.bound_sub` | pairwise OIDC subject |
| `wallets.bound_decision` | Veyns decision id |
| `approvals.decision_id`, `proof_id`, `request_id`, `challenge` | Veyns references |
| `members.palm_id` | `PALM-` + 12 chars of `SHA-256("palm:" + OIDC subject)` |
| `members.palm_at` | a timestamp |

### The `palm_id` distinction, documented

`palm_id` is derived from the **OIDC subject**, not from any biometric. It is a display label
so a person can recognise their own enrolment, and it is a function of an identifier Veyns
issued — not of a palm, a vein pattern, a template or a capture.

**It contains no biometric entropy and must never be represented as containing any.** It is an
enrollment reference. If the same person enrolled on different hardware, `palm_id` would be
unchanged, because the hardware is not an input.

---

## 12. Production-readiness classification

| Area | Status | Evidence | Blocker |
|---|---|---|---|
| Legacy custody inventory | **BLOCKED** | tooling verified; SQL shared with its test; `--help` added | Production database access not supplied |
| Normal server signing | **READY** | `broadcastPlan` deleted; `requestWithdrawal` refuses legacy; `runOperation` throws; tests | None identified |
| Legacy migration | **READY WITH LIMITATION** | 4-condition gate incl. upstream Veyns re-verification; forged-row tests | Production inventory unknown |
| Legacy deletion | **BLOCKED** | `LEGACY-CUSTODY-DELETION-GATE.md`, 1 of 10 conditions met | Legacy population unknown |
| WALLET_SEED dependency | **READY WITH LIMITATION** | `WALLET-SEED-DEPENDENCY-MAP.md`; never used at login; never the spending key | Root still required for unlock secrets |
| Browser signing isolation | **READY WITH LIMITATION** | signer audit; `IMPLEMENTED_ISOLATION` has one entry | Browser JavaScript remains |
| Hardware signer | **NOT IMPLEMENTED** | interface only; all other levels throw | Hardware integration |
| NIR scanner | **NOT IMPLEMENTED** | abstraction only; `capture()` throws, `discover()` returns `[]` | Hardware integration |
| PAD | **NOT IMPLEMENTED** | `getPADResult()` → `NOT_AVAILABLE`; `PASSED` unreachable in module | Real PAD implementation |
| Biometric verification | **NOT IMPLEMENTED** | `getBiometricResult()` → `NOT_AVAILABLE` | Real biometric implementation |
| Fuzzy extraction | **NOT IMPLEMENTED** | deliberately deferred | Characterization first |
| Scanner attestation | **NOT IMPLEMENTED** | `getAttestation()` → `NOT_AVAILABLE` | Hardware trust model |
| Portable wallet invariant | **READY** | no scanner value reachable from derivation; import test; same-phrase-same-address test | None identified |
| Transaction binding | **READY** | 8-field match + independent digest recomputation + behavioural conformance probe | None identified |
| API secret boundary | **READY** | material leak tests against the vault's actual key material | None identified |
| Security event boundary | **READY** | allowlist + scrubbing + live-stream assertions | None identified |
| Database privacy | **READY** | schema review; `palm_id` is a subject hash | None identified |
| V2 authorization | **READY WITH LIMITATION** | cannot be produced; placeholder records refused | Dormant until a real provider exists |

---

## Tests

```
npm test            → 157 passing, 0 failing
npm run audit       → exit 0; every tracked text file readable by grep; page names no key material
npm run inventory -- --help → exit 0
```

**Count changed from 156 to 157**, and the reason is §7: one test was added for
`probeTransactionBinding`, covering the gap where a signer could declare
`RECOMPUTED_DIGEST` without implementing it. No test was removed, weakened, skipped, or
converted to an assertion about a mock.

---

## KNOWN LIMITATIONS

- **Browser JavaScript signing remains the dominant security limitation until an isolated
  signing boundary exists.**
- JavaScript strings cannot be reliably zeroized. The mnemonic is a string wherever it exists.
- **There is no palm-vein scanner.** No NIR capture, no PAD, no biometric verification, no
  attestation, no fuzzy extraction, no palm-derived key material.
- **No biometric entropy has been measured**, and no claim about biometric key strength may
  appear anywhere in this product.
- **Nothing is certified.** Not ISO, not FIPS-validated as a system, not externally reviewed.
- `WALLET_SEED` is required in normal running and lives for the process lifetime as an
  unerasable string.
- One server-side private-key path remains, gated four ways. Gated and proven is not absent.
- Only Bitcoin testnet4 can send.
- `public/app.js` is unit-untested; its flows are verified manually in a browser.

| State | Contents |
|---|---|
| IMPLEMENTED | ML-DSA-65 authorization records; ML-KEM-768 + X25519 sealing; AES-256-GCM; transaction-bound signing with an authorization object and a behavioural binding probe; palm-gated single-use unlock; browser-held keys; upstream Veyns re-verification before any legacy key opens; Signer, scanner and event interfaces |
| EXPERIMENTALLY VALIDATED | nothing |
| CRYPTOGRAPHICALLY REVIEWED | nothing |
| FORMALLY CERTIFIED | nothing |

Phase 2 has not been started.
