# Phase 1 — Architecture audit for Human Verified Cryptographic Custody

**Date:** 2026-09-20. **Status:** discovery only. No code was modified for this document.
**Scope:** every repository on this machine that the brief names, plus the ones it implies.

How to read the confidence column: **traced** means call paths were followed in source;
**read** means module documentation and key source files were read but call paths were not
executed; **surveyed** means structure, manifests and reports only. Nothing here is inferred
from a filename.

---

## 1. The estate

| System | Location | Language | What it actually is | Confidence |
|---|---|---|---|---|
| **QuVault** (this repo) | `C:\ubtc\quvault` | Node 24, no framework | The shipping product: testnet4 Bitcoin vault, palm-approved withdrawals, five accounts from one phrase, browser-held keys. Live at quvault-one.vercel.app | traced |
| **QuFi Verification (VNL)** | `C:\QuFi Verification` | Rust workspace, 15 crates | Chain-agnostic attestation network **and** the Policy Vault engine. Holds `qufi.authz.v1`, the canonical PQC authorisation request | read |
| — stale copy | `C:\ubtc\qufi-vnl` | Rust | Same workspace, 2026-09-01, missing `qufi-pqc` and `qufi-ubtc-reserve`. **Superseded** | surveyed |
| **QuFi Verify** | `C:\ubtc\qufi-verify` | Node workspace | ML-DSA-65 signed envelopes, a quorum of independent verifiers, a dashboard that re-verifies. The closest thing to the "Guardian Network" | read |
| **QVault V2** | `C:\ubtc\qufi-vault` | Rust + Next.js | A *document* vault: ML-KEM-768 + Shamir + Argon2id, Rust authority service. Has an adversarial review with an unresolved critical finding | read (review) |
| **QUSEVA** | `C:\ubtc\quseva` | Rust, 12 crates | Post-quantum distributed KMS: key hierarchy, custody, governance, policy, audit | surveyed |
| **NABD crypto-hardware** | `C:\nabd_chain\crypto-hardware` | Rust + card-kit | Sansec PQC PCIe HSM integration. ML-DSA on-card. Card lives on a separate Linux host | surveyed |
| **Veyns** | hosted: `sandbox.id.veyns.io` | — | The palm identity provider. OIDC. Not our code | traced (client side) |
| **Palm terminals** | `C:\ubtc\qufi-node-app` (`com.nabd.usb`), `C:\ubtc\veyns-passport` (`com.nabd.pos`) | Android (decompiled APK + patched front ends) | The physical palm scanners. Vendor firmware, re-skinned | surveyed |
| Chain adapters | `C:\QuFi Verification\adapters` | Rust | `qufi-vnl-{bitcoin,evm,solana,stellar}` plus `qufi-vault-vnl`; Soroban contracts in `contracts/` | surveyed |

There is **no repository called "Guardian Network"**, but the word is already taken, and
usefully so. `GUARDIAN` is a participant **role** in the Rust policy vault
(`qufi-vault-types/src/ids.rs`: *"Recovery participant, typically inactive until a vault
expires"*), alongside `OWNER`, `BUYER`, `SELLER`, `VERIFIER`, `ARBITRATOR` and `INSTITUTION`.
Roles are validated labels, not enum variants, and the engine only tests set membership — so a
guardian set is configuration, not a protocol change. That is the vocabulary recovery (G9)
should adopt rather than inventing one.

The *network* role the brief gives a Guardian — independent verification of evidence — is
filled today by `qufi-verify`'s verifier quorum (JavaScript) and, at the network layer, by the
VNL's BFT validators (Rust). They are separate systems that do not know about each other, and
neither is the same thing as the `GUARDIAN` role above. Keeping those two senses apart matters:
one is *who may act for a vault*, the other is *who checks the evidence afterwards*.

---

## 2. QuVault as built — traced call paths

### 2.1 Sign-in
`public/app.js signIn()` → Veyns SDK or PKCE redirect → `POST /api/login/finish`
→ `src/app.js loginFinish()` → `src/veyns.js verifyToken()`.

Checks, in order: ES256 only (`alg` pinned), JWKS from the issuer, `iss`, `aud` = client id,
`exp`/`iat`, `nonce` matches a server-stored login nonce, `veyns_intent === 'login'`,
`auth_time` fresh within 300 s, and `veyns_presence === true`. On success a random 32-byte
session id is stored as `sha256(sid)`.

**Authenticated:** that the Veyns issuer asserted a pairwise subject was present at a time.
**Not authenticated:** any device, any liveness property, any hardware.

### 2.2 The approval ceremony (the security core)
1. `requestWithdrawal()` builds a **plan** from live UTXOs: inputs, outputs, fee, fee rate.
2. It writes `statement` (human sentence) + `details` (structured fields) + `digest =
   actionDigest(statement, details)` into `operations`. Digest = base64url SHA-256 over
   canonical JSON with sorted keys, `details: null` when absent (`src/veyns.js`).
3. The plan itself is stored as `payload`, **outside the digest**.
4. `startPalm()` sends `{ subject, action: { statement, details }, idempotency_key }` to
   `POST /v1/approvals` at Veyns. Veyns computes its own digest of the same action.
5. The phone shows the statement; the person scans; Veyns returns a **decision JWT**.
6. `settlePalm()` verifies: signature (ES256), `sub` matches the session's subject form,
   `request_id`, `request_nonce` = the stored challenge, `veyns_intent === 'action'`,
   `amr` includes `veyns:palm`, **`veyns_action.digest === op.digest`**, `auth_time` fresh,
   `decision_id` present. One decision settles one approval (`proof_id` is unique).
7. When approvals ≥ `required`, exactly one caller wins `startRunning()` and runs the action.
8. For a client-custody withdrawal the server stops there. The browser calls
   `/unlock`, decrypts the phrase, and `client/wallet.js signPlan()` rebuilds the transaction
   **from the stored plan** and refuses if the fee does not match.
9. `broadcastSigned()` re-parses the raw transaction and runs `verifyAgainstPlan()`:
   same coins, same outputs, same fee, fully signed — then broadcasts once.

**What binds today:** the palm decision is bound to the *statement digest*, and the signed
transaction is bound to the *stored plan*. The join between them is server-side state
(`operations.payload`), not a cryptographic commitment. See §5, gap G1.

### 2.3 Key custody
- New vaults: BIP39 12 words in the browser; entropy = HKDF(browser random ‖ server random ‖
  ceremony jitter). Encrypted with AES-256-GCM under HKDF(unlock secret, device salt) in
  IndexedDB. The server holds only the address, the public key, and an **ML-KEM-768 + X25519
  sealed** unlock secret (`src/vault.js`).
- Legacy vaults: a server-held secp256k1 key sealed with the same envelope. A palm-approved
  migration moves them into the browser and destroys the old key.
- Recovery: two palm scans (two slots on one operation) reveal the phrase in the browser.

### 2.4 Policy
`src/policy.js` — rules are `{ upToSats, approvals }` steps, ascending, last is `null`
(anything larger). `requiredFor(policy, sats)` picks the step; `requiredToChange()` is the
strongest step, capped by signer count. Per account since 2026-09-20: each account carries its
own `policy` and `signers`, and a change takes the palms guarding that account *before* the
change. Evaluation is deterministic and total; there is no scripting.

---

## 3. Component table

| Component | Status | Location | Depends on | Security role | Disposition |
|---|---|---|---|---|---|
| Veyns OIDC client, token verification | PRODUCTION (sandbox IdP) | `quvault/src/veyns.js` | hosted Veyns, JWKS | Human presence; binds a palm decision to an action digest | **Reuse**, extend with liveness/device claims if Veyns exposes them |
| Action digest (canonical JSON, SHA-256) | PRODUCTION | `quvault/src/veyns.js` | — | The only thing a human's palm is bound to | **Modify** — must also commit to the transaction bytes (G1) |
| Operation/quorum engine | PRODUCTION | `quvault/src/app.js` | Postgres | Quorum, one-decision-one-approval, fail-closed transitions | Reuse |
| Per-account policy engine | PRODUCTION | `quvault/src/policy.js` | — | Threshold by amount; change quorum | **Modify** — align vocabulary with `qufi-vault-policy` |
| Bitcoin plan/sign/verify | PRODUCTION (testnet4) | `quvault/src/bitcoin.js`, `client/wallet.js` | `@scure/btc-signer` | Plan-then-sign; `verifyAgainstPlan` before broadcast | Reuse |
| PQ envelope (ML-KEM-768 + X25519 + AES-GCM) | PRODUCTION | `quvault/src/vault.js` | `@noble/post-quantum` 0.7.1 | Seals the unlock secret at rest | Reuse |
| Browser key custody | PRODUCTION | `quvault/client/wallet.js` | WebCrypto, IndexedDB | The key never reaches the server | Reuse |
| Multi-network derivation | PRODUCTION | `quvault/client/wallet.js`, `src/networks.js` | `@scure/*`, `@noble/*` | Addresses for 5 chains from one phrase | Reuse |
| Migration/upgrade path | PRODUCTION | `quvault/src/db.js` | Postgres | Schema correctness across deploys | Reuse (tested since today) |
| **`qufi.authz.v1` AuthorizationRequest** | IMPLEMENTED, not deployed | `QuFi Verification/crates/qufi-vnl-types/src/authz.rs` | `fips204` | Canonical PQC authorisation request; strict codec; FIPS 204 context; replay/substitution tests | **Reuse as the model** for the attestation |
| VNL state machine, nullifier set | IMPLEMENTED | `crates/qufi-vnl-state` | — | Spend-once across chains; verifies authz signatures | Reuse later (G7) |
| VNL consensus, validator auth | IMPLEMENTED, single-validator | `crates/qufi-vnl-consensus`, `-node` | — | BFT agreement; no peer transport yet | Not on the critical path now |
| Policy Vault types (intent, authorization, attestation, commitment) | IMPLEMENTED | `crates/qufi-vault-types` | `sha3` | Exactly the binding model the brief asks for | **Reuse as the model** |
| Policy Vault engine | IMPLEMENTED | `crates/qufi-vault-policy` | vault-types | Deterministic policy as data, bounded tree | Reuse later |
| `qufi-pqc` (ML-DSA) | IMPLEMENTED | `crates/qufi-pqc` | `fips204` | Signature primitive, layer 0 | Reuse (Rust side) |
| **`@qufi/sdk` signed envelope** | IMPLEMENTED | `qufi-verify/packages/qufi-sdk` | `@noble/post-quantum` 0.6.1, `@noble/hashes` | ML-DSA-65 over canonical bytes; derived envelope id; signed region excludes transport fields | **Reuse** — this is the evidence format |
| Verifier quorum + aggregator + pull queue | IMPLEMENTED | `qufi-verify/services/verifier` | service-kit | k-of-n independent confirmation | **Reuse** as the Guardian |
| Dashboard that re-verifies | IMPLEMENTED | `qufi-verify/services/dashboard` | sdk | Independent verification of evidence | Reuse |
| QuFi Verify app (Expo/RN) | IMPLEMENTED | `qufi-verify/apps/qufi-verify-app` | sdk, client | Phone-as-verifier | Candidate device layer |
| QVault V2 (documents) | BETA, **critical finding open** | `C:\ubtc\qufi-vault` | ML-KEM-768, Shamir, Argon2id, ML-DSA-65 | Not on the asset-custody path | Leave untouched |
| QUSEVA PQ-DKMS | PROTOTYPE→BETA | `C:\ubtc\quseva` | Rust | Enterprise key hierarchy; a future home for institutional custody | Out of scope for now |
| Sansec PQC HSM | PROTOTYPE | `C:\nabd_chain\crypto-hardware` | separate Linux host | Hardware ML-DSA; the strongest future signer | Investigate in a later phase |
| Palm terminals | VENDOR + patches | `qufi-node-app`, `veyns-passport` | Android | Where a palm is actually captured | Not modifiable by us beyond the front end |

---

## 4. Cryptographic inventory — what is actually used today

| Primitive | Where | Purpose |
|---|---|---|
| ECDSA P-256 / ES256 (JOSE) | `quvault/src/veyns.js` | **Every human authorisation decision today** |
| SHA-256 | `quvault` action digest, session ids, HKDF | Action binding |
| ML-KEM-768 + X25519 → HKDF-SHA256 → AES-256-GCM | `quvault/src/vault.js` | Sealing the unlock secret at rest |
| AES-256-GCM (WebCrypto) | `client/wallet.js` | Phrase at rest in the browser |
| BIP39 / BIP32 / SLIP-0010 | `client/wallet.js` | Key derivation, 5 chains |
| secp256k1 (ECDSA), ed25519 | `client/wallet.js` | Chain signatures |
| ML-DSA-65 (FIPS 204) | `qufi-verify` (JS, noble), `QuFi Verification` (Rust, fips204) | Envelope and authz signatures — **not used by QuVault** |
| SHA3-256 | VNL `request_hash`, vault-types ids | Canonical hashing in the Rust layer |
| Argon2id, Shamir | QVault V2 only | Document vault |

**The headline:** the product that holds assets uses **no post-quantum signature anywhere in
the authorisation path**. The PQ envelope protects a secret at rest; the human's approval is
carried by a classical ES256 token. The brief's "post-quantum, human verified" claim is not
yet true of the signing path, and must not be made until it is.

---

## 5. Gaps against the brief

| # | Requirement | Today | Gap |
|---|---|---|---|
| G1 | Displayed = approved = signed = broadcast | Palm binds the **statement digest**; signing binds the **stored plan**; broadcast re-checks against the plan | The two are joined by server state, not by a hash inside the signed statement. A server that swapped `payload` after approval would be caught by `verifyAgainstPlan` only because the plan is what it compares to — i.e. the check is against the thing an attacker would have changed. **Fix: put the transaction digest inside the signed statement.** |
| G2 | PQC attestation of the authorisation | None | No ML-DSA signature is produced by QuVault at all |
| G3 | Evidence receipt, independently verifiable | None | No receipt object, no verifier path |
| G4 | Liveness | Not available | Veyns exposes `veyns_presence` only; no liveness claim is requested or verified |
| G5 | Device attestation / integrity | None | Nothing binds an approval to a device, Keystore or StrongBox |
| G6 | Canonical transaction object, one representation | Two half-models: `details` (human) and `payload` (machine) | Needs one canonical `HumanVerifiedTransaction` whose hash appears in both |
| G7 | Guardian verification of the evidence | None | `qufi-verify` exists and is unused by QuVault |
| G8 | Policy vocabulary shared with the vault engine | Two engines: JS thresholds, Rust policy trees | Converge on one model, JS first |
| G9 | Recovery independent of biometrics | Recovery **is** two palm scans | A destroyed palm or an unavailable sensor locks the user out of the *phrase display*, though the 12 words still restore elsewhere. Needs its own policy and delay — and the `GUARDIAN` role plus `IssuerConstraint` in `qufi-vault-types` already give it a vocabulary to borrow rather than invent |
| G10 | Multi-chain human-authorisation layer | Bitcoin only can spend | The authorisation layer must not learn chain specifics |
| G11 | Version skew | `@noble/post-quantum` 0.6.1 (sdk) vs 0.7.1 (quvault) | Must be pinned to one before sharing the SDK |

---

## 6. Duplication to resolve before building

1. **Two canonical encodings.** `actionDigest` (sorted-key JSON, SHA-256) in QuVault versus
   `CanonicalEncode`/`Writer` (length-prefixed binary, SHA3-256) in the Rust layer and
   `codec.js` in `@qufi/sdk`. The brief forbids a third. The JS product should adopt
   `@qufi/sdk`'s codec for anything it signs with ML-DSA, and keep `actionDigest` **only** as
   the human-statement digest that Veyns also computes.
2. **Two policy engines.** Keep the JS engine as the enforcement point for now; borrow the
   Rust engine's vocabulary (intent, authorisation context, issuer constraint) so a later move
   is a port rather than a redesign.
3. **Two verifier networks.** `qufi-verify` (JS quorum) and the VNL (Rust BFT). For evidence
   about a human authorisation, `qufi-verify` is the right one: it is JavaScript, it already
   has the envelope, the quorum and a re-verifying dashboard.

---

## 7. What I propose for Phase 2 (not implemented)

A `HumanAuthorisation` record produced by QuVault, signed with ML-DSA-65 through `@qufi/sdk`,
binding in one signed region:

```
vault id · account · policy id (content hash) · transaction digest (of the exact plan)
· statement digest (what the human read) · Veyns decision id · subject · amr · auth_time
· approval slot · nonce · validity window
```

with the transaction digest **also inside the `details` the human approves**, so Veyns's own
digest covers it. That single change closes G1 and G6 and makes G2/G3 mechanical.

Open decisions I need from you before Phase 2 is written:

- **D1.** Does the Veyns sandbox expose liveness or device-attestation claims? If not, is
  "presence + palm" the honest ceiling for now (my assumption), with liveness deferred?
- **D2.** Who holds the ML-DSA signing key for the attestation — the QuVault server (weakest,
  fastest), the browser next to the wallet key, the Sansec HSM, or a QuFi verifier?
- **D3.** Is `qufi-verify` deployed anywhere, or would QuVault be its first live producer?
- **D4.** Do you want the Rust policy-vault engine to become the enforcement point eventually,
  or should the JS engine stay authoritative for QuVault?

---

## 8. Honest position on the product claim

What the system can support today: *an authorised human, identified by a pairwise Veyns
subject, was verified by palm at a stated time and approved a stated sentence whose digest the
identity provider independently computed; the transaction that was broadcast matches the plan
the server recorded for that approval.*

What it cannot yet support: liveness, device integrity, post-quantum evidence, independent
verification without trusting this server, or proof that the displayed transaction is the
signed transaction without trusting the server's own state. Those are Phases 3–7.
