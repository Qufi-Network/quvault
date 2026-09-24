# Phase 2 entry gate

Phase 2 is the real NIR scanner and palm authentication integration. **It must not start until
everything below is understood.** These are things to *know*, not things to build — nothing in
this document may be implemented before the gate is passed.

**Current status: NOT PASSED.** Most items are unknown because they depend on hardware nobody
has selected and a production database nobody has supplied.

---

## Custody

| # | Requirement | Status | How it is satisfied |
|---|---|---|---|
| C1 | Production server-custody population known | **NOT MET** | `QUVAULT_ADMIN_DATABASE_URL="postgres://…" npm run inventory -- --json` |
| C2 | Migration strategy validated | **PARTLY MET** | Procedure is written and tested end to end against a real database and HTTP server. **Never validated against production data**, where row states may exist that the tests do not model — `serverInactive` rows in particular. |
| C3 | Legacy deletion criteria documented | **MET** | `LEGACY-CUSTODY-DELETION-GATE.md` — ten conditions, four-state model, two-stage deletion, backup dependency |

**C1 is the single blocking input for this whole section**, and it is one command away.

---

## Signing

| # | Requirement | Status | Notes |
|---|---|---|---|
| S1 | Secure signer boundary defined | **MET** | `getPublicKey` / `signTransaction(authorization)` / `signMessage(authorization)`; no key-returning method can exist; `sealResult` strips non-allowlisted fields; behavioural binding probe |
| S2 | Hardware signer trust boundary defined | **MET (as design)** | Documented in `PHASE-1.5-SECURITY-CLOSURE.md` §5 and `SCANNER-TRUST-BOUNDARY.md`. USB-C is transport and carries no security property. |
| S3 | Browser limitation explicitly retained | **MET** | `IMPLEMENTED_ISOLATION` has one entry; every other level throws; `describeIsolation` states it in words; tested |

**Not required for Phase 2 entry, but stated so it is not forgotten:** a hardware signer does
not exist, and Phase 2 does not create one. Phase 2 adds a scanner, which is a sensor. The
signing boundary is a separate problem and remains browser JavaScript after Phase 2 unless
something else changes.

---

## Hardware — none of this is known

| # | Requirement | Status |
|---|---|---|
| H1 | Actual NIR scanner identified | **NOT MET** |
| H2 | Vendor and model documented | **NOT MET** |
| H3 | Transport documented | **NOT MET** |
| H4 | SDK / protocol availability documented | **NOT MET** |
| H5 | Raw capture characteristics documented | **NOT MET** |

Every one of these is an input from the physical world. Nothing in this repository can supply
them, and nothing in this repository guesses at them — which is why `src/scanner.js` contains
no transport, no vendor API, no USB descriptor, no certificate and no device identifier.

What each answer has to settle before code is written:

- **H3** — where does PAD run? On the device, or on the host? A verdict computed by the host is
  a verdict an attacker with the host can write. If the vendor's device does not compute PAD
  itself, the PAD field in authorization V2 is worth nothing and should not be populated.
- **H4** — can the device sign an attestation over a host-chosen nonce? If not, `bindingNonce`
  cannot be honoured and V2 cannot become authoritative regardless of what else is built.
- **H5** — does raw capture cross the wire? If an image reaches the host, it can be stolen, and
  a vein pattern cannot be reissued.

---

## Biometrics — none of this is characterized

| # | Requirement | Status |
|---|---|---|
| B1 | Capture repeatability characterized | **NOT MET** |
| B2 | Sensor noise characterized | **NOT MET** |
| B3 | Environmental variation characterized | **NOT MET** |
| B4 | Cross-device variation characterized | **NOT MET** |
| B5 | PAD capability established | **NOT MET** |
| B6 | FAR / FRR measurement plan established | **NOT MET** |

**B4 is the one most likely to be skipped and the one that decides whether the product is
possible.** The portable wallet invariant requires the same palm to open the same wallet on a
*different compatible scanner*. If cross-device variation exceeds the error-correction budget,
portability and stable reconstruction cannot both hold, and the design has to change — not the
implementation, the design.

**B6 exists because a false rejection is a lockout from one's own money.** A measurement plan
means: a defined population, a defined threshold, a defined number of trials, and a stated
acceptable rate agreed before the numbers arrive rather than after.

These are measurements on hardware, not software tasks. **No amount of code substitutes for
them**, and Phase 2 must not begin its cryptographic half until B1–B6 have real numbers.

---

## Cryptography — rules that hold regardless of what the hardware turns out to be

| # | Rule | Status |
|---|---|---|
| X1 | Wallet key remains CSPRNG generated | **MET, and must stay met** |
| X2 | Palm is not raw wallet entropy | **MET** |
| X3 | Palm-derived material is a key-encryption / recovery capability | **DEFINED, not implemented** |
| X4 | Biometric change / re-enrollment recovery defined | **NOT MET** |
| X5 | Loss of scanner does not destroy wallet access | **MET today, must stay met** |

**X1** — the wallet key is browser CSPRNG + server randomness + ceremony jitter → HKDF → BIP39
→ BIP84. No biometric input, now or later. The palm decides whether an existing key can be
unwrapped; it never decides what the key *is*.

**X2** — the palm image is not sufficient entropy, and nothing in this product may say it is.
No entropy figure exists because none has been measured.

**X4 is unresolved and blocking.** Palms change — a healed cut, a burn, a re-enrollment on new
hardware. The recovery path for a person whose biometric no longer matches must be defined
*before* a palm-derived capability is built, not after somebody is locked out. Today the
answer is the twelve words, and that must remain true: **if a palm-derived capability is added,
losing it must never lose the money**, or the fuzzy extractor's failure rate becomes a
fund-loss rate.

**X5** — holds today because no scanner is involved in anything. It must survive Phase 2.

---

## What Phase 2 may implement, once the gate is passed

Scanner discovery and connection over the **real** protocol; capture; quality assessment; PAD
using the device's own capability; biometric verification; scanner attestation from real
hardware; populating authorization V2 with measured evidence.

## What Phase 2 may not implement under any circumstances

- Deriving the Bitcoin private key, seed phrase or wallet entropy from the palm.
- Binding the wallet to a scanner serial number, USB device ID, sensor ID, physical device or
  scanner-specific secret.
- Any entropy figure, PAD certification claim, or attestation claim that hardware has not
  actually produced.
- A PAD or match verdict computed anywhere other than the device.
- Making V2 authoritative before a provider can genuinely fill it in.
- Removing the recovery phrase as a complete and sufficient recovery path.

---

## Summary

| Section | Met | Blocking |
|---|---|---|
| Custody | 1 of 3 | C1 — production inventory |
| Signing | 3 of 3 | none |
| Hardware | 0 of 5 | H1–H5 — scanner not selected |
| Biometrics | 0 of 6 | B1–B6 — nothing characterized |
| Cryptography | 3 of 5 | X4 — re-enrollment recovery undefined |

**Gate status: NOT PASSED. 7 of 22 met.**

The signing section is the only one complete, and that is because it was the work of Phases 1
and 1.5. Everything else waits on two inputs that no amount of further code can produce: a
production database, and a scanner that physically exists.
