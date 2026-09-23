# The scanner trust boundary

**Status: design only. None of this is implemented.** No palm-vein scanner is integrated with
QuVault. There is no driver, no transport, no protocol, no device certificate and no vendor
SDK in this repository. The only provider that exists is `createNullScanner()` in
[src/scanner.js](src/scanner.js), which reports `NOT_AVAILABLE` to every question and has no
code path that can return a pass.

This document exists so the interface added in Phase 1 has a stated destination. It is written
in the conditional on purpose: everything below is what a scanner *would* have to do, not what
anything does.

---

## The chain, and where trust changes hands

```
  NIR scanner                       ── hardware nobody here has yet
       │
       ▼
  USB-C                             ── transport; unknown, so nothing is written against it
       │
       ▼
  scanner protocol                  ── vendor's; not guessed at, not stubbed
       │
       ▼
  PAD                               ── liveness. Runs ON the device, or it is worthless:
       │                               a verdict computed by the host is a verdict an
       │                               attacker with the host can write.
       ▼
  palm-vein feature extraction      ── on the device. Raw captures must not cross the wire;
       │                               an image that reaches the host is an image that can
       │                               be stolen, and a vein pattern cannot be reissued.
       ▼
  device-independent representation ── the hard part. See below.
       │
       ▼
  biometric key reconstruction      ── a fuzzy extractor, with published parameters
       │
       ▼
  authorization                     ── the V2 record in src/authorization.js, dormant today
```

**The trust boundary is between feature extraction and the host.** Everything above it is the
scanner's word. Everything below it is arithmetic anyone can check. The scanner's word is made
checkable by a signature over a nonce that the host chose — and in QuVault that nonce is the
transaction digest, so an attestation is a statement about one spend and cannot be replayed
onto another.

## What the scanner is trusted for, and what it is not

| | |
|---|---|
| **Trusted for** | that a live palm was presented, that it matched the enrolled one, and that both statements are about the capture named in the attestation |
| **Not trusted for** | authorising anything. A PAD pass authorises nothing. A match authorises nothing. Both together authorise nothing. |
| **Never holds** | the wallet key, any part of it, or anything from which it can be derived alone |

The wallet key would come from **two** factors — something derived from the phrase and
something derived from the palm — combined by a KDF. That is what makes the sentence above
true: a compromised scanner that can assert anything it likes still cannot produce the phrase
factor, and a stolen phrase still cannot produce the palm factor.

## Device-independent representation: the unsolved problem

A portable wallet has to work on a scanner it has never met. A key has to be the same key every
time or the money is gone. Those two requirements are what this whole design turns on, and
they pull in opposite directions:

- Biometric captures are **fuzzy**. Two readings of the same palm differ — different sensor,
  different firmware, different angle, different temperature, a healed cut.
- Key derivation is **exact**. One bit different is a different key, a different address, and
  coins that are still on the chain and permanently unreachable.

Bridging them needs a **fuzzy extractor**: a helper-data scheme that tolerates a bounded error
rate and reproduces the same secret. Before any of this can ship, three numbers have to exist
and be measured, not asserted:

1. the false-rejection rate at the operating threshold — the rate at which a legitimate owner
   is locked out of their own money;
2. the error-correction budget, and what happens to someone whose palm drifts past it;
3. the actual entropy of the extracted representation, measured on a real population.

None of these numbers exist. Until they do, **no claim about biometric key strength may appear
anywhere in this product**, and the recovery phrase must remain a complete, sufficient recovery
path on its own.

## Portability versus binding

"Any compatible scanner works" and "this exact device attested" cannot both hold. The trust
anchor therefore has to be a **class** of device — a manufacturer's attestation key covering a
model and firmware range — which carries an accepted consequence: a compromised device in that
class compromises the class, and the answer is revocation of the class, not of a serial number.

## What Phase 1 built toward this, and what it deliberately did not

**Built:**

- `ScannerProvider` shape: `getCapabilities`, `connect`, `capture`, `getPADResult`,
  `getBiometricResult`, `getAttestation`, with `assertProvider()` catching partial ones.
- `evidenceIsUsable()`, which treats a missing field, an unknown string and `true` as failures,
  and only counts an explicit `PASSED` from a check that was `performed`.
- Authorization record V2, carrying `padResult`, `biometricVerification`, `scannerClass`,
  `scannerAttestation`, `captureReference`, `biometricProvider`, `biometricPolicyVersion` and
  `bindingNonce`. `signAuthorizationV2()` refuses without usable evidence bound to that exact
  transaction; `verifyAuthorization()` refuses a V2 record whose contents are assertions rather
  than measurements, including one that smuggles V1's `biometricVerified` back in.
- `expected.minVersion`, so a caller can one day require V2 without today's callers changing.

**Deliberately not built:** any transport, any vendor API, feature extraction, template
formats, matching, thresholds, fuzzy extraction, or any number describing biometric entropy.
Writing a plausible-looking stub for any of these would mean a layer above it believing a
measurement that never happened.

## Claim discipline

Nothing in this product may say "256 bits of biometric entropy", "ISO certified", "hardware
secure" or "quantum proof" without a demonstration behind it. The four states are separate and
must stay separate in the copy as well as the code:

| State | What is in it today |
|---|---|
| **IMPLEMENTED** | ML-DSA-65 authorisation records; ML-KEM-768 + X25519 sealing; transaction-bound signing; palm-gated single-use unlock; browser-held keys |
| **EXPERIMENTALLY VALIDATED** | nothing |
| **CRYPTOGRAPHICALLY REVIEWED** | nothing |
| **FORMALLY CERTIFIED** | nothing |

The Veyns palm decisions the product collects today are real, and they are not the same thing
as a scanner this code has spoken to. V1 records say `biometricVerified: true` because that is
what the first version asserted; V2 exists so that a later version can report what was
measured instead. Until a provider can fill V2 in, nothing produces a V2 record — which is the
honest state, and is the state the tests in [test/boundary.test.js](test/boundary.test.js) pin
in place.
