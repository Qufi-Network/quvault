# What Veyns would have to return before a palm scan can lock down a Bitcoin spend

**Status: a request to Veyns, not a QuVault task.** Nothing here is implemented and nothing here
can be implemented on this side alone.

The product requirement is that the Veyns wallet accepts BTC and locks it down with the palm
vein scanner. Half of that is already true. The other half is blocked on six fields that the
Veyns approval API does not return, and this document names them exactly.

---

## 1. What already works

Every outgoing Bitcoin payment is already gated on a Veyns palm decision bound to that exact
transaction:

- `POST /v1/approvals` carries an `action.digest` computed over the canonical transaction —
  the precise inputs, outputs, fee and change.
- The spend path refuses unless the decision comes back `approved` for that digest, and the
  decision is **re-fetched from Veyns** rather than trusted from our own database, so a forged
  row cannot authorise a payment.
- The plan is re-derived and compared to the digest again immediately before broadcast.
- The unlock secret is released once, for one approval, inside a 300-second window.

So "a payment cannot leave without a palm" is implemented, tested and verified live. What is
**not** established is anything about the *device* that palm was presented to.

## 2. What the Veyns API returns today, and what it does not

From the published spec — `Veyns identity and approval API 0.6.0`, `sandbox.id.veyns.io` — the
durable `Approval` object has:

```
request_id, status, challenge, required_method: 'palm', application, kind,
action { statement, details, digest }, created_at, expires_at,
decision, decision_id, acknowledged, approval_url
```

Searching the whole specification for device measurement terms returns **nothing**:

| Term | Occurrences in the spec |
|---|---|
| `pad`, `liveness`, `spoof` | 0 |
| `device`, `firmware`, `model`, `serial` | 0 |
| `attestation`, `template`, `biometric` | 0 |
| `capture`, `score`, `threshold` | 0 |
| `scanner` | 9 — **all of them delivery routing** |

All nine `scanner` mentions are about *how the prompt reaches the person* on the first-party
sign-in ceremony: pairing a scanner to produce a QR, `delivery: 'scanner' | 'qr'`, and a
browser-local preference the spec says "grants no sign-in or approval". None of them appear on
`/v1/approvals`, and the endpoints they do appear on are documented as "First-party Veyns
ceremony UI" that "cannot authenticate the caller".

**So a palm decision is a decision, not a measurement.** `required_method: 'palm'` is a
constant stating which method was required. It does not say a live palm was presented, that it
matched an enrolled one, or which device did the work.

## 3. Why that blocks the stronger claim

QuVault's authorisation record has had the fields for this since Phase 1. Version 2 of the
record carries:

```js
verification: {
  approvalProvider, padResult, biometricVerification, scannerAttestation,
  scannerClass, captureReference, bindingNonce, biometricPolicyVersion, sensorEvidence,
}
```

and `evidenceIsUsable()` refuses to call it a measurement unless **all** of the following hold:

1. `pad.result === 'PASSED'` **and** `pad.performed === true`
2. `biometric.result === 'PASSED'` and performed
3. `attestation.result === 'PASSED'` and performed
4. a `scannerClass` is named
5. a `captureReference` is named
6. `bindingNonce` equals the transaction digest — the attestation is about *this* spend

Nothing in the Veyns response can satisfy a single one of those six. That is why V2 is dormant
and every record QuVault writes is V1. **The dormancy is not an oversight and it is not waiting
on hardware arriving in this room — it is waiting on the API.**

It would be trivial to fill those fields from `status === 'approved'`. That is exactly what must
not happen: `src/scanner.js` exists to prevent a placeholder that reports "verified", because
every layer above it then believes a measurement that never took place. The null provider stays
null until there is something real to report.

## 4. The request

Add the measurement to the approval decision. Six fields on `Approval`, returned when
`status: 'approved'`:

```jsonc
{
  "verification": {
    // Liveness, computed ON the device. A verdict computed by a host is a verdict an
    // attacker with the host can write.
    "pad": { "performed": true, "result": "PASSED" },
    // Match against the enrolled palm.
    "biometric": { "performed": true, "result": "PASSED" },
    // The device's signature over the action digest it was shown. This is the field that
    // makes the three above checkable rather than merely asserted.
    "attestation": {
      "performed": true,
      "result": "PASSED",
      "algorithm": "...",
      "key_id": "...",
      "signature": "..."
    },
    // A CLASS — manufacturer, model and firmware range — never a serial number. A portable
    // wallet has to work on a scanner it has never met, so what gets trusted is a class, and
    // the revocation unit is the class.
    "scanner_class": "veyns-bio-signature-disk/1",
    // An opaque handle naming one capture, so two approvals cannot share one scan.
    "capture_reference": "...",
    // MUST equal action.digest. Without this the attestation is a recording of some other
    // payment and can be replayed onto this one.
    "binding_nonce": "<action.digest>"
  }
}
```

Plus a published key set for the attestation keys, so the signature can be checked without
asking Veyns whether to believe Veyns — the same reason `jwks.json` already exists for the
identity tokens.

### Two properties that matter more than the field names

**The signature has to be the device's, over a nonce the device did not choose.** The nonce is
`action.digest`, which Veyns already receives. That single property is what turns "Veyns says a
palm passed" into something a third party can check: an attestation over a digest the host
supplied is a statement about one specific payment, and it cannot be lifted onto another.

**More than one signature is better than one.** QuVault relies today on a single Veyns decision,
which means a compromise at Veyns is a compromise of the gate. If several keys held by different
parties sign the verification result and a quorum is required, the trust model improves in the
same change — and the wallet would verify the quorum rather than take one signer's word.

Neither property needs new biometrics work. They are about what the approval response carries
and who signed it.

## 5. What QuVault does the moment it lands

One provider file against a seam that already exists, and three things switch on:

| | |
|---|---|
| `src/scanner.js` | a `veynsScanner` provider implementing the existing contract — `discover`, `getCapabilities`, `connect`, `capture`, `getPADResult`, `getBiometricResult`, `getAttestation`. `assertProvider` already refuses one that touches key material. |
| `src/authorization.js` | V2 records go live and say `sensorEvidence: 'measured'`. No change needed — `signAuthorizationV2` already refuses unless the evidence is usable and bound to that transaction. |
| policy | a treasury can **require** measured evidence for a spend, so a payment with no attested scan is refused rather than merely recorded as unmeasured. |

Everything else — the evidence log, the checkpoints, the quorum, the organisations — is
unchanged. This is a provider, not an architecture.

## 6. What stays out, and must

**Palm as a key factor is a different project and is not this one.** Deriving part of the wallet
key from the palm needs a fuzzy extractor and three numbers that do not exist: the
false-rejection rate at the operating threshold, the error-correction budget, and the measured
entropy of the extracted representation on a real population. Getting it wrong means coins that
are on the chain and permanently unreachable.

"Lock it down with the scanner" means **the scan gates the spend**. It does not mean the scan
derives the key, and the recovery phrase must remain a complete and sufficient recovery path on
its own. See `SCANNER-TRUST-BOUNDARY.md`.

## 7. The honest statement until then

> Every Bitcoin payment requires a Veyns palm approval bound to that exact transaction, verified
> upstream with Veyns before the spend proceeds. QuVault records what Veyns reports. It does not
> claim that a live palm was measured on an attested device, because the Veyns approval API does
> not report it.

No scanner, no PAD, no measured biometric entropy, no certification. testnet4 only.
