# Authorization receipt, version 3 — design

**Design only. Not implemented.** Version 2 remains what the browser signs.

Three things V2 cannot do, and one it must keep doing.

---

## 1. What V2 gets wrong

### Intent and transaction are the same field

V2 has one `transactionHash`: the canonical digest over the exact inputs, outputs and fee. That
is the right thing to sign, and it is the wrong thing to *approve*.

A human approves an **intent** — *pay 0.05 tBTC to tb1q…, from the operations account, on
testnet4*. The transaction that realises it names specific UTXOs and a specific fee, neither of
which the approver chose or can meaningfully verify. Collapsing both into one digest has a
practical consequence: **a fee adjustment requires a fresh palm approval**, because the digest
moves, even though nothing the human cared about changed.

Today that is arguably correct behaviour, because nothing adjusts fees. The moment a treasury
needs to bump a stuck transaction, this becomes the blocker.

### The policy is a digest with no readable descriptor

`policyVersion` is a 22-character digest of a sentence. It proves two records were made under
the same rules; it cannot tell a reader *what those rules were*. An auditor holding a receipt
and no database cannot answer "how many approvals did a payment of this size require?".

### A receipt and its evidence entry cannot be associated independently

The evidence log records that an authorisation was granted. The receipt records the
authorisation. Nothing in either points at the other, so a reader holding one cannot confirm the
other exists, and a reader holding both cannot confirm they are about the same event beyond
matching fields by eye.

---

## 2. The structure

```
  intentDigest     = SHA-256( canonical { chain, network, accountId, payee, amountSats, memoDigest } )
  policyDigest     = SHA-256( canonical policy descriptor )
  transactionHash  = SHA-256( canonical { chain, network, from, plan } )     ← unchanged from V2
  evidenceAnchor   = the evidence head BEFORE this authorisation was recorded
```

```
{
  v: 3,

  // ---- who and what
  vaultId, accountId, subject, proposalId,

  // ---- what was MEANT, separately from what was BUILT
  intentDigest,                     // the human's decision: payee, amount, network
  transactionHash,                  // the exact transaction, as V2
  intentBinding: 'strict' | 'fee-flexible',
  feeCeilingSats,                   // only meaningful when fee-flexible

  // ---- under what rules, readably
  policyVersion, policyDigest,
  policyDescriptor: {               // enough to re-derive the requirement without a database
    rules: [{ upToSats, approvals }],
    approverCount,
    selfApprovalPermitted: false,
  },
  threshold, approvalCount,

  // ---- where
  chain, network,

  // ---- association with the durable record, acyclic
  evidenceAnchor,                   // a head that already existed when this was signed
  evidenceFormat: 'quvault-evidence-1',

  // ---- when, and once
  approvedAt, expiresAt, nonce,

  // ---- who approved
  approvalMethod, approvedBy[], decisionIds[],

  // ---- what a sensor measured, unchanged in spirit from V2
  verification: { approvalProvider, padResult, biometricVerification,
                  scannerAttestation, scannerClass, captureReference,
                  bindingNonce, biometricPolicyVersion, sensorEvidence },

  keyEpoch,
}
```

### Why `intentBinding` is a field and not a default

`strict` means the signature covers the exact transaction: any change, including the fee,
invalidates it. That is V2's behaviour and must remain available, because it is the right
default for a treasury that would rather re-approve than widen anything.

`fee-flexible` means the signature covers the intent plus a **fee ceiling**, and the server may
realise the intent with any transaction paying the same payee the same amount with a fee at or
below the ceiling. The approver sees the ceiling in the statement they approve. Anything outside
it — a different payee, a different amount, a fee above the ceiling — requires fresh
authorisation.

The ceiling is what makes this safe. Without it, "fee-flexible" would authorise an unbounded
transfer of value to miners.

---

## 3. Avoiding the circular dependency

This is the part the brief specifically warns about, and the resolution is a one-line rule:

> **The receipt commits to an evidence head that already existed. The evidence entry commits to
> the receipt. Nothing commits forward.**

```
  entry N-1  ────────────────────────────────┐
     │ hash                                  │
     ▼                                       │
  evidenceAnchor  ──►  RECEIPT  ──► digest ──┤
                                             ▼
                                        entry N  =  authorization.granted
                                        (payload carries receiptDigest + keyId)
                                             │ hash
                                             ▼
                                        entry N+1 …
```

`hash(entry N)` depends on `digest(receipt)`, which depends on `evidenceAnchor`, which is
`hash(entry N-1)`. Every arrow points backwards in time. There is no cycle.

**What this buys.** A reader holding only the receipt can say which evidence log it was made
against and at what point. A reader holding only the log can find the receipt by digest. A
reader holding both can confirm they describe the same event without trusting either producer.

**What it deliberately does not do.** The receipt does not commit to the head *after* the grant,
and must not — that entry does not exist yet when the receipt is signed, and reaching for it is
exactly how the cycle appears.

Note this is a different mechanism from the **checkpoints** already implemented. A checkpoint is
signed *after the fact* over a head, to make a full rewrite detectable. An anchor is signed *at
the time* to associate one receipt with one position in the log. Both are acyclic, for the same
reason, and they are independent.

---

## 4. The distinction that must survive

**Cryptographic authorisation evidence and biometric measurement are different claims, and V3
must keep them as separate fields with separate failure modes.**

| | What it establishes | Who can produce it |
|---|---|---|
| The ML-DSA-65 signature | the owner's key approved this intent, under these rules, against this log | only the holder of the recovery phrase |
| `verification.sensorEvidence` | what a palm sensor measured | only a scanner, and **there is none in this build** |

A valid signature is not a measurement. A measurement is not an authorisation. V3 keeps
`verification` as its own object, keeps `sensorEvidence: 'none'` as a recorded value rather than
an omission, and the structural check must continue to refuse a record claiming a measurement
without the attestation, capture, scanner class and passed verdicts to support it.

**No V3 record may assert `biometricVerified`.** That field was V1's unconditional claim and is
forbidden in V2; it stays forbidden.

---

## 5. Migration

V1 and V2 records exist and must keep verifying. `whatItProves` already reports per-version
capability, and gains rows for V3:

| | V1 | V2 | V3 |
|---|---|---|---|
| transaction | yes | yes | yes |
| policy version | no | yes | yes |
| **readable policy** | no | no | **yes** |
| threshold | no | yes | yes |
| **intent, separately** | no | no | **yes** |
| **evidence association** | no | no | **yes** |
| sensor measurement | never | if measured | if measured |

No historical record becomes stronger. `expected.minVersion` already exists for a caller that
needs V3 guarantees, and the default stays unset so nothing changes under existing callers.

## 6. What must be true before building it

1. **Fee adjustment is an actual requirement.** `fee-flexible` is the only part that changes
   signing semantics, and building it before a treasury needs it adds an authorisation mode
   nobody uses — which is a liability, not a feature. Until then, V3 is V2 plus the policy
   descriptor and the evidence anchor, and `intentBinding` is always `strict`.
2. **The policy descriptor's canonical form is fixed**, because `policyDigest` is taken over it
   and changing the serialisation later invalidates every receipt.
3. **The evidence format version is stable.** The anchor names `quvault-evidence-1`; a future
   format needs the anchor to say which.
4. Phase C is done, or `accountId` and `subject` are known to be sufficient without an
   organisation identifier. See `TENANT-ISOLATION-DESIGN.md`.
