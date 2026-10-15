# Authorization receipt, version 3 — design

**Design only. Not implemented.** Version 2 remains what the browser signs.

> **E4 is decided: `fee-flexible` is not being built.** Approval binds the exact transaction —
> inputs, outputs, amounts, fee and change — and any material change requires fresh approval.
> `intentBinding` is `'strict'` and a record carrying any other value is **refused, not
> ignored**. §2's `fee-flexible` branch and `feeCeilingSats` are retained below as a documented
> future capability and are not implemented. The cost of this decision, stated plainly: **a
> stuck transaction cannot be fee-bumped without a fresh palm.**
>
> V3 therefore reduces to V2 plus the readable policy descriptor and the evidence anchor. The
> descriptor's canonical form is now fixed by `policies.digest` at migration v22 — *earlier* than
> the first V3 receipt — so §6.2's freeze has a deadline it did not have before. See
> [PHASE-C-SCHEMA-AND-MIGRATION.md](PHASE-C-SCHEMA-AND-MIGRATION.md) §4.

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
  intentBinding: 'strict',          // E4: the ONLY permitted value; anything else is refused
  // feeCeilingSats                 // NOT IMPLEMENTED — future capability, fee-flexible only

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

### Why `intentBinding` is a field at all, now that only one value is permitted

`strict` means the signature covers the exact transaction: any change, including the fee,
invalidates it. That is V2's behaviour, it is **the only value E4 permits**, and it is the right
default for a treasury that would rather re-approve than widen anything.

The field stays, carrying one legal value, for two reasons. A record has to *say* what its
signature binds rather than leave a reader to infer it from the version number; and a later
format that does implement a second mode must not be able to pass as this one. A record with
`intentBinding` absent, or set to anything other than `'strict'`, is refused by the structural
check — **a field that silently accepted an unimplemented mode would be worse than no field.**

**Not implemented, retained as a documented future capability:** `fee-flexible` would mean the
signature covers the intent plus a **fee ceiling**, with the server free to realise that intent
by any transaction paying the same payee the same amount at or below the ceiling. The approver
would see the ceiling in the statement they approve, and a different payee, a different amount or
a fee above the ceiling would require fresh authorisation.

The ceiling is what would make it safe, and it is also the entire risk: missing, defaulted,
unbounded or server-chosen, it turns "flexible on the fee" into "authorised to send an unbounded
amount to miners". That is why it is deferred rather than built cheaply.

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
| **intent, separately** | no | no | **yes** — recorded, never *relaxed* (E4) |
| **evidence association** | no | no | **yes** |
| sensor measurement | never | if measured | if measured |
| fee flexibility | never | never | **never, this release** (E4) |

No historical record becomes stronger. `expected.minVersion` already exists for a caller that
needs V3 guarantees, and the default stays unset so nothing changes under existing callers.

The `intent, separately` row needs its caveat read: V3 records the intent as its own digest so a
reader can see what the human decided apart from how it was realised. Under E4 that is a
**reporting** improvement only — the signature still binds the exact transaction, and the
separate intent digest does not license the server to realise it any other way.

## 6. What must be true before building it

1. ~~Fee adjustment is an actual requirement.~~ **SETTLED (E4): it is not, for this release.**
   `fee-flexible` was the only part that changes signing semantics, and it is deferred. V3 is V2
   plus the policy descriptor and the evidence anchor, and `intentBinding` is always `strict`.
2. **The policy descriptor's canonical form is fixed**, because `policyDigest` is taken over it
   and changing the serialisation later invalidates every receipt.

   **This now has a deadline earlier than V3 itself.** `policies.digest` is written from
   migration v22 over the same canonical descriptor, and those rows are immutable. So the form is
   frozen by the first migrated policy row, not by the first receipt — and a wrong serialisation
   at v22 means every digest written before the discovery is wrong, permanently. The round-trip
   test has to land **with** v22, not with V3.

   Not a hypothetical class of bug in this codebase: the preceding phase fixed a `canonicalJson`
   defect in which an absent field hashed one way when signed and a different way after a
   database round trip, so an honest signature read as a forged one.
3. **The evidence format version is stable.** The anchor names `quvault-evidence-1`; a future
   format needs the anchor to say which.
4. Phase C is done, or `accountId` and `subject` are known to be sufficient without an
   organisation identifier. See `TENANT-ISOLATION-DESIGN.md`. **Still the blocking item** — it is
   answerable only once tenancy exists, which is why tenancy is first.
