# Veyns palm-evidence token claims

**For the Veyns identity team.** This specifies what Veyns must add to its signed palm-approval
token so that a QuVault authorization receipt can report `sensorEvidence: "measured"` instead of
`sensorEvidence: "none"`.

## Why

QuVault's palm-vein scanner lives entirely on the Veyns side. QuVault never speaks to a scanner —
by deliberate design, nothing in QuVault binds the wallet key to a device (see `src/scanner.js`).
So the only way a receipt can attest to a *measured* palm (live, matched, attested) is for Veyns to
report what its scanner measured, inside the token it already signs.

Today QuVault already:

- sends Veyns the **action digest** (`op.digest`) when it opens a palm request, and
- verifies the returned **ES256 ID token** (against `${issuer}/jwks.json`), checking
  `veyns_action.digest === op.digest`, `request_id`, `request_nonce`, `amr` contains `veyns:palm`,
  `veyns_intent === "action"`, `veyns_presence === true`, `sub`, `exp`, `auth_time`.

The token's only biometric claim is `veyns_presence: true`. With no measurement claims, QuVault
honestly writes `sensorEvidence: "none"` — the receipt proves *account-holder palm approval of this
exact action*, but not a live, matched, attested palm.

## What to add

Add these claims to the **same** decision token Veyns already signs for an approval. They are bound
by the token's existing `request_id` / `request_nonce` / `veyns_action.digest`, so **no new binding
field is required** — QuVault ties the measurement to the transaction itself once it has verified
the palm approved this operation.

| Claim | Type | Values | Meaning |
|---|---|---|---|
| `veyns_pad` | string | `"pass"` \| `"fail"` \| `"not_performed"` | presentation-attack / liveness detection result for this capture |
| `veyns_match` | string | `"pass"` \| `"fail"` \| `"not_performed"` | palm-vein biometric match against the enrolled template |
| `veyns_scanner_class` | string | opaque class id, e.g. `"veyns-pv1"` | the **class** of scanner hardware — never a serial number |
| `veyns_capture` | string | opaque id, unique per presentation | names the single palm presentation this token is about |
| `veyns_attestation` | string | base64url / JWS | a signature attesting a real Veyns scanner performed this capture (see below) |

All five must describe the **same capture** that produced this approval, carried in the **same**
signed token. No extra round-trip, no second token.

## The rules QuVault enforces

QuVault maps the claims to its evidence object and marks a receipt `sensorEvidence: "measured"`
**only when every one of these holds** (see `evidenceIsUsable` in `src/scanner.js`):

- `veyns_pad === "pass"`
- `veyns_match === "pass"`
- `veyns_attestation` is present
- `veyns_scanner_class` is present
- `veyns_capture` is present
- the token verified, and `veyns_action.digest === op.digest` (already enforced)

Anything else — a missing claim, `"fail"`, `"not_performed"`, an unknown string, or `true` — yields
`sensorEvidence: "none"`. A placeholder that *says* verified is treated as **not** verified. The
receipt stays valid either way; it simply does not claim a measurement it cannot stand behind.

## The attestation (`veyns_attestation`)

- **Acceptable first version:** a JWS/signature Veyns produces over
  `{ veyns_capture, veyns_scanner_class, veyns_action.digest, auth_time }`. Because the enclosing ID
  token is already ES256-signed and QuVault verifies it, this proves *Veyns* vouches for the capture.
  Its strength is "trust Veyns' attestation."
- **Stronger version (recommended when the hardware supports it):** the **scanner device** signs the
  same payload with a device key whose certificate chains to a Veyns/vendor root a third party can
  check. Then the measurement is provable independently of the ID-token signature. If Veyns can
  expose a device-signed attestation + its certificate chain, say so and QuVault will verify it
  rather than trusting the token alone.

## What must NOT be in the token

- **No biometric data of any kind**: no image, no template, no raw vein features, no match score or
  distance, no entropy figure. QuVault records none of this and must never receive it.
- **No scanner serial number.** A class only — a portable wallet must work across compatible
  scanners, so what is trusted is a class, never one device.
- **No key material**, and nothing that would make a specific device necessary to open a wallet.

## Backward compatibility

- Absent claims → QuVault behaves exactly as today (`sensorEvidence: "none"`). Nothing breaks and no
  historical receipt is reinterpreted.
- The claims are purely additive to the existing token.

## End-to-end, once Veyns emits these

1. User scans their palm in Veyns for this action. Veyns' scanner runs PAD + match, and Veyns signs
   the decision token **with** `veyns_pad`, `veyns_match`, `veyns_scanner_class`, `veyns_capture`,
   `veyns_attestation`.
2. QuVault verifies the token (as today), extracts the five claims, and builds an evidence object
   bound to this operation's `transactionHash`.
3. The evidence rides into the browser's receipt signing; `verificationFrom` fills the receipt's
   `verification` block, and `sensorEvidence` flips to `"measured"` with `padResult: PASSED`,
   `biometricVerification: PASSED`, the attestation, the scanner class, the capture, and the binding.
4. Anyone verifying the ML-DSA-65 receipt can now see a live, matched, attested palm approved that
   exact transaction.
