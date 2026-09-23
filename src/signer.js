/*
 * The signing boundary.
 *
 * A Signer is asked for a signature and gives back a signature. It is never asked for a key,
 * and the interface has no method that could return one — that absence is the whole point,
 * and `assertSigner` below enforces it rather than leaving it to good intentions.
 *
 * WHAT THIS IS NOT
 *
 * QuVault's only signer today runs in browser JavaScript, in the same realm as the page. It
 * is not a TEE, not a Secure Element, not an HSM and not a hardware wallet. Anything with
 * script execution in that origin — an XSS, a malicious extension with host permissions, a
 * compromised dependency in the bundle — is inside the boundary, not outside it, and the
 * boundary does not stop it. Every signer therefore has to declare its isolation level, and
 * the honest answer for this build is `none:browser-javascript`.
 *
 * Declaring it in the type system is what stops the interface from being used later as
 * evidence that key material is protected by hardware. It is not. What the interface buys
 * today is narrower and still worth having: application code asks for signatures instead of
 * holding keys, so when a real isolated signer exists it replaces one object rather than
 * every call site.
 */

/**
 * How well separated the key is from the code asking for signatures.
 *
 * Only the first is implemented. The rest are named so a future signer states which one it
 * is, and so nothing can quietly claim a level it has not reached.
 */
export const ISOLATION = {
  /** Same realm as the page. Script in this origin can reach the key. IMPLEMENTED. */
  BROWSER_JAVASCRIPT: 'none:browser-javascript',
  /** Key held by the operating system's keystore. NOT IMPLEMENTED. */
  OS_KEYSTORE: 'os-keystore',
  /** Key held in a secure element on the device. NOT IMPLEMENTED. */
  SECURE_ELEMENT: 'secure-element',
  /** Key held inside a trusted execution environment. NOT IMPLEMENTED. */
  TEE: 'tee',
  /** Key held by a separate signing device the user confirms on. NOT IMPLEMENTED. */
  HARDWARE_WALLET: 'hardware-wallet',
  /** Key held in a hardware security module. NOT IMPLEMENTED. */
  HSM: 'hsm',
};

/** Which of the above this build actually has. One entry, and it is the weakest one. */
export const IMPLEMENTED_ISOLATION = [ISOLATION.BROWSER_JAVASCRIPT];

/** Plain words for a receipt or a report, with no room to imply hardware that is not there. */
export function describeIsolation(level) {
  switch (level) {
    case ISOLATION.BROWSER_JAVASCRIPT:
      return 'Signing runs in browser JavaScript, in the same realm as the page. '
        + 'Script running in this origin can reach the key while it is in use. '
        + 'This is not a secure element, a TEE, an HSM or a hardware wallet.';
    case ISOLATION.OS_KEYSTORE: return 'Not implemented: an operating-system keystore signer.';
    case ISOLATION.SECURE_ELEMENT: return 'Not implemented: a secure-element signer.';
    case ISOLATION.TEE: return 'Not implemented: a trusted-execution-environment signer.';
    case ISOLATION.HARDWARE_WALLET: return 'Not implemented: a separate signing device.';
    case ISOLATION.HSM: return 'Not implemented: a hardware security module.';
    default: return 'Unknown isolation level; treat as no isolation.';
  }
}

/* --------------------------------------------------------------- the interface */

const REQUIRED = ['signTransaction', 'signMessage', 'getPublicKey'];

/**
 * Names that must NOT exist on a signer.
 *
 * A signer with any of these is not a signing boundary, it is a key store with extra steps.
 * Checked at construction so the mistake is caught where the signer is built rather than at
 * the call site that eventually uses it.
 */
const FORBIDDEN = [
  'getPrivateKey', 'privateKey', 'exportKey', 'exportPrivateKey', 'getSecretKey', 'secretKey',
  'getMnemonic', 'mnemonic', 'getSeed', 'seed', 'unlock', 'reveal', 'dump',
];

export class SignerError extends Error {}

/**
 * Checks a signer has the whole interface, none of the forbidden surface, and an isolation
 * level it is honest about.
 */
export function assertSigner(signer) {
  const missing = REQUIRED.filter(name => typeof signer?.[name] !== 'function');
  if (missing.length) throw new SignerError(`A signer is missing: ${missing.join(', ')}.`);

  const exposed = FORBIDDEN.filter(name => signer[name] !== undefined);
  if (exposed.length) {
    throw new SignerError(`A signer must not expose key material: ${exposed.join(', ')}.`);
  }
  if (!Object.values(ISOLATION).includes(signer.isolation)) {
    throw new SignerError('A signer must declare an isolation level from ISOLATION.');
  }
  if (!IMPLEMENTED_ISOLATION.includes(signer.isolation)) {
    throw new SignerError(
      `This build has no ${signer.isolation} signer. Claiming that isolation without implementing it `
      + 'would misrepresent where the key is held.');
  }
  return signer;
}

/**
 * What a signer is allowed to hand back.
 *
 * Anything a caller receives passes through here, so a signer that returned key material by
 * accident — a stray field on a result object — is stripped rather than forwarded. The set is
 * deliberately small: a signature, a PSBT, what the transaction is, and nothing else.
 */
const ALLOWED_RESULT = ['hex', 'txid', 'psbt', 'signature', 'publicKey', 'signingKey', 'authorization', 'digest', 'network', 'chain'];

export function sealResult(result) {
  if (result === null || typeof result !== 'object') return result;
  const out = {};
  for (const key of Object.keys(result)) {
    if (ALLOWED_RESULT.includes(key)) out[key] = result[key];
  }
  return out;
}

export const SIGNER_RESULT_FIELDS = Object.freeze([...ALLOWED_RESULT]);
