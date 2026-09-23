/*
 * The scanner interface, and the only provider that exists.
 *
 * There is no palm-vein scanner integrated with QuVault. Not a driver, not a protocol, not a
 * vendor SDK, not a device certificate. This file does not change that. What it does is fix
 * the shape of the question — what would a scanner have to tell us, and how would we know it
 * was telling the truth — so that the answer can be filled in once hardware exists, instead
 * of being improvised into the middle of a signing path.
 *
 * The only provider here is the null one, and it reports NOT_AVAILABLE to everything. It has
 * no code path that can return a pass. That is deliberate and it is the point: a placeholder
 * that says "verified" is worse than no scanner at all, because every layer above it then
 * believes something that was never measured.
 *
 * What is NOT in this file, and must not be added until the hardware protocol is known:
 *   - WebUSB, WebHID, serial, or any transport. USB-C is a cable; it is not a security
 *     property and nothing here should be shaped around it.
 *   - any vendor's API surface, invented or guessed at
 *   - USB descriptors, certificates, device identifiers or firmware versions
 *   - feature extraction, template formats, matching, or thresholds
 *   - any number describing biometric entropy
 *
 * THE INVARIANT THIS FILE EXISTS TO PROTECT
 *
 * The wallet's core secret is never bound to a physical scanner. A scanner says what it
 * measured; it does not hold, derive, wrap or gate the key, and swapping to another
 * compatible scanner must not change which wallet a palm opens. Nothing in this module
 * returns key material, accepts key material, or takes part in deriving any. If a future
 * change would make a particular device necessary to open a wallet, that change is wrong.
 *
 * Today's authorisation records are V1 and say `biometricVerified: true` unconditionally.
 * That is a statement about the Veyns palm decision the operation collected, not about a
 * scanner this code spoke to, and it is why V2 exists — see `src/authorization.js`.
 */

/** Every answer a provider may give. There is no `PASS` that the null provider can reach. */
export const SCANNER = {
  NOT_AVAILABLE: 'NOT_AVAILABLE', // no provider, or no device
  NOT_SUPPORTED: 'NOT_SUPPORTED', // a device that cannot do what was asked
  NOT_PERFORMED: 'NOT_PERFORMED', // asked, but the check did not run
  FAILED: 'FAILED',               // ran, and did not pass
  PASSED: 'PASSED',               // ran, and passed — no provider in this repository returns it
};

/** What a provider claims it can do. The null provider claims nothing. */
export const NO_CAPABILITIES = Object.freeze({
  available: false,
  transport: null,
  presentationAttackDetection: false,
  biometricMatch: false,
  deviceAttestation: false,
  // A class rather than a device: a portable wallet has to work across compatible scanners,
  // so what gets trusted is a class of hardware, never a serial number.
  scannerClass: null,
  reason: 'No palm-vein scanner is integrated with this build.',
});

class ScannerUnavailable extends Error {}
export { ScannerUnavailable };

const unavailable = what => {
  throw new ScannerUnavailable(`${what} is not available: no palm-vein scanner is integrated with this build.`);
};

/**
 * The provider used everywhere, until there is hardware.
 *
 * `connect` and `capture` throw rather than returning an empty success, so a caller that
 * forgets to check `getCapabilities()` fails loudly instead of carrying an empty result
 * forward. The three evidence getters return a NOT_AVAILABLE verdict instead of throwing,
 * because a caller is entitled to ask "what does the scanner say about this?" and be told
 * "nothing" without that being an error.
 */
export function createNullScanner() {
  const verdict = detail => Object.freeze({
    result: SCANNER.NOT_AVAILABLE,
    performed: false,
    provider: 'null',
    scannerClass: null,
    detail,
  });

  return Object.freeze({
    name: 'null',
    /** What scanners are attached. None, and none can be, so the list is empty. */
    discover: async () => [],
    getCapabilities: () => NO_CAPABILITIES,
    connect: () => unavailable('Connecting to a scanner'),
    capture: () => unavailable('Capturing a palm'),
    getPADResult: () => verdict('Presentation-attack detection was never run.'),
    getBiometricResult: () => verdict('No palm was matched by a scanner.'),
    getAttestation: () => verdict('No scanner signed an attestation.'),
  });
}

/*
 * The capture identifier.
 *
 * A real provider would return one of these from `capture()`: an opaque handle naming one
 * presentation of one palm, which the PAD verdict, the match verdict and the attestation all
 * refer to. It carries no biometric material, so it is safe to put in an authorisation
 * record, a log line or a receipt — which is the point, because without it three verdicts
 * from three different moments could be assembled into one record that describes none of them.
 *
 * `sessionId` groups captures that belong to the same interaction; `captureReference` names
 * the single presentation.
 */
export const CAPTURE_SHAPE = Object.freeze({
  sessionId: 'opaque, per interaction',
  captureReference: 'opaque, per presentation',
  capturedAt: 'seconds since the epoch',
  scannerClass: 'a class of compatible hardware, never a serial number',
});

/**
 * Checks that something claiming to be a provider has the whole interface, so a partial
 * implementation is caught where it is installed rather than halfway through a spend.
 */
const REQUIRED = ['discover', 'getCapabilities', 'connect', 'capture', 'getPADResult', 'getBiometricResult', 'getAttestation'];

/**
 * Names a provider must NOT have.
 *
 * A scanner that can unwrap, derive or hold a key is not a sensor, and the wallet would then
 * be bound to it. Refused where the provider is installed rather than discovered later.
 */
const FORBIDDEN = ['deriveKey', 'unwrapKey', 'getKey', 'getPrivateKey', 'getSecret', 'getTemplate', 'getImage', 'getRawCapture'];

export function assertProvider(provider) {
  const missing = REQUIRED.filter(name => typeof provider?.[name] !== 'function');
  if (missing.length) throw new Error(`A scanner provider is missing: ${missing.join(', ')}.`);
  const exposed = FORBIDDEN.filter(name => provider[name] !== undefined);
  if (exposed.length) {
    throw new Error(`A scanner must not touch key or biometric material: ${exposed.join(', ')}.`);
  }
  return provider;
}

/**
 * The provider this process uses. There is one, and it is the null one.
 *
 * When a real provider is written it is registered here, behind a capability check, and
 * nothing above this line has to learn a vendor's name.
 */
export function createScanner({ provider } = {}) {
  return assertProvider(provider ?? createNullScanner());
}

/**
 * Is this evidence good enough to carry a signature?
 *
 * Every question is asked separately and every answer must be an explicit PASSED. A missing
 * field is not a pass, an unknown string is not a pass, and `true` is not a pass — the only
 * thing that counts is a provider having run the check and said so.
 */
export function evidenceIsUsable(evidence) {
  const reasons = [];
  const passed = part => evidence?.[part]?.result === SCANNER.PASSED && evidence[part].performed === true;

  if (!evidence || typeof evidence !== 'object') return { ok: false, reasons: ['there is no scanner evidence'] };
  if (!passed('pad')) reasons.push('presentation-attack detection did not pass');
  if (!passed('biometric')) reasons.push('no scanner reported a biometric match');
  if (!passed('attestation')) reasons.push('no scanner signed an attestation');
  if (!evidence.scannerClass) reasons.push('the evidence names no scanner class');
  if (!evidence.captureReference) reasons.push('the evidence names no capture');
  // The attestation has to be about *this* transaction, or it is a recording of another one.
  if (!evidence.bindingNonce) reasons.push('the evidence is not bound to a transaction');
  return reasons.length ? { ok: false, reasons } : { ok: true, reasons: [] };
}

/** One line for a receipt or a log, saying what was actually measured. */
export const describeEvidence = evidence => {
  const usable = evidenceIsUsable(evidence);
  return usable.ok
    ? `scanner ${evidence.scannerClass}: PAD passed, match passed, attestation signed`
    : `no scanner evidence (${usable.reasons.join('; ')})`;
};
