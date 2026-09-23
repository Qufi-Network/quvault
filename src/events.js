/*
 * Security events.
 *
 * These exist so that a refusal leaves a trace. A transaction that did not match its
 * approval, an authorisation that did not verify, a legacy vault being emptied — each of
 * those is worth knowing about afterwards, and none of them currently says anything.
 *
 * The hard rule is that an event is a record of a decision, not a copy of what the decision
 * was about. So the emitter does not take an object and log it: it takes named fields from a
 * fixed list, and anything not on that list is dropped rather than printed. A field that is
 * on the list is still length-capped, and any value that looks like a recovery phrase or a
 * long run of hex is replaced before it reaches the log.
 *
 * Dropping rather than throwing is deliberate. An event is a side effect of a security
 * decision; it must never be able to change the outcome of that decision or fail the request
 * that produced it.
 */

export const EVENT = {
  SCANNER_UNAVAILABLE: 'scanner.unavailable',
  PAD_FAILURE: 'scanner.pad_failure',
  BIOMETRIC_FAILURE: 'scanner.biometric_failure',
  AUTHORIZATION_FAILURE: 'authorization.failure',
  DIGEST_MISMATCH: 'transaction.digest_mismatch',
  SIGNING_ATTEMPT: 'signing.attempt',
  SIGNING_SUCCESS: 'signing.success',
  SIGNING_REJECTED: 'signing.rejected',
  MIGRATION: 'custody.migration',
};

/**
 * The only field names an event may carry.
 *
 * Every one of these is either an opaque identifier, a public value that is already on a
 * public chain, or a short reason written by this codebase. None of them is, or can contain,
 * key material. Adding to this list is a security decision, not a convenience.
 */
const ALLOWED = new Set([
  'operationId',    // opaque
  'userId',         // opaque, per-application
  'vaultId',        // a Bitcoin address; public by definition
  'accountId',      // 'bitcoin', 'ethereum', …
  'address',        // public
  'txid',           // public once broadcast
  'transactionHash', // the canonical digest; a hash, not the transaction
  'digestExpected', // both sides of a mismatch, so it can be investigated
  'digestOffered',
  'custody',        // 'client' or 'server'
  'kind',           // the operation kind
  'network',
  'chain',
  'reason',         // written here, never user or remote input
  'outcome',
  'keyEpoch',
  'scannerClass',
  'provider',
  'captureReference',
  'sessionId',
  'isolation',      // which signing boundary was used
  'sats',           // an amount; already visible on the chain
]);

const MAX_VALUE = 120;

/** Twelve lowercase words in a row is a recovery phrase however it got here. */
const PHRASE = /(?:\b[a-z]{3,8}\b[ \t]+){11}\b[a-z]{3,8}\b/;
/** A long run of hex or base64 is key-shaped; a txid or digest is named and allowed above. */
const KEY_SHAPED = /[0-9a-fA-F]{96,}|[A-Za-z0-9+/_-]{120,}/;

/**
 * Reduces one value to something safe to write down.
 *
 * Numbers and booleans pass through. Strings are checked for the two shapes that mean "this
 * is a secret that reached here by mistake", then truncated. Anything else becomes its type
 * name, because an object in a log line is an object whose fields nobody vetted.
 */
function scrub(value) {
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') return `[${typeof value}]`;
  if (PHRASE.test(value)) return '[redacted: phrase-shaped]';
  if (KEY_SHAPED.test(value)) return '[redacted: key-shaped]';
  return value.length > MAX_VALUE ? `${value.slice(0, MAX_VALUE)}…` : value;
}

/** Keeps only allowed names, and scrubs what is left. Never throws. */
export function redact(fields) {
  const out = {};
  if (!fields || typeof fields !== 'object') return out;
  for (const [key, value] of Object.entries(fields)) {
    if (!ALLOWED.has(key)) continue;
    const safe = scrub(value);
    if (safe !== null) out[key] = safe;
  }
  return out;
}

export const ALLOWED_EVENT_FIELDS = Object.freeze([...ALLOWED]);

/**
 * Builds the emitter the application uses.
 *
 * `sink` receives one flat object per event. The default writes a single line through the
 * app's own logger, which is what makes these visible in a deployment without adding a
 * dependency on anything.
 */
export function createSecurityLog({ log = console, now = () => Math.floor(Date.now() / 1000), sink } = {}) {
  const emit = (event, fields = {}) => {
    try {
      const record = { event, at: now(), ...redact(fields) };
      if (sink) sink(record);
      else log.log(`security ${event} ${JSON.stringify(record)}`);
      return record;
    } catch {
      // An event must never be able to fail the decision that produced it.
      return null;
    }
  };
  return {
    emit,
    ...Object.fromEntries(Object.entries(EVENT).map(([name, event]) => [
      name.toLowerCase().replace(/_([a-z])/g, (_, c) => c.toUpperCase()),
      fields => emit(event, fields),
    ])),
  };
}
