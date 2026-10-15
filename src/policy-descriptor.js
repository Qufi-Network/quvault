/*
 * The canonical policy descriptor: enough of a policy to re-derive what it required, readable,
 * and committed to by a digest.
 *
 * WHY THIS IS ITS OWN MODULE, AND WHY IT IS CAREFUL.
 *
 * `policies.digest` is taken over exactly the bytes this module produces, the `policies` rows
 * are immutable, and a future authorisation receipt will name the same digest. So the moment
 * the first row is written the serialisation is frozen: change a field name, add a field,
 * reorder a nested array or treat an absent value differently, and every digest written before
 * the change stops matching the descriptor it was taken over — with no migration available,
 * because the rows cannot be rewritten.
 *
 * That is not a hypothetical class of bug here. The preceding phase fixed `canonicalJson`
 * emitting the bare token `undefined`, which is not JSON, so a record with one absent field
 * hashed one way when it was signed and another after a database had round-tripped it.
 *
 * Hence `checkDescriptorStability`, which the v22 migration runs BEFORE it persists any digest.
 * It is a guard, not a test: if the canonical form has moved, the migration refuses to write
 * rather than writing digests nobody can reproduce.
 *
 * It takes its hash function as an argument rather than importing one, for the same reason
 * `src/canonical.js` has no Node or browser APIs in it: the browser will need to compute this
 * digest too, with @noble, and a module that imports `node:crypto` cannot be bundled for it.
 */
import { canonicalJson } from './canonical.js';

export const POLICY_DESCRIPTOR_VERSION = 1;

/** The only two values. Absence is not one of them — see `buildDescriptor`. */
export const SELF_APPROVAL = Object.freeze({ FORBIDDEN: 'forbidden', PERMITTED: 'permitted' });

export const ROLES = Object.freeze(['owner', 'administrator', 'operator', 'approver', 'auditor', 'viewer']);

export class DescriptorError extends Error {}

/**
 * Normalises a policy into the canonical descriptor.
 *
 * Normalising matters more than it looks. `rules` is a ladder, so its order is significant and
 * is preserved. `requiredRoles` is a set, so its order is NOT significant and is sorted — two
 * descriptors that require the same roles in a different order must produce the same digest,
 * and would not if the array were taken as written.
 */
export function buildDescriptor({ rules, selfApproval, approverCount, requiredToChange }) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new DescriptorError('A policy descriptor needs at least one rule.');
  }
  /*
   * The decision behind this check: maker-checker is the institutional default, and the
   * permissive value must never be reachable by omission. A field that fell back to
   * 'permitted' when absent would be a control that disappears whenever somebody forgets it,
   * so an absent or unknown value is refused here rather than defaulted anywhere.
   */
  if (selfApproval !== SELF_APPROVAL.FORBIDDEN && selfApproval !== SELF_APPROVAL.PERMITTED) {
    throw new DescriptorError(
      "A policy descriptor must state selfApproval as 'forbidden' or 'permitted'; it is never defaulted.");
  }
  if (!Number.isInteger(approverCount) || approverCount < 1) {
    throw new DescriptorError('A policy descriptor must count its approvers.');
  }
  if (!Number.isInteger(requiredToChange) || requiredToChange < 1) {
    throw new DescriptorError('A policy descriptor must say how many approvals change it.');
  }

  const cleanRules = rules.map(rule => {
    const limit = rule.upToSats === null || rule.upToSats === undefined ? null : Number(rule.upToSats);
    if (limit !== null && (!Number.isInteger(limit) || limit < 1)) {
      throw new DescriptorError('Each rule limit is a whole number of satoshis, or null for any amount.');
    }
    if (!Number.isInteger(rule.approvals) || rule.approvals < 1) {
      throw new DescriptorError('Each rule needs a whole number of approvals, at least one.');
    }
    const roles = [...new Set(rule.requiredRoles ?? ['approver'])].sort();
    for (const role of roles) {
      if (!ROLES.includes(role)) throw new DescriptorError(`Unknown role in a rule: ${role}`);
    }
    if (roles.length === 0) throw new DescriptorError('A rule must require at least one role.');
    return { upToSats: limit, approvals: rule.approvals, requiredRoles: roles };
  });

  return {
    v: POLICY_DESCRIPTOR_VERSION,
    rules: cleanRules,
    selfApproval,
    approverCount,
    requiredToChange,
  };
}

/**
 * The exact bytes the digest is taken over.
 *
 * One function, used by whoever writes a digest and by whoever checks one, so the two cannot
 * drift apart. Returns a string; the caller hashes it with what it has.
 */
export const descriptorBytes = descriptor => canonicalJson(descriptor);

/* --------------------------------------------------------------- the locked vector */

/**
 * A fixed descriptor and the bytes it must produce. This is the whole point of the stability
 * check: these bytes are a statement about the serialisation, written down, so that a change
 * to it fails loudly instead of silently invalidating every digest already stored.
 *
 * Deliberately exercises the parts that could move: a null limit, a multi-role rule, roles
 * given out of order, and two rules rather than one.
 */
export const REFERENCE_INPUT = Object.freeze({
  rules: [
    { upToSats: 100_000, approvals: 1, requiredRoles: ['approver'] },
    // Roles out of alphabetical order on purpose: normalisation has to sort them.
    { upToSats: null, approvals: 3, requiredRoles: ['owner', 'approver'] },
  ],
  selfApproval: 'forbidden',
  approverCount: 4,
  requiredToChange: 3,
});

export const REFERENCE_BYTES =
  '{"approverCount":4,"requiredToChange":3,"rules":[{"approvals":1,"requiredRoles":["approver"],"upToSats":100000},{"approvals":3,"requiredRoles":["approver","owner"],"upToSats":null}],"selfApproval":"forbidden","v":1}';

/** base64url SHA-256 of REFERENCE_BYTES. Locked; see the note on REFERENCE_BYTES. */
export const REFERENCE_DIGEST = 'ybpUdQCb1EummNK3Hm3abPIuIjY8tPv002pQdNCOy00';

/**
 * Refuses to let a caller proceed if the canonical form of a descriptor has moved.
 *
 * Called by the v22 migration before it writes any digest, and by the test suite. Throws with
 * what changed rather than returning false, because every caller's correct response is to stop.
 *
 * `digestOf(text) -> string` is supplied by the caller: see the module header.
 */
export function checkDescriptorStability(digestOf) {
  if (typeof digestOf !== 'function') {
    throw new DescriptorError('checkDescriptorStability needs a digest function.');
  }
  const descriptor = buildDescriptor(REFERENCE_INPUT);
  const bytes = descriptorBytes(descriptor);

  if (bytes !== REFERENCE_BYTES) {
    throw new DescriptorError(
      'The canonical form of a policy descriptor has changed. Every digest already stored was '
      + 'taken over the old bytes and those rows are immutable, so nothing may be written until '
      + `this is understood.\n  expected: ${REFERENCE_BYTES}\n  produced: ${bytes}`);
  }

  // Valid JSON. The defect this guards against produced a byte string that was not.
  let parsed;
  try {
    parsed = JSON.parse(bytes);
  } catch (error) {
    throw new DescriptorError(`Descriptor bytes are not valid JSON: ${error.message}`);
  }

  // Survives the round trip a database and a network each make of it.
  const roundTripped = descriptorBytes(JSON.parse(JSON.stringify(descriptor)));
  if (roundTripped !== bytes) {
    throw new DescriptorError(
      `A descriptor does not survive a JSON round trip.\n  before: ${bytes}\n  after:  ${roundTripped}`);
  }
  // And again from the bytes themselves, which is the path a verifier takes.
  if (descriptorBytes(parsed) !== bytes) {
    throw new DescriptorError('Re-canonicalising parsed descriptor bytes does not reproduce them.');
  }

  // The order the fields were written in must not matter.
  const shuffled = buildDescriptor({
    requiredToChange: REFERENCE_INPUT.requiredToChange,
    approverCount: REFERENCE_INPUT.approverCount,
    selfApproval: REFERENCE_INPUT.selfApproval,
    rules: REFERENCE_INPUT.rules,
  });
  if (descriptorBytes(shuffled) !== bytes) {
    throw new DescriptorError('The order the descriptor fields were supplied in changed its bytes.');
  }

  const digest = digestOf(bytes);
  if (digest !== REFERENCE_DIGEST) {
    throw new DescriptorError(
      `The policy descriptor digest has changed.\n  expected: ${REFERENCE_DIGEST}\n  produced: ${digest}`);
  }
  // Twice, because a digest function with state would be the worst kind of wrong here.
  if (digestOf(bytes) !== digest) {
    throw new DescriptorError('The digest function is not deterministic.');
  }

  return { bytes, digest };
}
