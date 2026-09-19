/*
 * The spending rules.
 *
 * A policy is a list of approvers and a ladder of amount rules: the first rule whose limit
 * covers the amount decides how many palm approvals the spend needs. One approver and one
 * rule is an ordinary personal wallet; more of either makes it a shared one.
 */
export class PolicyError extends Error {}

export const DEFAULT_POLICY = { rules: [{ upToSats: null, approvals: 1 }] };
const MAX_RULES = 6;
const MAX_SATS = 21_000_000 * 1e8;

/** How many approvals a spend of this size needs, and which rule said so. */
export function requiredFor(policy, sats) {
  const rules = policy?.rules?.length ? policy.rules : DEFAULT_POLICY.rules;
  const rule = rules.find(r => r.upToSats === null || sats <= r.upToSats) ?? rules.at(-1);
  return { approvals: rule.approvals, rule };
}

/** Changing the rules needs the strongest quorum the current rules ask for, so they cannot be quietly weakened. */
export const requiredToChange = (policy, memberCount) =>
  Math.min(Math.max(1, ...(policy?.rules ?? DEFAULT_POLICY.rules).map(r => r.approvals)), Math.max(1, memberCount));

/**
 * Checks a proposed policy against the people who can approve for this wallet.
 * Throws PolicyError with a plain message; returns the cleaned policy.
 */
export function validatePolicy(policy, memberCount) {
  const rules = policy?.rules;
  if (!Array.isArray(rules) || rules.length === 0) throw new PolicyError('Add at least one rule.');
  if (rules.length > MAX_RULES) throw new PolicyError(`Use at most ${MAX_RULES} rules.`);

  const cleaned = rules.map((rule, index) => {
    const last = index === rules.length - 1;
    const limit = rule.upToSats === null || rule.upToSats === undefined || rule.upToSats === '' ? null : Number(rule.upToSats);
    const approvals = Number(rule.approvals);
    if (limit !== null && (!Number.isInteger(limit) || limit < 1 || limit > MAX_SATS)) {
      throw new PolicyError('Each limit must be a whole number of satoshis.');
    }
    if (limit === null && !last) throw new PolicyError('Only the last rule can cover any amount.');
    if (!Number.isInteger(approvals) || approvals < 1) throw new PolicyError('Each rule needs at least one approval.');
    if (approvals > memberCount) {
      throw new PolicyError(`A rule asks for ${approvals} approvals but the wallet has ${memberCount} approver${memberCount === 1 ? '' : 's'}.`);
    }
    return { upToSats: limit, approvals };
  });

  if (cleaned.at(-1).upToSats !== null) throw new PolicyError('The last rule must cover any amount: leave its limit empty.');
  for (let i = 1; i < cleaned.length; i++) {
    const previous = cleaned[i - 1].upToSats;
    const limit = cleaned[i].upToSats;
    if (previous === null || (limit !== null && limit <= previous)) throw new PolicyError('Put the rules in order, each limit larger than the one before.');
    if (cleaned[i].approvals < cleaned[i - 1].approvals) throw new PolicyError('Larger amounts cannot need fewer approvals.');
  }
  return { rules: cleaned };
}

const fmt = n => Number(n).toLocaleString('en-US');

/** One line per rule, the way it is shown on the approval screen and signed with the palm. */
export const describePolicy = (policy, members) => [
  `Approvers: ${members.map(m => m.label).join(', ')}`,
  ...(policy.rules.map(rule => (rule.upToSats === null
    ? `Any larger amount: ${rule.approvals} palm approval${rule.approvals === 1 ? '' : 's'}`
    : `Up to ${fmt(rule.upToSats)} sats: ${rule.approvals} palm approval${rule.approvals === 1 ? '' : 's'}`))),
].join(' · ');
