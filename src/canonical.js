/*
 * One canonical representation of a transaction, shared by the server and the browser.
 *
 * Everything downstream refers to the digest of these bytes: the sentence a person reads
 * before they put their palm down, the approval the identity provider signs, the
 * authorisation record QuVault signs with ML-DSA, the plan the browser is allowed to sign,
 * and the check made before broadcasting. If any of them disagree, nothing is signed.
 *
 * This module is deliberately free of Node and of browser APIs: it produces the bytes, and
 * each side hashes them with what it has. That is what keeps the two sides in agreement.
 */

/** Sorted keys, no whitespace: the same value always produces the same bytes. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort()
      .map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * The exact movement of coins. Inputs are sorted, so two plans that spend the same coins
 * in a different order are the same transaction and hash the same way.
 */
export function canonicalTransaction({ chain, network, from, plan }) {
  return {
    v: 1,
    chain,
    network,
    from,
    inputs: [...plan.inputs]
      .map(input => ({ txid: input.txid, index: input.index, value: input.value }))
      .sort((a, b) => (a.txid === b.txid ? a.index - b.index : a.txid < b.txid ? -1 : 1)),
    outputs: plan.outputs.map(output => ({ address: output.address, sats: output.sats })),
    feeSats: plan.feeSats,
  };
}

/** The bytes that get hashed, for whichever side is doing the hashing. */
export const canonicalBytes = transaction => canonicalJson(transaction);

/** Shortened for a screen, never for a comparison. */
export const shortDigest = digest => `${digest.slice(0, 10)}…${digest.slice(-6)}`;
