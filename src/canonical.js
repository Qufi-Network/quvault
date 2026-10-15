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

/**
 * Sorted keys, no whitespace: the same value always produces the same bytes.
 *
 * It follows `JSON.stringify`'s own rules for values JSON cannot represent — an object
 * property that would serialise to nothing is omitted, an array element becomes null — so a
 * value produces the same bytes before and after it has been through JSON.
 *
 * That property is the point, not a detail. These bytes get signed: a record is canonicalised
 * once when it is signed, and again when somebody verifies it, by which time a database and a
 * network have each round-tripped it and dropped every undefined property on the way. An
 * earlier version emitted the bare token `undefined` instead, which is not JSON at all — so
 * one missing field anywhere upstream produced a signature over bytes nobody could reproduce,
 * and an honest record read later as a forged one. A missing field is now a missing field on
 * both sides, and `undefined` on its own is refused outright rather than digested.
 */
export function canonicalJson(value) {
  const text = canonical(value);
  if (text === undefined) throw new TypeError('There is no canonical form of undefined.');
  return text;
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(item => canonical(item) ?? 'null').join(',')}]`;
  if (value && typeof value === 'object') {
    const pairs = [];
    for (const key of Object.keys(value).sort()) {
      const text = canonical(value[key]);
      if (text !== undefined) pairs.push(`${JSON.stringify(key)}:${text}`);
    }
    return `{${pairs.join(',')}}`;
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
