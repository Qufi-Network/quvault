/*
 * The words a person approves, held to the transaction they approve.
 *
 * Veyns puts a sentence and some details on the person's phone, and the palm approves exactly
 * those words. The transaction itself is bound only by a hash among the details. So someone able
 * to write this server's database could leave a harmless sentence in place and swap the
 * transaction and its hash underneath it, and the palm would approve something the person never
 * read. These checks close that: every address coins go to, how much goes there, and the network
 * fee must appear in the sentence itself, worked out from the transaction. The palm signer runs
 * them before it signs, and so does the person's own browser.
 *
 * The amounts are written the way the server writes them (toBtc in src/bitcoin.js, format in
 * src/networks.js), and this module is free of node:crypto so the browser runs the same code.
 */

/** How the server writes a Bitcoin amount in a sentence. */
export const btcText = sats => (Number(sats) / 1e8).toFixed(8);

/** How the server writes an EVM amount in a sentence. */
export const unitsText = (amount, decimals = 18) => (Number(amount) / 10 ** decimals).toFixed(Math.min(decimals, 8));

/**
 * Why the approved words do not describe this Bitcoin transaction, or null when they do. Coins
 * going back to `vaultAddress` are change, or a refresh; everything else is a payee.
 */
export function bitcoinWordsProblem({ statement, details, plan, vaultAddress }) {
  const text = String(statement ?? '');
  const outputs = plan?.outputs ?? [];
  const inputs = plan?.inputs ?? [];
  const fee = plan?.feeSats !== undefined
    ? Number(plan.feeSats)
    : inputs.reduce((sum, input) => sum + Number(input.value), 0) - outputs.reduce((sum, output) => sum + Number(output.sats), 0);
  const payees = outputs.filter(output => output.address !== vaultAddress);
  for (const output of payees) {
    if (!text.includes(output.address)) return `the words approved do not name ${output.address}, where coins are going`;
    if (!text.includes(btcText(output.sats))) return `the words approved do not say that ${btcText(output.sats)} tBTC goes to ${output.address}`;
  }
  if (!payees.length) {
    const moved = outputs.reduce((sum, output) => sum + Number(output.sats), 0);
    if (!text.includes(btcText(moved))) return 'the words approved do not say how much moves';
  }
  if (!text.includes(btcText(fee))) return `the words approved do not say the network fee of ${btcText(fee)} tBTC`;
  if (details?.fee_sats !== undefined && Number(details.fee_sats) !== fee) return 'the approved fee is not this transaction’s';
  return null;
}

/**
 * Why the approved words do not describe this token payment, or null. A token's decimals and name
 * come from the token itself, which the palm signer cannot ask, so the sentence also carries every
 * number in the token's own base units, and those are what are checked.
 */
export function evmTokenWordsProblem({ statement, to, token, amount, fee, gasRefund }) {
  const text = String(statement ?? '').toLowerCase();
  if (!text.includes(String(to).toLowerCase())) return 'the words approved do not name the payee';
  if (!text.includes(String(token).toLowerCase())) return 'the words approved do not name the token';
  if (!text.includes(`${amount} base units`)) return 'the words approved do not say the amount';
  if (!text.includes(`${fee} base units`)) return 'the words approved do not say Palm’s fee';
  if (!text.includes(unitsText(gasRefund, 18))) return 'the words approved do not say the network fee';
  return null;
}

/** Why the approved words do not describe this EVM payment, or null when they do. */
export function evmWordsProblem({ statement, to = null, amount = null, fees = null, decimals = 18 }) {
  const text = String(statement ?? '').toLowerCase();
  if (to !== null && !text.includes(String(to).toLowerCase())) return 'the words approved do not name the payee';
  if (amount !== null && !text.includes(unitsText(amount, decimals))) return 'the words approved do not say the amount';
  if (fees !== null && !text.includes(unitsText(fees, decimals))) return 'the words approved do not say the fees';
  return null;
}
