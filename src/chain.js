/*
 * Bitcoin network data, read from a mempool.space-compatible API (testnet4 by default).
 * The wallet never runs a node: it reads balances, coins and fees, and posts signed transactions.
 */
export class ChainError extends Error {}

export function createChain({ apiUrl, fetchImpl = globalThis.fetch }) {
  const base = apiUrl.replace(/\/$/, '');

  async function call(path, { method = 'GET', body, asText = false } = {}) {
    let response;
    try {
      response = await fetchImpl(`${base}${path}`, {
        method,
        ...(body === undefined ? {} : { body, headers: { 'content-type': 'text/plain' } }),
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      throw new ChainError('The Bitcoin network service is not reachable right now.');
    }
    const text = await response.text();
    if (!response.ok) throw new ChainError(text.trim().slice(0, 200) || `Bitcoin service returned ${response.status}.`);
    if (asText) return text.trim();
    try {
      return JSON.parse(text);
    } catch {
      throw new ChainError('The Bitcoin service sent an unreadable answer.');
    }
  }

  return {
    explorerTx: txid => `${base.replace(/\/api$/, '')}/tx/${txid}`,
    explorerAddress: address => `${base.replace(/\/api$/, '')}/address/${address}`,

    /** Confirmed and unconfirmed balance in satoshis. */
    async balance(address) {
      const stats = await call(`/address/${address}`);
      const sum = s => (s ? s.funded_txo_sum - s.spent_txo_sum : 0);
      return {
        confirmed: sum(stats.chain_stats),
        pending: sum(stats.mempool_stats),
        txCount: (stats.chain_stats?.tx_count ?? 0) + (stats.mempool_stats?.tx_count ?? 0),
      };
    },

    /** Confirmed coins only: unconfirmed change would make a spend unreliable. */
    async spendableUtxos(address) {
      const utxos = await call(`/address/${address}/utxo`);
      return utxos
        .filter(u => u.status?.confirmed)
        .map(u => ({ txid: u.txid, vout: u.vout, value: u.value, height: u.status.block_height }));
    },

    async history(address, limit = 10) {
      const txs = await call(`/address/${address}/txs`);
      return txs.slice(0, limit).map(tx => {
        const received = tx.vout.filter(o => o.scriptpubkey_address === address).reduce((s, o) => s + o.value, 0);
        const spent = tx.vin.filter(i => i.prevout?.scriptpubkey_address === address).reduce((s, i) => s + i.prevout.value, 0);
        return {
          txid: tx.txid,
          confirmed: Boolean(tx.status?.confirmed),
          at: tx.status?.block_time ?? null,
          deltaSats: received - spent,
          feeSats: tx.fee ?? 0,
        };
      });
    },

    async feeRate() {
      const fees = await call('/v1/fees/recommended');
      return Math.max(1, Math.round(fees.halfHourFee ?? fees.hourFee ?? 1));
    },

    broadcast: rawHex => call('/tx', { method: 'POST', body: rawHex, asText: true }),
  };
}
