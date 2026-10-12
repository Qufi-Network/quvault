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
    if (!response.ok) {
      // The status travels with the error. A caller that needs to distinguish "not found" from
      // "something went wrong" must not have to pattern-match an error message to do it.
      throw Object.assign(
        new ChainError(text.trim().slice(0, 200) || `Bitcoin service returned ${response.status}.`),
        { status: response.status },
      );
    }
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

    /*
     * Whether the network has a transaction, for reconciling an uncertain broadcast.
     *
     * A broadcast whose outcome was never recorded leaves the evidence log saying "attempted,
     * outcome unknown". The chain is the authority on what actually happened, so this asks it.
     * A 404 is an answer — not known — rather than a failure, because "the network has never
     * seen this" is exactly what reconciliation needs to distinguish from "we could not ask".
     */
    async transactionStatus(txid) {
      try {
        const status = await call(`/tx/${txid}/status`);
        return { known: true, confirmed: Boolean(status?.confirmed), blockHeight: status?.block_height ?? null };
      } catch (error) {
        if (error instanceof ChainError && error.status === 404) {
          return { known: false, confirmed: false, blockHeight: null };
        }
        /*
         * Could not find out. `null` rather than `false`, and the difference is the whole
         * point: "the network has never seen this" licenses recording a refusal, while "we
         * could not ask" licenses nothing at all and must leave the outcome open.
         */
        return { known: null, confirmed: false, blockHeight: null };
      }
    },
  };
}

/**
 * Bitcoin's market price, read on the server so the wallet page never has to talk to a
 * third party. Cached briefly: the price is background information, not wallet state.
 */
export function createPrices({ apiUrl, fetchImpl = globalThis.fetch, now = () => Math.floor(Date.now() / 1000), ttl = 300 }) {
  const base = apiUrl.replace(/\/$/, '');
  let cache = { at: -Infinity, data: null };

  async function get(path) {
    let response;
    try {
      response = await fetchImpl(`${base}${path}`, { signal: AbortSignal.timeout(12_000) });
    } catch {
      throw new ChainError('The price service is not reachable right now.');
    }
    if (!response.ok) throw new ChainError(`The price service returned ${response.status}.`);
    try {
      return await response.json();
    } catch {
      throw new ChainError('The price service sent an unreadable answer.');
    }
  }

  return {
    async latest() {
      if (cache.data && now() - cache.at < ttl) return cache.data;
      const [current, history] = await Promise.all([get('/v1/prices'), get('/v1/historical-price?currency=USD')]);
      // Keep the long series: the dashboard slices it into day, week, month and year.
      const series = (history.prices || [])
        .filter(point => Number.isFinite(point.USD) && point.USD > 0)
        .map(point => ({ t: point.time, usd: point.USD }))
        .sort((a, b) => a.t - b.t)
        .slice(-3000);
      const dayAgo = series.find(point => point.t >= (series.at(-1)?.t ?? 0) - 86_400)?.usd ?? series[0]?.usd;
      const usd = current.USD ?? series.at(-1)?.usd ?? null;
      cache = { at: now(), data: { usd, at: current.time ?? now(), change24h: dayAgo ? ((usd - dayAgo) / dayAgo) * 100 : null, series } };
      return cache.data;
    },
  };
}
