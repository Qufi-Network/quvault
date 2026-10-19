/*
 * EVM network data over JSON-RPC, for Ethereum and BSC. The account-chain twin of src/chain.js:
 * the wallet reads a balance, an account nonce, current fees and a token balance, estimates gas,
 * posts a signed transaction, and follows it to a receipt. It never holds a key.
 *
 * Every quantity in and out is a base-10 string of wei (or token base units), never a JS number,
 * for the reason canonical-transfer.js gives: a balance in wei is past Number's safe range.
 */
export class EvmChainError extends Error {}

const ERC20_BALANCE_SELECTOR = '0x70a08231'; // keccak256('balanceOf(address)')[:4]

export function createEvmChain({ rpcUrl, chainId, explorer = null, fetchImpl = globalThis.fetch }) {
  if (!rpcUrl) throw new EvmChainError('An EVM chain needs an RPC URL.');
  let id = 0;

  async function rpc(method, params = []) {
    let response;
    try {
      response = await fetchImpl(rpcUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
        signal: AbortSignal.timeout(20_000),
      });
    } catch {
      throw new EvmChainError('The EVM network service is not reachable right now.');
    }
    const text = await response.text();
    if (!response.ok) {
      throw Object.assign(new EvmChainError(`EVM service returned ${response.status}.`), { status: response.status });
    }
    let body;
    try { body = JSON.parse(text); } catch { throw new EvmChainError('The EVM service sent an unreadable answer.'); }
    if (body.error) {
      // The node's own message is the useful part — a reverted estimate, a nonce gap, a bad tx.
      throw Object.assign(new EvmChainError(String(body.error.message || 'EVM RPC error').slice(0, 200)),
        { code: body.error.code });
    }
    return body.result;
  }

  const big = hex => (hex && hex !== '0x' ? BigInt(hex) : 0n);
  const toQuantity = value => `0x${BigInt(value).toString(16)}`;

  return {
    explorerTx: txid => (explorer ? `${explorer}/tx/${txid}` : null),
    explorerAddress: address => (explorer ? `${explorer}/address/${address}` : null),

    /** The configured chain id, for checking the RPC is the chain the wallet expects. */
    async chainId() {
      return big(await rpc('eth_chainId')).toString(10);
    },

    /** Native balance in wei, as a decimal string. */
    async balance(address) {
      return big(await rpc('eth_getBalance', [address, 'latest'])).toString(10);
    },

    /** An ERC-20 balance in the token's base units, as a decimal string. */
    async tokenBalance(token, address) {
      const data = ERC20_BALANCE_SELECTOR + address.replace(/^0x/, '').toLowerCase().padStart(64, '0');
      return big(await rpc('eth_call', [{ to: token, data }, 'latest'])).toString(10);
    },

    /** The next nonce, counting pending transactions so two sends do not collide. */
    async nonce(address) {
      return big(await rpc('eth_getTransactionCount', [address, 'pending'])).toString(10);
    },

    /**
     * EIP-1559 fee suggestion as decimal-string wei: a priority tip from the node and a max fee
     * of baseFee*2 + tip, which survives a base-fee rise over the next few blocks.
     */
    async fees() {
      const [tipHex, block] = await Promise.all([
        rpc('eth_maxPriorityFeePerGas').catch(() => '0x3b9aca00'), // 1 gwei if the node lacks it
        rpc('eth_getBlockByNumber', ['latest', false]),
      ]);
      const tip = big(tipHex);
      const baseFee = big(block?.baseFeePerGas);
      const maxFee = baseFee * 2n + tip;
      return {
        maxPriorityFeePerGas: tip.toString(10),
        maxFeePerGas: maxFee.toString(10),
        baseFeePerGas: baseFee.toString(10),
      };
    },

    /** Gas units a transaction will need, as a decimal string. Throws with the node's reason if it reverts. */
    async estimateGas({ from, to, value = '0', data = '0x' }) {
      const result = await rpc('eth_estimateGas', [{ from, to, value: toQuantity(value), data }]);
      return big(result).toString(10);
    },

    /** Posts a signed raw transaction, returning its hash. */
    async broadcast(rawHex) {
      return rpc('eth_sendRawTransaction', [rawHex]);
    },

    /**
     * The receipt once mined, or null while pending. `status` is '0x1' success, '0x0' revert.
     * Shaped like the Bitcoin reader's confirmation check so the app can treat both the same.
     */
    async receipt(txid) {
      const r = await rpc('eth_getTransactionReceipt', [txid]);
      if (!r) return null;
      return {
        txid,
        confirmed: true,
        success: r.status === '0x1',
        blockNumber: big(r.blockNumber).toString(10),
        gasUsed: big(r.gasUsed).toString(10),
      };
    },
  };
}
