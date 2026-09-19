/*
 * The networks a vault can hold accounts on. Every address comes from the same phrase in the
 * owner's browser; the server only ever stores the address and reads public chain data.
 *
 * Sending is live for Bitcoin. The others receive and report balances today; their signing
 * is the next step, and `canSend` is what the page reads, so nothing pretends otherwise.
 */
import { base32, base58, base58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';

/** Decodes an address and checks what it actually contains, not just how it looks. */
const decodes = (address, decode, check) => {
  try {
    return check(decode(address));
  } catch {
    return false;
  }
};

/** A Stellar account id: version byte, 32-byte key, CRC16-XModem, in base32. */
const strkeyValid = address => decodes(address, base32.decode, body => {
  if (body.length !== 35 || body[0] !== 6 << 3) return false;
  let crc = 0;
  for (const byte of body.subarray(0, 33)) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return body[33] === (crc & 0xff) && body[34] === ((crc >> 8) & 0xff);
});

export const NETWORKS = {
  bitcoin: {
    label: 'Bitcoin', symbol: 'tBTC', chain: 'testnet4', decimals: 8, canSend: true,
    valid: address => /^(tb1|[mn2])[a-zA-HJ-NP-Z0-9]{20,80}$/.test(address),
    explorer: address => `https://mempool.space/testnet4/address/${address}`,
  },
  ethereum: {
    label: 'Ethereum', symbol: 'ETH', chain: 'sepolia', decimals: 18, canSend: false,
    valid: address => /^0x[0-9a-fA-F]{40}$/.test(address),
    explorer: address => `https://sepolia.etherscan.io/address/${address}`,
    rpc: 'https://ethereum-sepolia-rpc.publicnode.com',
  },
  tron: {
    label: 'Tron', symbol: 'TRX', chain: 'nile', decimals: 6, canSend: false,
    // The checksum and the 0x41 prefix, not just the shape of the string.
    valid: address => /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address)
      && decodes(address, base58check(sha256).decode, body => body.length === 21 && body[0] === 0x41),
    explorer: address => `https://nile.tronscan.org/#/address/${address}`,
    rpc: 'https://nile.trongrid.io',
  },
  solana: {
    label: 'Solana', symbol: 'SOL', chain: 'devnet', decimals: 9, canSend: false,
    // A Solana address is a 32-byte key in base58; a Tron address is shorter and would
    // otherwise slip through the pattern.
    valid: address => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)
      && decodes(address, base58.decode, key => key.length === 32),
    explorer: address => `https://explorer.solana.com/address/${address}?cluster=devnet`,
    rpc: 'https://api.devnet.solana.com',
  },
  stellar: {
    label: 'Stellar', symbol: 'XLM', chain: 'testnet', decimals: 7, canSend: false,
    valid: address => /^G[A-Z2-7]{55}$/.test(address) && strkeyValid(address),
    explorer: address => `https://stellar.expert/explorer/testnet/account/${address}`,
    rpc: 'https://horizon-testnet.stellar.org',
  },
};

export const networkList = () => Object.entries(NETWORKS).map(([id, n]) => ({
  id, label: n.label, symbol: n.symbol, chain: n.chain, canSend: n.canSend,
}));

/**
 * Balance in the network's smallest unit, read from a public endpoint.
 * Returns null when the address has never been used or the service is unreachable.
 */
export function createBalances({ fetchImpl = globalThis.fetch, timeout = 12_000 } = {}) {
  const get = async (url, init) => {
    const response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeout) });
    const text = await response.text();
    if (!response.ok && response.status !== 404) throw new Error(`${response.status}`);
    try {
      return { status: response.status, body: JSON.parse(text) };
    } catch {
      return { status: response.status, body: null };
    }
  };
  const rpc = (url, method, params) => get(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });

  return {
    async of(networkId, address) {
      const network = NETWORKS[networkId];
      if (!network) return null;
      try {
        if (networkId === 'ethereum') {
          const { body } = await rpc(network.rpc, 'eth_getBalance', [address, 'latest']);
          return body?.result ? Number(BigInt(body.result)) : 0;
        }
        if (networkId === 'solana') {
          const { body } = await rpc(network.rpc, 'getBalance', [address]);
          return body?.result?.value ?? 0;
        }
        if (networkId === 'tron') {
          const { body } = await get(`${network.rpc}/wallet/getaccount`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ address, visible: true }),
          });
          return body?.balance ?? 0;
        }
        if (networkId === 'stellar') {
          const { status, body } = await get(`${network.rpc}/accounts/${address}`);
          if (status === 404) return 0; // not funded yet
          const native = (body?.balances || []).find(b => b.asset_type === 'native');
          return native ? Math.round(Number(native.balance) * 10 ** network.decimals) : 0;
        }
        return null; // bitcoin has its own reader
      } catch {
        return null;
      }
    },
  };
}

/** Human amount for display, e.g. 12345678 sats -> "0.12345678". */
export const format = (amount, networkId) => {
  const decimals = NETWORKS[networkId]?.decimals ?? 8;
  return (Number(amount) / 10 ** decimals).toFixed(Math.min(decimals, 8));
};
