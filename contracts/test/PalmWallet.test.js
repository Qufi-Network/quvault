/*
 * PalmWallet on a local Ethereum chain. The palm signatures here come from Palm's own palm
 * signer (src/palm-signer.js) given real ES256 palm decisions, the digests and every call from
 * src/palm-wallet.js, and wallets are deployed the way the app deploys them, through the CREATE2
 * proxy, so these tests check that the off-chain code and the contract agree on every byte.
 *
 * The attacks an independent audit found against the first version are replayed at the end, and
 * must all fail now.
 */
const { expect } = require('chai');
const { ethers } = require('hardhat');
const crypto = require('node:crypto');

const ISSUER = 'https://issuer.test';
const AUDIENCE = 'palm-test';
const DAY = 24 * 3600;
// Arachnid's deterministic deployment proxy, as it sits at 0x4e59…956c on Sepolia and BSC testnet.
const PROXY = '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3';

let pw;
let signerModule;
let relayer;
let actionDigest;
let words;
before(async () => {
  pw = await import('../../src/palm-wallet.js');
  signerModule = await import('../../src/palm-signer.js');
  relayer = await import('../../src/palm-relayer.js');
  ({ actionDigest } = await import('../../src/veyns.js'));
  words = await import('../../src/approval-words.js');
  await ethers.provider.send('hardhat_setCode', [pw.DEPLOYER, PROXY]);
});

/** Stands in for Veyns: real ES256 decision tokens, signed with a key the palm signer pins. */
function mockVeyns() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1' };
  let serial = 0;
  const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const decision = (sub, action) => {
    const at = Math.floor(Date.now() / 1000);
    const input = `${b64({ alg: 'ES256', kid: 'k1', typ: 'JWT' })}.${b64({
      iss: ISSUER, aud: AUDIENCE, sub, iat: at, exp: at + 300, auth_time: at,
      veyns_intent: 'action', veyns_presence: true, amr: ['veyns:palm'],
      request_id: `req-${++serial}`, request_nonce: `n-${serial}`,
      veyns_action: { statement: action.statement, digest: actionDigest(action.statement, action.details) },
    })}`;
    return `${input}.${crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  };
  return { jwk, decision };
}

/** The call reverts with the contract's custom error, and nothing else counts. */
async function reverts(promise, contract, name) {
  try {
    const tx = await promise;
    if (tx?.wait) await tx.wait();
  } catch (error) {
    const data = error.data ?? error.info?.error?.data ?? error.error?.data;
    let parsed = null;
    try { parsed = contract.interface.parseError(data); } catch { parsed = null; }
    if (parsed?.name === name) return;
    throw new Error(`expected ${name}, got ${parsed?.name ?? error.shortMessage ?? error.message}`);
  }
  throw new Error(`expected ${name}, but it did not revert`);
}

const now = async () => (await ethers.provider.getBlock('latest')).timestamp;
const later = async seconds => { await ethers.provider.send('evm_increaseTime', [seconds]); await ethers.provider.send('evm_mine', []); };
const byAddress = (a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1);

/**
 * A Palm Wallet built the app's way: `count` signers with keys the browser's signing code uses,
 * the real palm signer (or, with `palmKey`, a raw key the test signs with directly), deployed
 * through the CREATE2 proxy at the address src/palm-wallet.js promised, and funded.
 */
async function built({ count = 1, threshold = 1, days = 30, fund = ethers.parseEther('5'), palmKey = null } = {}) {
  const [payer] = await ethers.getSigners();
  const veyns = mockVeyns();
  const palm = signerModule.createPalmSigner({ seed: crypto.randomBytes(32), issuer: ISSUER, audience: AUDIENCE, pinnedKeys: [veyns.jwk] });
  const vaultId = `vault-${crypto.randomBytes(4).toString('hex')}`;
  const people = Array.from({ length: count }, (_, i) => {
    const key = crypto.randomBytes(32);
    return { key, address: pw.addressOfKey(key), sub: `sub-${i}` };
  }).sort(byAddress);
  const palmAddress = palmKey ? pw.addressOfKey(palmKey) : palm.palmAddressFor(vaultId);
  const params = pw.walletParams({ signers: people.map(p => p.address), threshold, palmSigner: palmAddress, recoveryDays: days });
  const salt = pw.walletSalt(vaultId);
  const address = pw.walletAddressOf(params, salt);
  await (await payer.sendTransaction({ to: pw.DEPLOYER, data: pw.deployCallOf(params, salt) })).wait();
  const wallet = await ethers.getContractAt('PalmWallet', address);
  if (fund) await (await payer.sendTransaction({ to: address, value: fund })).wait();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  return { payer, veyns, palm, palmKey, vaultId, people, wallet, address, chainId, threshold, params };
}

/** A payment as the app makes one: Palm's 0.1% fee, a network fee refund, a two hour deadline. */
async function payment(ctx, { to, amount, token = pw.NATIVE, feeTo = null, gasRefund = '0', refundTo = null, nonce = null, deadline = null, fee = null }) {
  return pw.normalTransfer({
    token, to, amount: String(amount),
    fee: fee ?? (BigInt(amount) / 1000n).toString(), feeTo: feeTo ?? ctx.payer.address,
    gasRefund: String(gasRefund), refundTo: refundTo ?? ctx.payer.address, deadline: String(deadline ?? (await now()) + 7200),
    nonce: String(nonce ?? await ctx.wallet.nonce()),
  });
}

/** What the app puts in front of a person, and the palm signer's signature for it. */
function approve(ctx, transfer, { approvers = ctx.people.slice(0, ctx.threshold).map(p => p.sub), tweak = {} } = {}) {
  const t = pw.normalTransfer(transfer);
  const details = {
    action: 'withdraw', network: 'ethereum', wallet: ctx.address, to: t.to,
    token: t.token === pw.NATIVE ? 'native' : t.token, amount_units: t.amount,
    palm_fee_units: t.fee, palm_fee_to: t.feeTo, network_fee_units: t.gasRefund, network_fee_to: t.refundTo, chain_id: String(ctx.chainId),
    transaction_hash: pw.evmTransferDigest({ chainId: ctx.chainId, wallet: ctx.address, transfer: t }),
    ...tweak,
  };
  const fees = (BigInt(t.fee) + BigInt(t.gasRefund)).toString();
  const statement = t.token === pw.NATIVE
    ? `Send ${words.unitsText(t.amount)} ETH to ${t.to}, plus ${words.unitsText(fees)} ETH in fees`
    : `Send ${t.amount} base units of token ${t.token} to ${t.to}, plus Palm fee ${t.fee} base units and network fee ${words.unitsText(t.gasRefund)} ETH`;
  const action = { statement, details };
  return ctx.palm.signEvmTransfer({
    vaultId: ctx.vaultId,
    wallet: { address: ctx.address, chainId: ctx.chainId, threshold: ctx.threshold, signerSubs: ctx.people.map(p => p.sub) },
    transfer: t, action, decisions: approvers.map(sub => ctx.veyns.decision(sub, action)),
  });
}

function approveRefresh(ctx, refresh, approvers = ctx.people.slice(0, ctx.threshold).map(p => p.sub)) {
  const r = pw.normalRefresh(refresh);
  const details = {
    action: 'refresh the wallet', wallet: ctx.address, chain_id: String(ctx.chainId), network_fee_units: r.gasRefund, network_fee_to: r.refundTo,
    transaction_hash: pw.evmRefreshDigest({ chainId: ctx.chainId, wallet: ctx.address, refresh: r }),
  };
  const action = { statement: `Refresh my Ethereum Palm Wallet, network fee ${words.unitsText(r.gasRefund)} ETH`, details };
  return ctx.palm.signEvmRefresh({
    vaultId: ctx.vaultId,
    wallet: { address: ctx.address, chainId: ctx.chainId, threshold: ctx.threshold, signerSubs: ctx.people.map(p => p.sub) },
    refresh: r, action, decisions: approvers.map(sub => ctx.veyns.decision(sub, action)),
  });
}

const digestOf = (ctx, transfer) => pw.eip712TransferDigest({ chainId: ctx.chainId, wallet: ctx.address, transfer });
const signersSign = (people, digest) => [...people].sort(byAddress).map(p => pw.signDigest(digest, p.key));
const send = (ctx, data, from = ctx.payer) => from.sendTransaction({ to: ctx.address, data, gasLimit: 500_000 });

describe('PalmWallet v2', () => {
  it('lands at the address the app promised, and agrees with the app on every digest', async () => {
    const ctx = await built();
    expect(await ethers.provider.getBalance(ctx.address)).to.equal(ethers.parseEther('5'));
    expect(await ctx.wallet.palmSigner()).to.equal(ethers.getAddress(ctx.palm.palmAddressFor(ctx.vaultId)));
    const t = await payment(ctx, { to: ctx.payer.address, amount: 1_000_000 });
    const onChain = await ctx.wallet.transferDigest([t.token, t.to, t.amount, t.fee, t.feeTo, t.gasRefund, t.refundTo, t.deadline], t.nonce);
    expect(onChain).to.equal(`0x${Buffer.from(digestOf(ctx, t)).toString('hex')}`);
    const r = pw.normalRefresh({ gasRefund: '7', refundTo: ctx.payer.address, deadline: '99', nonce: '3' });
    expect(await ctx.wallet.refreshDigest(7n, ctx.payer.address, 99n, 3n)).to.equal(`0x${Buffer.from(pw.eip712RefreshDigest({ chainId: ctx.chainId, wallet: ctx.address, refresh: r })).toString('hex')}`);
    const rec = { token: pw.NATIVE, to: ctx.payer.address, amount: '5', deadline: '9', nonce: '1' };
    expect(await ctx.wallet.recoveryDigest(rec.token, rec.to, 5n, 9n, 1n)).to.equal(`0x${Buffer.from(pw.eip712RecoveryDigest({ chainId: ctx.chainId, wallet: ctx.address, recovery: rec })).toString('hex')}`);
  });

  it('pays the payee, Palm its 0.1%, and the network fee to the gas account the signatures name, not to whoever submits', async () => {
    const ctx = await built();
    const [, frontRunner, feeBox, gasBox] = await ethers.getSigners();
    const to = ethers.Wallet.createRandom().address;
    const t = await payment(ctx, { to, amount: ethers.parseEther('1'), feeTo: feeBox.address, gasRefund: ethers.parseEther('0.01'), refundTo: gasBox.address });
    const { signature } = approve(ctx, t);
    const feeBefore = await ethers.provider.getBalance(feeBox.address);
    const gasBefore = await ethers.provider.getBalance(gasBox.address);
    const runnerBefore = await ethers.provider.getBalance(frontRunner.address);
    // A bot copies the call out of the mempool and submits it first: it pays the gas and earns nothing.
    const receipt = await (await send(ctx, pw.transferCallOf(t, signersSign(ctx.people, digestOf(ctx, t)), signature), frontRunner)).wait();
    expect(await ethers.provider.getBalance(to)).to.equal(ethers.parseEther('1'));
    expect(await ethers.provider.getBalance(feeBox.address) - feeBefore).to.equal(ethers.parseEther('0.001'));
    expect(await ethers.provider.getBalance(gasBox.address) - gasBefore).to.equal(ethers.parseEther('0.01'));
    expect(runnerBefore - await ethers.provider.getBalance(frontRunner.address)).to.equal(receipt.gasUsed * receipt.gasPrice);
    expect(await ctx.wallet.nonce()).to.equal(1n);
  });

  it('refuses the signer alone, and a palm signature from any other key', async () => {
    const ctx = await built();
    const t = await payment(ctx, { to: ctx.payer.address, amount: 1000 });
    const sigs = signersSign(ctx.people, digestOf(ctx, t));
    await reverts(send(ctx, pw.transferCallOf(t, sigs, sigs[0])), ctx.wallet, 'NoPalm');
    await reverts(send(ctx, pw.transferCallOf(t, sigs, pw.signDigest(digestOf(ctx, t), crypto.randomBytes(32)))), ctx.wallet, 'NoPalm');
  });

  it('a palm signature is for one payment: not another amount, payee, fee, refund, deadline, nonce or wallet', async () => {
    const ctx = await built();
    const t = await payment(ctx, { to: ctx.payer.address, amount: 100_000, gasRefund: 5 });
    const { signature } = approve(ctx, t);
    const variants = [
      { ...t, amount: '100001' }, { ...t, to: ethers.Wallet.createRandom().address.toLowerCase() }, { ...t, fee: '99' },
      { ...t, feeTo: ethers.Wallet.createRandom().address.toLowerCase() }, { ...t, gasRefund: '6' },
      { ...t, refundTo: ethers.Wallet.createRandom().address.toLowerCase() },
      { ...t, deadline: String(BigInt(t.deadline) + 1n) },
    ];
    for (const v of variants) await reverts(send(ctx, pw.transferCallOf(v, signersSign(ctx.people, digestOf(ctx, v)), signature)), ctx.wallet, 'NoPalm');
    const other = await built();
    await reverts(send(other, pw.transferCallOf(t, signersSign(other.people, digestOf(other, t)), signature)), other.wallet, 'NoPalm');
    await (await send(ctx, pw.transferCallOf(t, signersSign(ctx.people, digestOf(ctx, t)), signature))).wait();
    await reverts(send(ctx, pw.transferCallOf(t, signersSign(ctx.people, digestOf(ctx, t)), signature)), ctx.wallet, 'NoPalm');
  });

  it('a shared wallet needs that many different signers, in order, plus the palm', async () => {
    const ctx = await built({ count: 3, threshold: 2 });
    const t = await payment(ctx, { to: ctx.payer.address, amount: 1000 });
    const { signature } = approve(ctx, t);
    const d = digestOf(ctx, t);
    const [a, b] = ctx.people;
    await reverts(send(ctx, pw.transferCallOf(t, [pw.signDigest(d, a.key)], signature)), ctx.wallet, 'NotEnoughSigners');
    await reverts(send(ctx, pw.transferCallOf(t, [pw.signDigest(d, a.key), pw.signDigest(d, a.key)], signature)), ctx.wallet, 'NotADistinctSigner');
    await reverts(send(ctx, pw.transferCallOf(t, [pw.signDigest(d, b.key), pw.signDigest(d, a.key)], signature)), ctx.wallet, 'NotADistinctSigner');
    await (await send(ctx, pw.transferCallOf(t, [pw.signDigest(d, a.key), pw.signDigest(d, b.key)], signature))).wait();
  });

  it('sends ERC-20 tokens the same way, Palm\'s fee in the same token', async () => {
    const ctx = await built();
    const token = await (await ethers.getContractFactory('TestToken')).deploy();
    await (await token.mint(ctx.address, 1_000_000n)).wait();
    const [, , feeBox] = await ethers.getSigners();
    const to = ethers.Wallet.createRandom().address;
    const t = await payment(ctx, { to, amount: 500_000, token: await token.getAddress(), feeTo: feeBox.address });
    const { signature } = approve(ctx, t);
    await (await send(ctx, pw.transferCallOf(t, signersSign(ctx.people, digestOf(ctx, t)), signature))).wait();
    expect(await token.balanceOf(to)).to.equal(500_000n);
    expect(await token.balanceOf(feeBox.address)).to.equal(500n);
  });

  it('the palm signer will not sign what a person did not read: payee, amount, fee or its recipient, network fee', async () => {
    const ctx = await built();
    const t = await payment(ctx, { to: ctx.payer.address, amount: 100_000, gasRefund: 5 });
    for (const tweak of [{ to: ethers.Wallet.createRandom().address }, { amount_units: '1' }, { palm_fee_units: '1' },
      { palm_fee_to: ethers.Wallet.createRandom().address }, { network_fee_units: '4' }, { network_fee_to: ethers.Wallet.createRandom().address },
      { token: ethers.Wallet.createRandom().address }]) {
      expect(() => approve(ctx, t, { tweak })).to.throw(signerModule.PalmRefused);
    }
    // And never a fee above 0.1%: the app's encoder refuses to build one, and so does the palm signer.
    expect(() => approve(ctx, { ...t, fee: '101' })).to.throw(/0\.1%/);
    expect(() => ctx.palm.signEvmTransfer({
      vaultId: ctx.vaultId, wallet: { address: ctx.address, chainId: ctx.chainId, threshold: 1, signerSubs: ['sub-0'] },
      transfer: { ...t, fee: '101' }, action: { statement: 'x', details: {} }, decisions: [],
    })).to.throw(signerModule.PalmRefused);
  });

  it('the contract caps Palm\'s fee at 0.1% even with every signature, refuses expired payments and fake tokens', async () => {
    const palmKey = crypto.randomBytes(32);
    const ctx = await built({ palmKey });
    const deadline = String((await now()) + 7200);
    const raw = { token: pw.NATIVE, to: ctx.payer.address, amount: '100000', fee: '101', feeTo: ctx.payer.address, gasRefund: '0', refundTo: ctx.payer.address, deadline, nonce: '0' };
    // Built by hand, because the app's own encoder will not even produce this.
    const iface = ctx.wallet.interface;
    const digest = await ctx.wallet.transferDigest([raw.token, raw.to, raw.amount, raw.fee, raw.feeTo, raw.gasRefund, raw.refundTo, raw.deadline], 0n);
    const sign = key => pw.signDigest(ethers.getBytes(digest), key);
    const data = iface.encodeFunctionData('transfer', [[raw.token, raw.to, raw.amount, raw.fee, raw.feeTo, raw.gasRefund, raw.refundTo, raw.deadline], [sign(ctx.people[0].key)], sign(palmKey)]);
    await reverts(send(ctx, data), ctx.wallet, 'FeeTooHigh');

    const old = await payment(ctx, { to: ctx.payer.address, amount: 1000, deadline: (await now()) - 1 });
    const d = digestOf(ctx, old);
    await reverts(send(ctx, pw.transferCallOf(old, [pw.signDigest(d, ctx.people[0].key)], pw.signDigest(d, palmKey))), ctx.wallet, 'Expired');

    const fake = await payment(ctx, { to: ctx.payer.address, amount: 1000, token: ethers.Wallet.createRandom().address });
    const fd = digestOf(ctx, fake);
    await reverts(send(ctx, pw.transferCallOf(fake, [pw.signDigest(fd, ctx.people[0].key)], pw.signDigest(fd, palmKey))), ctx.wallet, 'NotAToken');
    expect(await ctx.wallet.nonce()).to.equal(0n, 'nothing used a nonce');
  });

  it('recovery opens only after the palm has approved nothing for the delay, and the signers alone then move the coins', async () => {
    const ctx = await built({ days: 30 });
    const thief = ethers.Wallet.createRandom().address;
    const recovery = async () => {
      const r = { token: pw.NATIVE, to: thief, amount: ethers.parseEther('5').toString(), deadline: String((await now()) + 3600), nonce: String(await ctx.wallet.nonce()) };
      return pw.recoverCallOf(r, signersSign(ctx.people, pw.eip712RecoveryDigest({ chainId: ctx.chainId, wallet: ctx.address, recovery: r })));
    };
    await reverts(send(ctx, await recovery()), ctx.wallet, 'NotYetDormant');
    await later(29 * DAY);
    await reverts(send(ctx, await recovery()), ctx.wallet, 'NotYetDormant');
    expect(await ctx.wallet.nonce()).to.equal(0n, 'trying changed nothing');
    await later(2 * DAY);
    await (await send(ctx, await recovery())).wait();
    expect(await ethers.provider.getBalance(thief)).to.equal(ethers.parseEther('5'));
  });

  it('a refresh needs the signers and the palm, refunds its network fee, and closes the recovery path again', async () => {
    const ctx = await built({ days: 30 });
    await later(25 * DAY);
    const r = pw.normalRefresh({ gasRefund: '1000', refundTo: ctx.payer.address, deadline: String((await now()) + 3600), nonce: '0' });
    const d = pw.eip712RefreshDigest({ chainId: ctx.chainId, wallet: ctx.address, refresh: r });
    const { signature } = approveRefresh(ctx, r);
    await reverts(send(ctx, pw.refreshCallOf(r, [], signature)), ctx.wallet, 'NotEnoughSigners');
    await reverts(send(ctx, pw.refreshCallOf(r, signersSign(ctx.people, d), signersSign(ctx.people, d)[0])), ctx.wallet, 'NoPalm');
    await (await send(ctx, pw.refreshCallOf(r, signersSign(ctx.people, d), signature))).wait();
    const opens = await ctx.wallet.recoveryOpensAt();
    expect(opens).to.equal(BigInt(await now()) + BigInt(30 * DAY));
  });

  it('refuses a wallet that could be spent by one signature, or that is set up wrong', async () => {
    const [payer] = await ethers.getSigners();
    const factory = await ethers.getContractFactory('PalmWallet');
    const a = ethers.Wallet.createRandom().address;
    const b = ethers.Wallet.createRandom().address;
    const [lo, hi] = BigInt(a) < BigInt(b) ? [a, b] : [b, a];
    const palm = ethers.Wallet.createRandom().address;
    for (const args of [[[lo, hi], 1, palm, 30 * DAY], [[hi, lo], 2, palm, 30 * DAY], [[lo], 1, lo, 30 * DAY], [[lo], 1, palm, 60], [[lo], 2, palm, 30 * DAY]]) {
      let failed = false;
      try { await factory.connect(payer).deploy(...args); } catch { failed = true; }
      expect(failed, JSON.stringify(args)).to.equal(true);
    }
  });

  it('is built and spent by the gas account exactly as the app does it, coins arriving before it exists', async () => {
    const [payer] = await ethers.getSigners();
    const veyns = mockVeyns();
    const palm = signerModule.createPalmSigner({ seed: crypto.randomBytes(32), issuer: ISSUER, audience: AUDIENCE, pinnedKeys: [veyns.jwk] });
    const vaultId = `vault-${crypto.randomBytes(4).toString('hex')}`;
    const people = Array.from({ length: 3 }, (_, i) => { const key = crypto.randomBytes(32); return { key, address: pw.addressOfKey(key), sub: `sub-${i}` }; }).sort(byAddress);
    const params = pw.walletParams({ signers: people.map(p => p.address), threshold: 2, palmSigner: palm.palmAddressFor(vaultId), recoveryDays: 30 });
    const salt = pw.walletSalt(vaultId);
    const address = pw.walletAddressOf(params, salt);
    await (await payer.sendTransaction({ to: address, value: ethers.parseEther('3') })).wait();

    const gasKey = relayer.relayerKeyFrom(crypto.randomBytes(32).toString('base64'));
    const gasAddress = relayer.relayerAddressOf(gasKey);
    await (await payer.sendTransaction({ to: gasAddress, value: ethers.parseEther('1') })).wait();
    const relayed = async (to, data, gasLimit) => {
      const block = await ethers.provider.getBlock('latest');
      const { raw, txid } = relayer.signRelayed({
        chainId: (await ethers.provider.getNetwork()).chainId.toString(), nonce: String(await ethers.provider.getTransactionCount(gasAddress, 'pending')),
        maxPriorityFeePerGas: '1000000000', maxFeePerGas: (block.baseFeePerGas * 2n + 1000000000n).toString(),
        gasLimit: String(gasLimit), to, value: '0', data,
      }, gasKey);
      expect(await ethers.provider.send('eth_sendRawTransaction', [raw])).to.equal(txid);
      return ethers.provider.getTransactionReceipt(txid); // the local chain mines each transaction at once
    };
    expect((await relayed(pw.DEPLOYER, pw.deployCallOf(params, salt), 3_000_000)).status).to.equal(1);
    const wallet = await ethers.getContractAt('PalmWallet', address);
    expect(await wallet.recoveryDelay()).to.equal(BigInt(30 * DAY));
    expect(BigInt(await ethers.provider.call({ to: address, data: pw.NONCE_CALL }))).to.equal(0n);
    expect(BigInt(await ethers.provider.call({ to: address, data: pw.LAST_ACTIVITY_CALL }))).to.equal(BigInt(await now()));

    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    const ctx = { payer, palm, veyns, vaultId, people, address, chainId, threshold: 2, wallet };
    const to = ethers.Wallet.createRandom().address;
    const t = await payment(ctx, { to, amount: ethers.parseEther('1.25'), feeTo: gasAddress, gasRefund: ethers.parseEther('0.001'), refundTo: gasAddress });
    const { signature } = approve(ctx, t, { approvers: [people[0].sub, people[2].sub] });
    const paid = await relayed(address, pw.transferCallOf(t, signersSign([people[0], people[2]], digestOf(ctx, t)), signature), 300_000);
    expect(paid.status).to.equal(1);
    expect(await ethers.provider.getBalance(to)).to.equal(ethers.parseEther('1.25'));
  });
});

describe('PalmWallet v2 recovery, as an heir does it', () => {
  it('an heir with nothing but the twelve words recovers through the browser’s own signing code, once the wallet is dormant', async () => {
    const client = await import('../../client/wallet.js');
    const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const signerKey = client.cosignerFrom(phrase, 3).privateKey; // the signer's key for this vault is on branch 3
    const [payer] = await ethers.getSigners();
    const palmKey = crypto.randomBytes(32);
    const params = pw.walletParams({ signers: [pw.addressOfKey(signerKey)], threshold: 1, palmSigner: pw.addressOfKey(palmKey), recoveryDays: 90 });
    const salt = pw.walletSalt(`heir-${crypto.randomBytes(4).toString('hex')}`);
    const address = pw.walletAddressOf(params, salt);
    await (await payer.sendTransaction({ to: pw.DEPLOYER, data: pw.deployCallOf(params, salt) })).wait();
    await (await payer.sendTransaction({ to: address, value: ethers.parseEther('2') })).wait();
    const wallet = await ethers.getContractAt('PalmWallet', address);
    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    const heir = ethers.Wallet.createRandom().address;
    const recoveryNow = async () => ({ token: pw.NATIVE, to: heir.toLowerCase(), amount: ethers.parseEther('2').toString(), deadline: String((await now()) + 3600), nonce: String(await wallet.nonce()) });

    let recovery = await recoveryNow();
    let { signatures } = client.signPalmWalletRecovery([phrase], { chainId, wallet: address, recovery, signers: params.signers });
    await reverts(payer.sendTransaction({ to: address, data: pw.recoverCallOf(recovery, signatures), gasLimit: 300_000 }), wallet, 'NotYetDormant');
    expect(() => client.signPalmWalletRecovery(['zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'], { chainId, wallet: address, recovery, signers: params.signers }))
      .to.throw(/does not hold a key for this wallet/);

    await later(91 * DAY);
    recovery = await recoveryNow();
    ({ signatures } = client.signPalmWalletRecovery([phrase], { chainId, wallet: address, recovery, signers: params.signers }));
    await (await payer.sendTransaction({ to: address, data: pw.recoverCallOf(recovery, signatures), gasLimit: 300_000 })).wait();
    expect(await ethers.provider.getBalance(heir)).to.equal(ethers.parseEther('2'));
    // What an heir reads from the chain, decoded the way the app decodes it.
    expect(pw.decodeAddressArray(await ethers.provider.call({ to: address, data: pw.SIGNERS_CALL }))).to.deep.equal(params.signers);
    expect(BigInt(await ethers.provider.call({ to: address, data: pw.THRESHOLD_CALL }))).to.equal(1n);
    expect(BigInt(await ethers.provider.call({ to: address, data: pw.RECOVERY_DELAY_CALL }))).to.equal(BigInt(90 * DAY));
  });
});

/*
 * The attacks the audit proved against version 1 (A1 to A3), replayed against version 2.
 */
describe('PalmWallet v2 against the audit\'s attacks', () => {
  it('A1: a thief with the signer keys can no longer touch the nonce, so every palm approved rescue goes through', async () => {
    const ctx = await built({ days: 30 });
    const thief = ethers.Wallet.createRandom().address;
    // The thief tries what used to work: a recovery for 1 wei, to burn the nonce.
    const r = { token: pw.NATIVE, to: thief, amount: '1', deadline: String((await now()) + 3600), nonce: '0' };
    const thiefCall = pw.recoverCallOf(r, signersSign(ctx.people, pw.eip712RecoveryDigest({ chainId: ctx.chainId, wallet: ctx.address, recovery: r })));
    await reverts(send(ctx, thiefCall), ctx.wallet, 'NotYetDormant');
    expect(await ctx.wallet.nonce()).to.equal(0n);
    // The owner's palm approved rescue of everything to a safe address lands at the nonce it was signed for.
    const safe = ethers.Wallet.createRandom().address;
    const amount = ethers.parseEther('4.99');
    const t = await payment(ctx, { to: safe, amount });
    const { signature } = approve(ctx, t);
    await (await send(ctx, pw.transferCallOf(t, signersSign(ctx.people, digestOf(ctx, t)), signature))).wait();
    expect(await ethers.provider.getBalance(safe)).to.equal(amount);
  });

  it('A2: a "token" with no code is refused rather than reported as sent', async () => {
    const palmKey = crypto.randomBytes(32);
    const ctx = await built({ palmKey });
    const t = await payment(ctx, { to: ctx.payer.address, amount: 1000, token: ethers.Wallet.createRandom().address });
    const d = digestOf(ctx, t);
    await reverts(send(ctx, pw.transferCallOf(t, [pw.signDigest(d, ctx.people[0].key)], pw.signDigest(d, palmKey))), ctx.wallet, 'NotAToken');
  });

  it('A3: whoever holds the palm key alone cannot keep the signers out once the delay has passed', async () => {
    const palmKey = crypto.randomBytes(32);
    const ctx = await built({ palmKey, days: 30 });
    // The palm key has no function of its own: a refresh without the signers is refused.
    const fr = pw.normalRefresh({ gasRefund: '0', deadline: String((await now()) + 3600), nonce: '0' });
    const frd = pw.eip712RefreshDigest({ chainId: ctx.chainId, wallet: ctx.address, refresh: fr });
    await reverts(send(ctx, pw.refreshCallOf(fr, [], pw.signDigest(frd, palmKey))), ctx.wallet, 'NotEnoughSigners');
    await later(31 * DAY);
    const heir = ethers.Wallet.createRandom().address;
    const r = { token: pw.NATIVE, to: heir, amount: ethers.parseEther('5').toString(), deadline: String((await now()) + 3600), nonce: '0' };
    await (await send(ctx, pw.recoverCallOf(r, signersSign(ctx.people, pw.eip712RecoveryDigest({ chainId: ctx.chainId, wallet: ctx.address, recovery: r }))))).wait();
    expect(await ethers.provider.getBalance(heir)).to.equal(ethers.parseEther('5'));
  });
});
