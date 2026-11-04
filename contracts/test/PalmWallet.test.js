/*
 * PalmWallet on a local Ethereum chain. The palm signatures here come from Palm's own palm
 * signer (src/palm-signer.js) given real ES256 palm decisions, and the digests from
 * src/palm-wallet.js, so these tests check that the off-chain code and the contract agree on
 * every byte, not just that the contract works with signatures made the contract's way.
 */
const { expect } = require('chai');
const { ethers } = require('hardhat');
const crypto = require('node:crypto');

const ISSUER = 'https://issuer.test';
const AUDIENCE = 'palm-test';
const DAY = 24 * 3600;

let pw;
let signerModule;
before(async () => {
  pw = await import('../../src/palm-wallet.js');
  signerModule = await import('../../src/palm-signer.js');
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
let actionDigest;
before(async () => { ({ actionDigest } = await import('../../src/veyns.js')); });

/** The call reverts with the contract's custom error , and nothing else counts. */
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

const sortByAddress = wallets => [...wallets].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));
const signWith = (wallet, digest) => wallet.signingKey.sign(digest).serialized;

/** A deployed Palm Wallet with `count` signers, `threshold`, its palm signer, and some coin. */
async function deployed({ count = 1, threshold = 1, delay = 30 * DAY, fund = ethers.parseEther('5') } = {}) {
  const [payer] = await ethers.getSigners();
  const veyns = mockVeyns();
  const palm = signerModule.createPalmSigner({
    seed: crypto.randomBytes(32), issuer: ISSUER, audience: AUDIENCE, pinnedKeys: [veyns.jwk],
  });
  const vaultId = `vault-${crypto.randomBytes(4).toString('hex')}`;
  const people = sortByAddress(Array.from({ length: count }, () => ethers.Wallet.createRandom()));
  const subs = people.map((_, i) => `sub-${i}`);
  const factory = await (await ethers.getContractFactory('PalmWalletFactory')).deploy();
  const salt = ethers.id(vaultId);
  const args = [people.map(p => p.address), threshold, palm.palmAddressFor(vaultId), delay, salt];
  const predicted = await factory.addressOf(...args);
  await (await factory.create(...args)).wait();
  const wallet = await ethers.getContractAt('PalmWallet', predicted);
  if (fund) await (await payer.sendTransaction({ to: predicted, value: fund })).wait();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  return { payer, veyns, palm, vaultId, people, subs, wallet, address: predicted, chainId, threshold };
}

/** What the app would put in front of a person, and the palm signer's signature for it. */
function approve(ctx, transfer, { approvers = ctx.subs.slice(0, ctx.threshold), tweak = {} } = {}) {
  const t = pw.normalTransfer(transfer);
  const details = {
    action: 'withdraw', network: 'ethereum', wallet: ctx.address, to: t.to,
    token: t.token === pw.NATIVE ? 'native' : t.token, amount_units: t.amount, chain_id: String(ctx.chainId),
    transaction_hash: pw.evmTransferDigest({ chainId: ctx.chainId, wallet: ctx.address, transfer: t }),
    ...tweak,
  };
  const action = { statement: `Send ${t.amount} to ${t.to}`, details };
  return ctx.palm.signEvmTransfer({
    vaultId: ctx.vaultId,
    wallet: { address: ctx.address, chainId: ctx.chainId, threshold: ctx.threshold, signerSubs: ctx.subs },
    transfer: t,
    action,
    decisions: approvers.map(sub => ctx.veyns.decision(sub, action)),
  });
}

const digestOf = (ctx, transfer) => pw.eip712TransferDigest({ chainId: ctx.chainId, wallet: ctx.address, transfer });

describe('PalmWallet', () => {
  it('lands at the address the factory promised, and agrees with Palm on the digest', async () => {
    const ctx = await deployed();
    expect(await ethers.provider.getBalance(ctx.address)).to.equal(ethers.parseEther('5'));
    expect(await ctx.wallet.palmSigner()).to.equal(ethers.getAddress(ctx.palm.palmAddressFor(ctx.vaultId)));
    const transfer = { token: pw.NATIVE, to: ctx.payer.address, amount: '1000', nonce: '0' };
    const onChain = await ctx.wallet.transferDigest(pw.NATIVE, ctx.payer.address, 1000n, 0n);
    expect(onChain).to.equal(`0x${Buffer.from(digestOf(ctx, transfer)).toString('hex')}`);
  });

  it('sends with the signer and the palm key, both checked by the contract', async () => {
    const ctx = await deployed();
    const to = ethers.Wallet.createRandom().address;
    const transfer = { token: pw.NATIVE, to, amount: ethers.parseEther('1').toString(), nonce: '0' };
    const { signature: palmSig } = approve(ctx, transfer);
    await (await ctx.wallet.transfer(pw.NATIVE, to, ethers.parseEther('1'), [signWith(ctx.people[0], digestOf(ctx, transfer))], palmSig)).wait();
    expect(await ethers.provider.getBalance(to)).to.equal(ethers.parseEther('1'));
    expect(await ctx.wallet.nonce()).to.equal(1n);
  });

  it('refuses the signer alone, and a palm signature from any other key', async () => {
    const ctx = await deployed();
    const to = ethers.Wallet.createRandom().address;
    const transfer = { token: pw.NATIVE, to, amount: '1000', nonce: '0' };
    const mine = signWith(ctx.people[0], digestOf(ctx, transfer));
    await reverts(ctx.wallet.transfer(pw.NATIVE, to, 1000n, [mine], mine), ctx.wallet, 'NoPalm');
    const thief = ethers.Wallet.createRandom();
    await reverts(ctx.wallet.transfer(pw.NATIVE, to, 1000n, [mine], signWith(thief, digestOf(ctx, transfer))), ctx.wallet, 'NoPalm');
  });

  it('a palm signature is for one transfer: not another amount, payee, nonce or wallet', async () => {
    const ctx = await deployed();
    const other = await deployed();
    const to = ethers.Wallet.createRandom().address;
    const transfer = { token: pw.NATIVE, to, amount: '1000', nonce: '0' };
    const { signature: palmSig } = approve(ctx, transfer);
    const mine = signWith(ctx.people[0], digestOf(ctx, transfer));
    await expect(ctx.wallet.transfer(pw.NATIVE, to, 2000n, [mine], palmSig), ctx.wallet, 'NoPalm');
    await reverts(ctx.wallet.transfer(pw.NATIVE, ctx.payer.address, 1000n, [mine], palmSig), ctx.wallet, 'NoPalm');
    await reverts(other.wallet.transfer(pw.NATIVE, to, 1000n, [mine], palmSig), other.wallet, 'NoPalm');
    await (await ctx.wallet.transfer(pw.NATIVE, to, 1000n, [mine], palmSig)).wait();
    await reverts(ctx.wallet.transfer(pw.NATIVE, to, 1000n, [mine], palmSig), ctx.wallet, 'NoPalm');
  });

  it('a shared wallet needs that many different signers, in order, plus the palm', async () => {
    const ctx = await deployed({ count: 3, threshold: 2 });
    const to = ethers.Wallet.createRandom().address;
    const transfer = { token: pw.NATIVE, to, amount: '1000', nonce: '0' };
    const { signature: palmSig } = approve(ctx, transfer);
    const d = digestOf(ctx, transfer);
    const [a, b] = ctx.people;
    await reverts(ctx.wallet.transfer(pw.NATIVE, to, 1000n, [signWith(a, d)], palmSig), ctx.wallet, 'NotEnoughSigners');
    await reverts(ctx.wallet.transfer(pw.NATIVE, to, 1000n, [signWith(a, d), signWith(a, d)], palmSig), ctx.wallet, 'NotADistinctSigner');
    await reverts(ctx.wallet.transfer(pw.NATIVE, to, 1000n, [signWith(b, d), signWith(a, d)], palmSig), ctx.wallet, 'NotADistinctSigner');
    const stranger = sortByAddress([ethers.Wallet.createRandom(), a]);
    await reverts(ctx.wallet.transfer(pw.NATIVE, to, 1000n, stranger.map(w => signWith(w, d)), palmSig), ctx.wallet, 'NotADistinctSigner');
    await (await ctx.wallet.transfer(pw.NATIVE, to, 1000n, [signWith(a, d), signWith(b, d)], palmSig)).wait();
    expect(await ethers.provider.getBalance(to)).to.equal(1000n);
  });

  it('sends ERC-20 tokens the same way', async () => {
    const ctx = await deployed({ fund: 0n });
    const token = await (await ethers.getContractFactory('TestToken')).deploy();
    await (await token.mint(ctx.address, 500n)).wait();
    const to = ethers.Wallet.createRandom().address;
    const transfer = { token: await token.getAddress(), to, amount: '200', nonce: '0' };
    const { signature: palmSig } = approve(ctx, transfer);
    await (await ctx.wallet.transfer(transfer.token, to, 200n, [signWith(ctx.people[0], digestOf(ctx, transfer))], palmSig)).wait();
    expect(await token.balanceOf(to)).to.equal(200n);
  });

  it('the palm signer will not sign what a person did not read', async () => {
    const ctx = await deployed();
    const transfer = { token: pw.NATIVE, to: ethers.Wallet.createRandom().address, amount: '1000', nonce: '0' };
    const refusedFor = tweak => {
      try {
        approve(ctx, transfer, { tweak });
        return null;
      } catch (error) {
        return error instanceof signerModule.PalmRefused ? error.message : `not a refusal: ${error.message}`;
      }
    };
    expect(refusedFor({ to: ctx.payer.address })).to.match(/payee/);
    expect(refusedFor({ amount_units: '999' })).to.match(/amount/);
    expect(refusedFor({ token: ctx.payer.address })).to.match(/asset/);
    expect(refusedFor({ wallet: ctx.payer.address })).to.match(/different wallet/);
    expect(refusedFor({ chain_id: '1' })).to.match(/different chain/);
    expect(refusedFor({ transaction_hash: 'x'.repeat(43) })).to.match(/different transfer/);
    expect(() => approve(ctx, transfer, { approvers: [] })).to.throw(/needs 1 palm approval/);
  });

  it('recovery: the signers alone can schedule, only after the delay does it run, and the palm can cancel', async () => {
    const ctx = await deployed({ delay: 30 * DAY });
    const to = ethers.Wallet.createRandom().address;
    const sign = nonce => signWith(ctx.people[0], pw.eip712RecoveryDigest({
      chainId: ctx.chainId, wallet: ctx.address, transfer: { token: pw.NATIVE, to, amount: '1000', nonce },
    }));

    const id = await ctx.wallet.scheduleRecovery.staticCall(pw.NATIVE, to, 1000n, [sign('0')]);
    await (await ctx.wallet.scheduleRecovery(pw.NATIVE, to, 1000n, [sign('0')])).wait();
    await reverts(ctx.wallet.executeRecovery(id), ctx.wallet, 'TooEarly');
    await ethers.provider.send('evm_increaseTime', [30 * DAY]);
    await ethers.provider.send('evm_mine', []);
    await (await ctx.wallet.executeRecovery(id)).wait();
    expect(await ethers.provider.getBalance(to)).to.equal(1000n);

    // A thief with the phrase schedules one; the palm path cancels it before it can run.
    const stolen = await ctx.wallet.scheduleRecovery.staticCall(pw.NATIVE, to, 2000n, [signWith(ctx.people[0], pw.eip712RecoveryDigest({
      chainId: ctx.chainId, wallet: ctx.address, transfer: { token: pw.NATIVE, to, amount: '2000', nonce: '1' },
    }))]);
    await (await ctx.wallet.scheduleRecovery(pw.NATIVE, to, 2000n, [signWith(ctx.people[0], pw.eip712RecoveryDigest({
      chainId: ctx.chainId, wallet: ctx.address, transfer: { token: pw.NATIVE, to, amount: '2000', nonce: '1' },
    }))])).wait();
    const cancelHash = (await import('../../src/veyns.js')).transactionDigest({
      v: 1, kind: 'palm-wallet-cancel', chainId: String(ctx.chainId), wallet: ctx.address.toLowerCase(), id: stolen.toLowerCase(), nonce: '2',
    });
    const action = { statement: 'Cancel the scheduled transfer', details: { action: 'cancel a scheduled transfer', transaction_hash: cancelHash } };
    const { signature } = ctx.palm.signEvmCancel({
      vaultId: ctx.vaultId, wallet: { address: ctx.address, chainId: ctx.chainId, signerSubs: ctx.subs },
      id: stolen, nonce: '2', action, decisions: [ctx.veyns.decision(ctx.subs[0], action)],
    });
    await (await ctx.wallet.cancelRecovery(stolen, signature)).wait();
    await ethers.provider.send('evm_increaseTime', [30 * DAY]);
    await ethers.provider.send('evm_mine', []);
    await reverts(ctx.wallet.executeRecovery(stolen), ctx.wallet, 'NothingScheduled');
  });

  it('refuses a wallet that could be spent by one signature, or that is set up wrong', async () => {
    const Wallet = await ethers.getContractFactory('PalmWallet');
    const people = sortByAddress([ethers.Wallet.createRandom(), ethers.Wallet.createRandom()]).map(p => p.address);
    const palmAddr = ethers.Wallet.createRandom().address;
    await reverts(Wallet.deploy(people, 1, palmAddr, 30 * DAY), Wallet, 'BadSetup');
    await reverts(Wallet.deploy([...people].reverse(), 2, palmAddr, 30 * DAY), Wallet, 'BadSetup');
    await reverts(Wallet.deploy(people, 2, people[0], 30 * DAY), Wallet, 'BadSetup');
    await reverts(Wallet.deploy(people, 2, palmAddr, 60), Wallet, 'BadSetup');
  });
});
