# Palm Vault

Palm Vault is a vault for digital assets where nothing moves without a palm scan. It is a
standalone product built on Veyns palm authentication.

## What it does

- **Every payment needs a palm approval.** You see exactly what you are approving, the amount,
  the destination and the fee, and confirm it with a palm scan in the Veyns app.
- **The approval is tied to that exact transaction.** If anything about it changes after you
  approve, the vault refuses to sign.
- **Your keys stay with you.** They are created and kept in your own browser, backed by a
  recovery phrase. Palm Vault's servers never hold them.
- **Vaults can be shared.** Invite cosigners and choose how many palms must approve, for
  example 2 of 3. On Bitcoin a shared vault is locked to the chain, so the network itself
  enforces the rule and no single person can move funds alone.
- **Every approval leaves a receipt.** It records who approved which transaction, is signed
  with post quantum cryptography, and anyone can check it.

## How a payment works

1. Enter the amount and where it is going.
2. Palm Vault prepares the exact transaction.
3. You, and any cosigners the vault needs, approve it with a palm scan.
4. Your browser signs it, the payment is sent, and a receipt is issued.

## Networks

Bitcoin, with sending also available on Ethereum and BNB Smart Chain.

## Status

Palm Vault currently runs on test networks only.
