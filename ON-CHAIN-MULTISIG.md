# A quorum the chain keeps

Until an account is locked, its threshold is a rule QuVault remembers. The coins sit behind
one key — the owner's — so "two of three" is a promise this server makes while Bitcoin would
accept one signature from one person. Anyone who got hold of the owner's twelve words could
spend alone, and no rule in any database would have stopped them.

Locking an account ends that. The coins move into a P2WSH output holding an ordinary m-of-n
script naming every signer's key, and from then on the rule is Bitcoin's. It holds if this
server is compromised, misconfigured, or switched off for good.

## What it is

An ordinary multisig script, nothing invented:

```
OP_2 <33-byte key> <33-byte key> <33-byte key> OP_3 OP_CHECKMULTISIG
```

wrapped in P2WSH, giving a `tb1q…` address 62 characters long. Keys are ordered
lexicographically (BIP67), so the same people always derive the same address whichever of them
derives it, and an order nobody agreed on cannot quietly become a different vault. Any wallet
or explorer can read this. If QuVault disappears, the signers can rebuild the script from
their own phrases and spend without us — which is the point.

## Who holds what

Every signer has a key of their own, derived in their own browser from their own twelve words
on the ordinary co-signing path, with a branch per vault:

```
m/48'/1'/0'/2'/0/{branch}
```

One phrase per person, however many vaults they sign for, and no two vaults share a key, so
the chain does not link them for anyone watching. The server is told the public half and the
branch number. Both are safe in the open; neither can produce a signature.

To sign for a vault you need a vault of your own, because it is your own phrase the key comes
from. Creating one costs nothing and it can stay empty. The alternative — handing a co-signer
a second set of words to keep — is worse: more to lose, and nothing gained.

Losing a co-signing key is survivable in a way losing a wallet phrase is not. The rest of the
quorum moves the coins to a script without that key in it. That is what a threshold is for.

## What happens when an account is locked

One approval covers the whole thing. The statement the palms cover names the threshold, the
signers, the new address, and the hash of the exact transaction that carries the coins there,
so there is no moment where the account has changed but the money has not followed. A lock
that cannot be broadcast leaves everything exactly as it was.

The address the account used before is kept. Somebody working from an old note will still send
coins there, and the owner's key still opens them.

## What spending looks like afterwards

1. A withdrawal is planned once, against the script: exact inputs, exact outputs, exact fee.
2. The palms gather, as they always did.
3. Each of those people opens their own key — only their own palm opens it — and adds one
   signature in their own browser.
4. When enough signatures exist the transaction is finalised, checked against the approved
   plan, and broadcast.

The transaction the signatures gather on is rebuilt from the stored plan every time one
arrives, so a signature can only ever be collected for the transaction the palms approved, and
a database that lost or rewrote the half-signed copy cannot make signatures appear. What a
browser sends is compared against what was already there, and the only thing it may have added
is a signature from its own key.

The window to sign runs from the moment the request became signable — when the last palm it
needed landed — rather than from each person's own approval, because a quorum's approvals
arrive minutes apart and whoever approved first would otherwise find their window gone.

## Two things Bitcoin decides, not us

**An account the chain guards has one threshold, not a ladder of them.** A script cannot read
the amount being sent. There is no way to write "one signature under 0.01, two above" into a
Bitcoin output today, so the amount steps stop applying once an account is locked. Anything
claiming otherwise would be enforcing it in the same database we just stopped trusting.

**Changing the threshold means moving the coins again.** The keys and the number are part of
the address. Adding a signer, removing one, or changing the number produces a different
address, and the coins have to be sent there — approved under the old rules, and costing a
fee. This is not a limitation of the implementation; it is what a P2WSH output is.

## What is weaker here than for a single key

The ML-DSA record that says a palm was verified is signed by the vault's own attestation key,
which only the owner holds. A spend finished by two other signers has no such record. What it
has instead is the chain: two signatures from two keys, each released by its own palm, visible
to anyone. Giving every signer an attestation key of their own is the next step and is not
claimed today.

## What this is tested against

`test/multisig.test.js` works at the level of the coins: what a set of keys locks them to,
what it costs to spend, and what the script actually contains. The fee a sweep sets aside is
checked against transactions really signed at one, two and three signatures, because a sweep
has no change output to absorb a bad estimate.

`test/signing-keys.test.js`, `test/lock.test.js` and `test/quorum-spend.test.js` cover the
rest: a key that cannot be made for a vault you do not sign for, a lock that cannot be sent
leaving the account alone, a signer who did not approve, a browser offering somebody else's
signature, a signature carried over from another spend, and a signer who waits too long.
