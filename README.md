# CRD: blockchain for fast programmable transactions from untrusted code

## tl;dr

```
npm i -g crds
crds host=127.0.0.1 port=9999 dataDirectory=~/.crds
```

`CRD` ("credits") is a blockchain currency for decentralized, permissionless, realtime, programmatic value exchange. Supports:

- Mining
- **Custom token minting** (permissioned)
- **Charges** (permissionless)
- **Chargebacks** (timeboxed)

Implemented in pure Javascript.

## Motivation

You want a payments API in an _untrusted_ execution environment (thid-party code).
You want apps to define their own notion of value, identity, and ownership. But you also want to exchange value across apps.
You want all of this to be done at the speed of user interaction, as opposed to the speed of a bank transfer.
You want this without trusting any authority (the "code is law" approach).

That's what `CRD` does.

## Overview

**CRD** is a blockchain with similar structure to bitcoin. It uses the same algorithms (`SHA-256`, `secp256k1`), the same mining concept (proof of work hashing to incentivize reeplication), the same conflict resolution (block height), and the same client/server model (P2P nodes).

The main architectureal difference is in the consensus rules and parameters, which are optimized for realtime transactions in untrusted execution environments:

- There are transaction messages that allow anyone to invoke arbitrary _charges_ (and arbitrarily long charge custody chains). This seems crazy, but charges can be _charged back_ by the address being charged for a brief block range. This undoes the whole charge custody chain. If not charged back, charges settle automatically. Addresses can be _locked_ at the owner's request for assurance that balance can't leak while you're not looking.
- Anyone can mint their own currency -- the chain supports multiple independent currencies and P2P exchange between them. Minting a currency means you claim a name, and you get a token representing your exclusive ability to mint currency with that name. These concepts are first-class citizens and enforced by the blockchain consensus rules.
- Messages are plain JSON. The API is pure HTTP. The code is pure Javascript. If you like web dev, you'll like this. If you don't like web dev, this arrangement is guaranteed to interface with any framework you like.
- The data store is a simple JSON database that indexes balances and data needed to verify transaction and block integrity. There is no concept of UTXO's (unspent transaction outputs) or scripts. This is simpler to implement, simpler to reason about, and minimizes necessary data storage to only the things the code needs to tell if someone isn't playing by the rules.
- Mining/block parameters are adjusted to be much faster and have much higher caps than e.g. Bitcoin, allowing use in soft-realtime applications such as games.
- All of this is designed to be programmable from a lightweight Javasript environment, such as a web browser. There are no wallets or indexes, so there's no blobs to download. There is no binary parsing. If you can compute a hash, construct JSON, and send HTTP, you can participate in the blockchain.

## Technical discussion

Blocks are JSON files:

```
{
  "hash": "000063acda12aa7125073934a847bf00e6cd376e6f459e043289de9219b66c3b",
  "prevHash": "000064c989a29312ac0e8bfe88c9e1e2783cc4abdb0a44c7aa8cbfafe81842ed",
  "height": 2,
  "difficulty": 100000,
  "version": "0.0.1",
  "timestamp": 1497528374123,
  "messages": [
    {
      "payload": "{\"type\":\"coinbase\",\"asset\":\"CRD\",\"quantity\":1,\"address\":\"G4ExZ6nYBPnu7Sr1c8kMgbzz3VS9DbGi6cNeghEirbHj\",\"startHeight\":2,\"timestamp\":1497528374123}",
      "signature": "MEUCIQDIwYpShdO6SFxNvdZppECKzPhdbBVuIT2PO/NpsEsAlgIgbmSJb3Am+HnC5JIll/MJDbBPQecZA06QuaPtYCgCNH0="
    }
  ],
  "nonce": 749
}
```

Hashes are `SHA-256` and cover all keys. The nonce is an arbitrary JSON number that lets you try for a hash under `0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff / difficulty`. A block with such a hash, a valid previous hash, and all messages valid, is itself accepted as valid and added to the chain.

To get a useful view of the blockchain such as address balances, we simply walk the blocks and deterministically build up an index database. This database is also JSON:

```
{
  "balances": {
    "G4ExZ6nYBPnu7Sr1c8kMgbzz3VS9DbGi6cNeghEirbHj": {
      "CRD": 3655.8,
      "ZEOCOIN:mint": 1,
      "ZEOCOIN": 99
    },
    "GJfJvo6ZbDXV31g5QuLSKF3NTWQLc36VVNXJBcyhRehY": {
      "CRD": 19.2,
      "ZEOCOIN": 1
    }
  },
  "charges": [
    {
      "payload": "{\"type\":\"charge\",\"srcAddress\":\"GJfJvo6ZbDXV31g5QuLSKF3NTWQLc36VVNXJBcyhRehY\",\"dstAddress\":\"G4ExZ6nYBPnu7Sr1c8kMgbzz3VS9DbGi6cNeghEirbHj\",\"srcAsset\":\"CRD\",\"srcQuantity\":1,\"dstAsset\":\"ZEOCOIN\",\"dstQuantity\":1,\"startHeight\":1148,\"timestamp\":1497553212090}",
      "signature": "MEUCIQDcIpySoqa91+w2DkVH6JUHOvrGNmL5+G0jt0yqUpbHpgIgcqGxWXGnKo9nxkJvveKh3g4rR+hkEJTDEnvLSNZpHQs="
    }
  ],
  "messageRevocations": [
    [
      "MEUCIQCdU8WzRlCiZ7PQ00zAIyAdeBE+kNLEn/nCiS0gHwM5ZQIgYhs5f4I/ofa7GN5t+H/fCZNGFW+F2x9y1w78vvwE26Q="
    ],
    [
      "MEQCIBAYtyW62JRLdz+dsr4FUX3c6czQVqyeITgofPbBmfZLAiBnAJw7qY5p4MLQ5sFGOQbUEHMwU2IPoA3CbTnzkXsfag=="
    ]
  ],
  "minters": {
    "CRD": null,
    "ZEOCOIN": "G4ExZ6nYBPnu7Sr1c8kMgbzz3VS9DbGi6cNeghEirbHj"
  }
}
```

The database is immutable and proceeds in lockstep with blocks -- that is, when a new block comes in we chunch the numbers and tick the database to the next state. The database holds every piece of metadata we need to check integrity of the next block -- such as the balance of every address, the confirmed message signatures that still have a valid TTL (to prevent replays), and the unsettled charges that can be charged back by the payer.

Note there is no concept of transaction outputs or scripts. The tradeoff is users can't invent their own crazy signing scheme without a software upgrade/fork, but we save memory and disk space and gain performance and simplicity. Consistency guarantees are identical to Bitcoin.

Also note the multiple currencies and minters/minting tokens. Each additional currency has a name (such as `ZEOCOIN`), and a corresponding `:mint` token (such as `ZEOCOIN:mint`). This grants permission for posting `mint` transactions to create more tokens of a currency. Anyone can register a new currency provided the name isn't taken, which grants the currency's initial `:mint` token. The `:mint` token itself can be transferred to grant mint authority over the currency. All of this happens on the blockchain and is auditable by hand.

A short history of database snapshots (literally just old copies of the database files) is kept to allow for easy backtracking to a previous state if we detect a blockchain fork and need to reconstruct the new state. We never try to "undo" the database however -- it only goes forward in time, which keeps code simple to reason about. If we don't have enough history to go back to (i.e. we're seriously desynchronized from the true blockchain), the price we pay is reindexing the blockchain from scratch. No biggie.

One more interesting piece is charges and chargebacks. Charges are a special kind of send transaction that doesn't need any signature. Which sounds crazy, but, charges are "unsettled" for a mandatory grace period during which the payer (who has the key to their address) can sign a chargeback transaction to abort the charge. _This allows for frictionless, permissionless, and trustless payments from untrusted code_, since damage can be trivially undone (even automatically) by the affected party.

Charges and chargebacks are transitive. That is, if A charges B, then C charges A, both charges will go through frictionlessly in realtime. However, a chargeback from B will undo _both_ charges if it would make them invalid. The database tracks all the state required to implement this.
