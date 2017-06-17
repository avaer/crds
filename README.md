# CRD: blockchain currency for open source

## tl;dr

```
npm i -g crds
crds
```

Blockchain currency for decentralized, permissionless, realtime, programmatic value exchange. Supports:

- Mining
- **Custom token minting** (permissioned)
- **Charges** (permissionless)
- **Chargebacks** (windowed)

Implemented in pure Javascript.

## Motivation

You want a payments API in an _untrusted_ execution environment.
You want apps to define their own notion of value, identity, and ownership. But you also want to exchange value across apps.
You want all of this to be done at the speed of code.
You want all of this without trusting any authority.

That's what this code tries to do.

## Overview

**CRD** is a blockchain with similar structure to bitcoin. It uses the same algorithms (`SHA-256`, `secp256k1`), the same mining concept to incentivize replication (proof of work hashing), the same conflict resolution (block height), and the same replication strategy (P2P nodes).

The main architectureal difference is in the block/message consensus rules and parameters:

- There are transaction messages that allow anyone to invoke arbitrary _charges_ (and arbitrarily long charge custody chains). This seems crazy, but charges can be _charged back_ by the address being charged for a brief block range. This undoes the whole charge custody chain. If not charged back, charges settle automatically. Addresses can be _locked_ at the owner's request for assurance that balance can't leak while you're not looking.
- Anyone can mint their own currency -- the chain supports multiple independent currencies and P2P exchange between them. Minting a currency means you claim a name, and you get a token representing your exclusive ability to mint currency with that name. These concepts are first-class citizens and enforced by the blockchain consensus rules.
- Messages are plain JSON. The API is pure HTTP. The code is pure Javascript. If you like web dev, you'll like this. If you don't like web dev, this arrangement is guaranteed to interface with any framework you like.
- The data store is a simple JSON database that indexes balances and data needed to verify transaction and block integrity. There is no concept of UTXO's (unspent transaction outputs) or scripts. This is simpler to implement, simpler to reason about, and minimizes necessary data storage to only the things the code needs to tell if someone isn't playing by the rules.
- Mining/block parameters are adjusted to be much faster and have much higher caps than e.g. Bitcoin, allowing use in soft-realtime applications such as games.
- All of this is designed to be programmable from a lightweight Javasript environment, such as a web browser. There are no wallets or indexes. There is no binary parsing. If you can compute a hash, construct JSON, and send HTTP, you can participate in the blockchain.
