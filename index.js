const path = require('path');
const fs = require('fs');
const http = require('http');
const querystring = require('querystring');
const crypto = require('crypto');
const repl = require('repl');

const mkdirp = require('mkdirp');
const express = require('express');
const bodyParser = require('body-parser');
const bodyParserJson = bodyParser.json();
const request = require('request');
const writeFileAtomic = require('write-file-atomic');
const replHistory = require('repl.history');
const bigint = require('big-integer');
const eccrypto = require('eccrypto');

const WORK_TIME = 20;
const CHARGE_SETTLE_BLOCKS = 100;

const args = process.argv.slice(2);
const _findArg = name => {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const match = arg.match(new RegExp('^' + name + '=(.+)$'));
    if (match) {
      return match[1];
    }
  }
  return null;
};
const port = parseInt(_findArg('port')) || 9999;
const dataDirectory = _findArg('dataDirectory') || 'db';

class Block {
  constructor(hash, prevHash, timestamp, messages, nonce) {
    this.hash = hash;
    this.prevHash = prevHash;
    this.timestamp = timestamp;
    this.messages = messages;
    this.nonce = nonce;
  }

  static from(o) {
    const {hash, prevHash, timestamp, messages, nonce} = o;
    return new Block(hash, prevHash, timestamp, messages.map(message => Message.from(message)), nonce);
  }

  equals(block) {
    return this.hash === block.hash;
  }
}
class Message {
  constructor(payload, signature) {
    this.payload = payload;
    this.signature = signature;
  }

  static from(o) {
    const {payload, signature} = o;
    return new Message(payload, signature);
  }

  equals(message) {
    return this.signature === message.signature;
  }
}

let db = {
  version: '0.0.1',
  blocks: [],
  balances: {},
  charges: [],
  minters: {
    'CRD': null,
  },
};
let mempool = [];
let peers = [];

const privateKey = new Buffer('9reoEGJiw+5rLuH6q9Z7UwmCSG9UUndExMPuWzrc50c=', 'base64');
const publicKey = eccrypto.getPublic(privateKey); // BCqREvEkTNfj0McLYve5kUi9cqeEjK4d4T5HQU+hv+Dv+EsDZ5HONk4lcQVImjWDV5Aj8Qy+ALoKlBAk0vsvq1Q=

const privateKey2 = new Buffer('0S5CM+e3u2Y1vx6kM/sVHUcHaWHoup1pSZ0ty1lxZek=', 'base64');
const publicKey2 = eccrypto.getPublic(privateKey); // BL6r5/T6dVKfKpeh43LmMJQrOXYOjbDX1zcwgA8hyK6ScDFUUf35NAyFq8AgQfNsMuP+LPiCreOIjdOrDV5eAD4=

const difficulty = 1e5;
const target = bigint('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16).divide(bigint(difficulty))

const _getConfirmedBalances = (db, address) => JSON.parse(JSON.stringify(db.balances[address] || {}));
const _getConfirmedBalance = (db, address, asset) => {
  let balance = (db.balances[address] || {})[asset];
  if (balance === undefined) {
    balance = 0;
  }
  return balance;
};
const _getUnconfirmedBalances = (db, mempool, address) => {
  let result = _getConfirmedBalances(db, address);

  for (let i = 0; i < mempool.length; i++) {
    const message = mempool[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
      const {asset, quantity, address} = payloadJson;
      let dstAddressEntry = db.balances[address];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        result[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAddressEntry[asset] = dstAssetEntry + quantity;
    } else if (type === 'send') {
      const {asset, quantity, srcAddress, dstAddress} = payloadJson;

      let srcAddressEntry = db.balances[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        result[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAddressEntry[asset] = srcAssetEntry - quantity;

      let dstAddressEntry = db.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        result[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAddressEntry[asset] = dstAssetEntry + quantity;
    } else if (type === 'minter') {
      const {address, asset} = payloadJson;
      const mintAsset = asset + ':mint';

      let addressEntry = db.balances[address];
      if (addressEntry === undefined){
        addressEntry = {};
        result[address] = addressEntry;
      }
      let assetEntry = addressEntry[mintAsset];
      if (assetEntry === undefined) {
        assetEntry = 0;
      }
      assetEntry += 1;
      addressEntry[mintAsset] = assetEntry;
    }
  }

  return result;
};
const _getUnconfirmedBalance = (db, mempool, address, asset) => {
  let result = _getConfirmedBalance(db, address, asset);

  for (let i = 0; i < mempool.length; i++) {
    const message = mempool[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
      const {asset: a, quantity} = payloadJson;
      if (a === asset && dstAddress === address) {
        result += quantity;
      }
    } else if (type === 'send') {
      const {asset: a, quantity, srcAddress, dstAddress} = payloadJson;

      if (a === asset) {
        if (srcAddress === address) {
          result -= quantity;
        }
        if (dstAddress === address) {
          result += quantity;
        }
      }
    } else if (type === 'mint') {
      const {address: mintAddress, asset} = payloadJson;
      const mintAsset = asset + ':mint';

      if (mintAsset === asset && mintAddress === address) {
        result += 1;
      }
    }
  }

  return result;
};
const _getUnconfirmedUnsettledBalances = (db, mempool, address) => {
  let result = _getConfirmedBalances(db, address);

  for (let i = 0; i < mempool.length; i++) {
    const message = mempool[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
      const {asset: a, quantity, address} = payloadJson;
      let dstAddressEntry = db.balances[address];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        result[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAddressEntry[asset] = dstAssetEntry + quantity;
    } else if (type === 'send') {
      const {asset, quantity, srcAddress, dstAddress} = payloadJson;

      let srcAddressEntry = db.balances[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        result[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAddressEntry[asset] = srcAssetEntry - quantity;

      let dstAddressEntry = db.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        result[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAddressEntry[asset] = dstAssetEntry + quantity;
    } else if (type === 'minter') {
      const {address, asset} = payloadJson;
      const mintAsset = asset + ':mint';

      let addressEntry = db.balances[address];
      if (addressEntry === undefined){
        addressEntry = {};
        result[address] = addressEntry;
      }
      let assetEntry = addressEntry[mintAsset];
      if (assetEntry === undefined) {
        assetEntry = 0;
      }
      assetEntry += 1;
      addressEntry[mintAsset] = assetEntry;
    }
  }

  const invalidatedCharges = _getUnconfirmedInvalidatedCharges(db, mempool);
  for (let i = 0; i < invalidatedCharges.length; i++) {
    const charge = invalidatedCharges[i];
    const {asset, quantity, srcAddress, dstAddress} = JSON.parse(charge.payload);

    let srcAddressEntry = db.balances[srcAddress];
    if (srcAddressEntry === undefined){
      srcAddressEntry = {};
      result[srcAddress] = srcAddressEntry;
    }
    let srcAssetEntry = srcAddressEntry[asset];
    if (srcAssetEntry === undefined) {
      srcAssetEntry = 0;
    }
    srcAddressEntry[asset] = srcAssetEntry + quantity;

    let dstAddressEntry = db.balances[dstAddress];
    if (dstAddressEntry === undefined){
      dstAddressEntry = {};
      result[dstAddress] = dstAddressEntry;
    }
    let dstAssetEntry = dstAddressEntry[asset];
    if (dstAssetEntry === undefined) {
      dstAssetEntry = 0;
    }
    dstAddressEntry[asset] = dstAssetEntry - quantity;
  }

  return result;
};
const _getUnconfirmedUnsettledBalance = (db, mempool, address, asset) => {
  let result = _getConfirmedBalance(db, address, asset);

  for (let i = 0; i < mempool.length; i++) {
    const message = mempool[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
      const {asset: a, quantity} = payloadJson;
      if (a === asset && dstAddress === address) {
        result += quantity;
      }
    } else if (type === 'send') {
      const {asset: a, quantity, srcAddress, dstAddress} = payloadJson;

      if (a === asset) {
        if (srcAddress === address) {
          result -= quantity;
        }
        if (dstAddress === address) {
          result += quantity;
        }
      }
    } else if (type === 'charge') {
      const {asset: a, quantity, srcAddress, dstAddress} = payloadJson;

      if (a === asset) {
        if (srcAddress === address) {
          result -= quantity;
        }
        if (dstAddress === address) {
          result += quantity;
        }
      }
    } else if (type === 'mint') {
      const {address: mintAddress, asset} = payloadJson;
      const mintAsset = asset + ':mint';

      if (mintAsset === asset && mintAddress === address) {
        result += 1;
      }
    }
  }

  const invalidatedCharges = _getUnconfirmedInvalidatedCharges(db, mempool);
  for (let i = 0; i < invalidatedCharges.length; i++) {
    const charge = invalidatedCharges[i];
    const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(charge.payload);

    if (a === asset) {
      if (srcAddress === address) {
        result += quantity;
      }
      if (dstAddress === address) {
        result -= quantity;
      }
    }
  }

  return result;
};
const _findChargeBlockIndex = (db, chargeSignature) => {
  for (let i = db.blocks.length - 1; i >= 0; i--) {
    const block = db.blocks[i];
    const {messages} = block;
    const chargeMessage = _findLocalChargeMessage(messages, chargeSignature);

    if (chargeMessage) {
      return i;
    }
  }
  return -1;
};
const _findLocalChargeMessage = (messages, signature) => {
  for (let i = 0; i < messages.length; i++) {
    const message = messages[i];
    const {payload, signature} = message;
    const payloadJson = JSON.parse(payload);
    const {type} = payloadJson;

    if (type === 'charge' && signature === chargeSignature) {
      return message;
    }
  }
  return null;
};
const _findConfirmedChargeMessage = (db, chargeSignature) => {
  const {blocks} = db;
  for (let i = blocks.length - 1; i >= 0; i--) {
    const block = blocks[i];
    const {messages} = block;
    const message = _findLocalChargeMessage(messages, chargeSignature);

    if (message) {
      return message;
    }
  }

  return null;
};
const _findUnconfirmedChargeMessage = (db, mempool, chargeSignature) => {
  const {blocks} = db;
  for (let i = blocks.length - 1; i >= 0; i--) {
    const block = blocks[i];
    const {messages} = block;
    const message = _findLocalChargeMessage(messages, chargeSignature);

    if (message) {
      return message;
    }
  }

  return _findLocalChargeMessage(messages, mempool);
};
class AddressAssetSpec {
  constructor(address, asset, balance, charges) {
    this.address = address;
    this.asset = asset;
    this.balance = balance;
    this.charges = charges;
  }

  equals(addressAssetSpec) {
    return this.address === addressAssetSpec.address && this.asset === addressAssetSpec.asset;
  }
}
const _getConfirmedInvalidatedCharges = (db, block) => {
  const charges = db.charges.slice();
  const chargebacks = block.messages.filter(({type}) => type === 'chargeback');
  const directlyInvalidatedCharges = chargebacks.map(chargeback => {
    const {chargeSignature} = JSON.parse(chargeback.payload);
    const chargeMessage = _findConfirmedChargeMessage(db, chargeSignature);
    return chargeMessage || null;
  }).filter(chargeMessage => chargeMessage !== null);

  const confirmedAddressAssetSpecs = (() => {
    const result = [];

    for (let i = 0; i < directlyInvalidatedCharges.length; i++) {
      const charge = directlyInvalidatedCharges[i];
      const {asset, srcAddress, dstAddress} = JSON.parse(charge.payload);

      const srcEntry = new AddressAssetSpec(asset, srcAddress, 0, []);
      if (!result.some(entry => entry.equals(srcEntry))) {
        srcEntry.balance = _getConfirmedBalance(db, srcAddress, asset);

        result.push(srcEntry);
      }

      const dstEntry = new AddressAssetSpec(asset, dstAddress, 0, []);
      if (!result.some(entry => entry.equals(dstEntry))) {
        dstEntry.balance = _getConfirmedBalance(db, dstAddress, asset);

        result.push(dstEntry);
      }
    }

    return result;
  })();
  const unsettledInvalidatedConfirmedAddressAssetSpecs = confirmedAddressAssetSpecs.map(addressAssetSpec => {
    const {address, asset} = addressAssetSpec;
    let {balance} = addressAssetSpec;
    const charges = addressAssetSpec.charges.slice();

    for (let i = 0; i < charges.length; i++) {
      const charge = charges[i];

      if (!directlyInvalidatedCharges.includes(charge)) {
        const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(charge.payload);

        if (a === asset) {
          let applied = false;

          if (srcAddress === address) {
            balance -= quantity;
            applied = true;
          }
          if (dstAddress === address) {
            balance += quantity;
            applied = true;
          }

          if (applied) {
            charges.push(charge);
          }
        }
      }
    }

    return new AddressAssetSpec(address, asset, balance, charges);
  });

  const indirectlyInvalidatedCharges = (() => {
    const result = [];

    for (let i = 0; i < unsettledInvalidatedConfirmedAddressAssetSpecs.length; i++) {
      const assetSpec = unsettledInvalidatedConfirmedAddressAssetSpecs[i];
      const {address, asset} = assetSpec;
      let {balance} = assetSpec;
      const charges = assetSpec.charges.slice()
        .sort((a, b) => {
          const aJson = JSON.parse(a.payload);
          const bJson = JSON.parse(b.payload);

          const timestampDiff = aJson.timestamp - bJson.timestamp;
          if (timestampDiff !== 0) {
            return timestampDiff;
          } else {
            if (bigint(aJson.hash).leq(bigint(bJson.hash))) {
              return -1;
            } else {
              return 1;
            }
          }
        });

      while (balance < 0 && charges.length > 0) {
        const charge = charges.pop();
        const {quantity, srcAddress, dstAddress} = JSON.parse(charge.payload);

        if (srcAddress === address) {
          balance += quantity;
        }
        if (dstAddress === address) {
          balance -= quantity;
        }

        result.push(charge);
      }
    }

    return result;
  })();

  return directlyInvalidatedCharges.concat(indirectlyInvalidatedCharges);
};
const _getUnconfirmedInvalidatedCharges = (db, mempool) => {
  const charges = db.charges.concat(mempool.filter(({type}) => type === 'charge'));
  const chargebacks = mempool.filter(({type}) => type === 'chargeback');
  const directlyInvalidatedCharges = chargebacks.map(chargeback => {
    const {chargeSignature} = JSON.parse(chargeback.payload);
    const chargeMessage = _findUnconfirmedChargeMessage(db, mempool, chargeSignature);
    return chargeMessage || null;
  }).filter(chargeMessage => chargeMessage !== null);

  const confirmedAddressAssetSpecs = (() => {
    const result = [];

    for (let i = 0; i < directlyInvalidatedCharges.length; i++) {
      const charge = directlyInvalidatedCharges[i];
      const {asset, srcAddress, dstAddress} = JSON.parse(charge.payload);

      const srcEntry = new AddressAssetSpec(asset, srcAddress, 0, []);
      if (!result.some(entry => entry.equals(srcEntry))) {
        srcEntry.balance = _getConfirmedBalance(db, srcAddress, asset);

        result.push(srcEntry);
      }

      const dstEntry = new AddressAssetSpec(asset, dstAddress, 0, []);
      if (!result.some(entry => entry.equals(dstEntry))) {
        dstEntry.balance = _getConfirmedBalance(db, dstAddress, asset);

        result.push(dstEntry);
      }
    }

    return result;
  })();
  const unsettledInvalidatedConfirmedAddressAssetSpecs = confirmedAddressAssetSpecs.map(addressAssetSpec => {
    const {address, asset} = addressAssetSpec;
    let {balance} = addressAssetSpec;
    const charges = addressAssetSpec.charges.slice();

    for (let i = 0; i < charges.length; i++) {
      const charge = charges[i];

      if (!directlyInvalidatedCharges.includes(charge)) {
        const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(charge.payload);

        if (a === asset) {
          let applied = false;

          if (srcAddress === address) {
            balance -= quantity;
            applied = true;
          }
          if (dstAddress === address) {
            balance += quantity;
            applied = true;
          }

          if (applied) {
            charges.push(charge);
          }
        }
      }
    }

    return new AddressAssetSpec(address, asset, balance, charges);
  });

  const indirectlyInvalidatedCharges = (() => {
    const result = [];

    for (let i = 0; i < unsettledInvalidatedConfirmedAddressAssetSpecs.length; i++) {
      const assetSpec = unsettledInvalidatedConfirmedAddressAssetSpecs[i];
      const {address, asset} = assetSpec;
      let {balance} = assetSpec;
      const charges = assetSpec.charges.slice()
        .sort((a, b) => {
          const aJson = JSON.parse(a.payload);
          const bJson = JSON.parse(b.payload);

          const timestampDiff = aJson.timestamp - bJson.timestamp;
          if (timestampDiff !== 0) {
            return timestampDiff;
          } else {
            if (bigint(aJson.hash).leq(bigint(bJson.hash))) {
              return -1;
            } else {
              return 1;
            }
          }
        });

      while (balance < 0 && charges.length > 0) {
        const charge = charges.pop();
        const {quantity, srcAddress, dstAddress} = JSON.parse(charge.payload);

        if (srcAddress === address) {
          balance += quantity;
        }
        if (dstAddress === address) {
          balance -= quantity;
        }

        result.push(charge);
      }
    }

    return result;
  })();

  return directlyInvalidatedCharges.concat(indirectlyInvalidatedCharges);
};
const _getUnconfirmedMinter = (db, mempool, asset) => {
  let minter = db.minters[asset];

  const mintMessages = mempool.filter(message =>
    message.type === 'minter' && message.asset === asset ||
    message.type === 'send' && message.asset === (asset + ':mint')
  );

  let done = false;
  while (mintMessages.length > 0 && !done) {
    done = true;

    for (let i = 0; i < mintMessages.length; i++) {
      const mintMessage = mintMessages[i];
      const {type} = mintMessage;

      if (type === 'minter') {
        const {address} = mintMessage;

        if (minter === undefined) {
          minter = address;
          done = false;
          mintMessages.splice(i, 1);
          break;
        }
      } else if (type === 'send') {
        const {srcAddress, dstAddress} = mintMessage;

        if (minter === srcAddress) {
          minter = dstAddress;
          mintMessages.splice(i, 1);
          done = false;
          break;
        }
      }
    }
  }

  return minter;
};
const _commitBlock = (db, mempool, block) => {
  const {messages: blockMessages} = block;

  // update balances
  for (let i = 0; i < blockMessages.length; i++) {
    const message = blockMessages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
      const {asset, quantity, dstAddress} = payloadJson;

      let dstAddressEntry = db.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        db.balances[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAssetEntry += quantity;
      dstAddressEntry[asset] = dstAssetEntry;
    } else if (type === 'send') {
      const {asset, quantity, srcAddress, dstAddress} = payloadJson;

      let srcAddressEntry = db.balances[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        db.balances[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAssetEntry -= quantity;
      srcAddressEntry[asset] = srcAssetEntry;

      let dstAddressEntry = db.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        db.balances[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAssetEntry += quantity;
      dstAddressEntry[asset] = dstAssetEntry;

      if (/:mint$/.test(asset)) {
        db.minters[asset] = dstAddress;
      }
    } else if (type === 'charge') { // XXX disallow mint assets here
      const {asset, quantity, srcAddress, dstAddress} = payloadJson;

      let srcAddressEntry = db.balances[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        db.balances[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAssetEntry -= quantity;
      srcAddressEntry[asset] = srcAssetEntry;

      let dstAddressEntry = db.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        db.balances[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAssetEntry += quantity;
      dstAddressEntry[asset] = dstAssetEntry;
    } else if (type === 'minter') {
      const {asset, address} = payloadJson;
      const mintAsset = asset + ':mint';

      let addressEntry = db.balances[address];
      if (addressEntry === undefined){
        addressEntry = {};
        db.balances[address] = addressEntry;
      }
      let assetEntry = addressEntry[mintAsset];
      if (assetEntry === undefined) {
        assetEntry = 0;
      }
      assetEntry += 1;
      addressEntry[mintAsset] = assetEntry;

      db.minters[asset] = address;
    } else if (type === 'mint') {
      const {asset, quantity, address} = payloadJson;

      let addressEntry = db.balances[address];
      if (addressEntry === undefined){
        addressEntry = {};
        db.balances[address] = addressEntry;
      }
      let assetEntry = addressEntry[asset];
      if (assetEntry === undefined) {
        assetEntry = 0;
      }
      assetEntry += quantity;
      addressEntry[asset] = assetEntry;
    }
  }

  // add block
  db.blocks.push(block);

  // add new charges
  for (let i = 0; i < blockMessages.length; i++) {
    const message = blockMessages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'charge') {
      db.charges.push(message);
    }
  }

  // apply chargebacks
  const invalidatedCharges = _getConfirmedInvalidatedCharges(db, block);
  for (let i = 0; i < invalidatedCharges.length; i++) {
    const charge = invalidatedCharges[i];
    db.charges.splice(db.charges.indexOf(charge), 1);
  }

  // settle charges
  const oldCharges = db.charges.slice();
  for (let i = 0; i < oldCharges.length; i++) {
    const charge = oldCharges[i];
    const chargePayload = JSON.parse(charge.payload);
    const {signature} = chargePayload;
    const chargeBlockIndex = _findChargeBlockIndex(db, signature);

    if (chargeBlockIndex !== -1 && (db.blocks.length - chargeBlockIndex) >= CHARGE_SETTLE_BLOCKS) {
      const {asset, quantity, srcAddress, dstAddress} = chargePayload;

      let srcAddressEntry = db.balances[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        db.balances[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAssetEntry -= quantity;
      srcAddressEntry[asset] = srcAssetEntry;

      let dstAddressEntry = db.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        db.balances[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAssetEntry += quantity;
      dstAddressEntry[asset] = dstAssetEntry;

      db.charges.splice(db.charges.indexOf(charge), 1);
    }
  }

  return mempool.filter(message => !blockMessages.some(blockMessage => blockMessage.signature === message.signature));
};

let lastBlockTime = Date.now();
let numHashes = 0;
const doHash = () => new Promise((accept, reject) => {
  const start = Date.now();
  const startString = String(start);
  const prevHash = db.blocks.length > 0 ? db.blocks[db.blocks.length - 1].hash : bigint(0).toString(16);
  const coinbaseMessage = new Message(JSON.stringify({type: 'coinbase', asset: 'CRD', quantity: 50, dstAddress: publicKey.toString('base64'), timestamp: Date.now()}), null);
  const blockMessages = mempool.concat(coinbaseMessage);
  const blockMessagesJson = blockMessages
    .map(message => JSON.stringify(message))
    .join('\n');

  const hashRoot = (() => {
    const hash = crypto.createHash('sha256');
    hash.update(prevHash);
    hash.update(':');
    hash.update(startString);
    hash.update(':');
    hash.update(blockMessagesJson);
    return hash.digest();
  })();

  for (let nonce = 0;; nonce++) {
    const hash = crypto.createHash('sha256');
    hash.update(hashRoot);
    hash.update(String(nonce));
    const digest = hash.digest('hex');
    const digestBigint = bigint(digest, 16);

    if (digestBigint.leq(target)) {
      const block = new Block(digest, prevHash, start, blockMessages, nonce);
      accept(block);

      return;
    } else {
      const now = Date.now();
      const timeDiff = now - start;

      if (timeDiff > WORK_TIME) {
        accept(null);

        return;
      } else {
        numHashes++;
      }
    }
  }
});

const dbPath = path.join(__dirname, dataDirectory);
const _decorateDb = db => {
  db.blocks = db.blocks.map(b => Block.from(b));
  db.charges = db.charges.map(b => Message.from(b));
};
const _load = () => new Promise((accept, reject) => {
  fs.readdir(dbPath, (err, files) => {
    if (!err || err.code === 'ENOENT') {
      files = files || [];

      const bestFile = (() => {
        let result = null;
        let resultHeight = -Infinity;
        for (let i = 0; i < files.length; i++) {
          const file = files[i];
          const match = file.match(/^db-([0-9]+)\.json$/);

          if (match) {
            const numBlocks = parseInt(match[1], 10);

            if (numBlocks > resultHeight) {
              result = file;
              resultHeight = numBlocks;
            }
          }
        }
        return result;
      })();

      if (bestFile) {
        fs.readFile(path.join(dbPath, bestFile), 'utf8', (err, s) => {
          if (!err) {
            const j = JSON.parse(s);
            db = j;
            _decorateDb(db);

            accept();
          } else if (err.code === 'ENOENT') {
            accept();
          } else {
            reject(err);
          }
        });
      } else {
        accept();
      }
    } else {
      reject(err);
    }
  });
});
const _ensureDbPath = () => new Promise((accept, reject) => {
  mkdirp(dbPath, err => {
    if (!err) {
      accept();
    } else {
      reject(err);
    }
  });
});
const _save = (() => {
  let running = false;
  let queued = false;

  const _doSave = cb => {
    const _removeOldFiles = () => new Promise((accept, reject) => {
      fs.readdir(dbPath, (err, files) => {
        if (!err || err.code === 'ENOENT') {
          files = files || [];

          const keepFiles = [];
          for (let i = db.blocks.length - 1; i >= db.blocks.length - 10; i--) {
            keepFiles.push(`db-${i}.json`);
          }

          const promises = [];
          const _removeFile = p => new Promise((accept, reject) => {
            fs.unlink(p, err => {
              if (!err || err.code === 'ENOENT') {
                accept();
              } else {
                reject(err);
              }
            });
          });
          for (let i = 0; i < files.length; i++) {
            const file = files[i];

            if (!keepFiles.includes(file)) {
              promises.push(_removeFile(path.join(dbPath, file)));
            }
          }

          Promise.all(promises)
            .then(accept)
            .catch(reject);
        } else {
          reject(err);
        }
      });
    });
    const _writeNewFile = () => new Promise((accept, reject) => {
      writeFileAtomic(path.join(dbPath, `db-${db.blocks.length}.json`), JSON.stringify(db, null, 2), err => {
        if (!err) {
          accept();
        } else {
          reject(err);
        }
      });
    });

    _ensureDbPath()
      .then(() => _removeOldFiles())
      .then(() => _writeNewFile())
      .then(() => {
        cb();
      })
      .catch(err => {
        cb(err);
      });
  };
  const _recurse = () => {
    if (!running) {
      running = true;

      _doSave(err => {
        if (err) {
          console.warn(err);
        }

        running = false;

        if (queued) {
          queued = false;

          _recurse();
        }
      });
    } else {
      queued = true;
    }
  };
  return _recurse;
})();

const _listen = () => {
  const app = express();

  app.get('/balances/:address', (req, res, next) => {
    const {address, asset} = req.params;
    const balance = _getConfirmedBalances(db, address);
    res.json({balance});
  });
  app.get('/balance/:address/:asset', (req, res, next) => {
    const {address, asset} = req.params;
    const balance = _getConfirmedBalance(db, address, asset);
    res.json({balance});
  });
  app.get('/unconfirmedBalances/:address', (req, res, next) => {
    const {address, asset} = req.params;
    const balance = _getUnconfirmedUnsettledBalances(db, address);
    res.json({balance});
  });
  app.get('/unconfirmedBalance/:address/:asset', (req, res, next) => {
    const {address, asset} = req.params;
    const balance = _getUnconfirmedUnsettledBalance(db, address, asset);
    res.json({balance});
  });

  const _createSend = ({asset, quantity, srcAddress, dstAddress, timestamp, privateKey}) => {
    const privateKeyBuffer = new Buffer(privateKey, 'base64');

    if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === srcAddress) {
      if (_getUnconfirmedBalance(db, mempool, srcAddress, asset) >= quantity) {
        const payload = JSON.stringify({type: 'send', asset, quantity, srcAddress, dstAddress, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
            const signatureString = signature.toString('base64');
            const message = new Message(payload, signatureString);
            mempool.push(message);
          });
      } else {
        return Promise.reject({
          status: 400,
          stack: 'insufficient funds',
        });
      }
    } else {
      return Promise.reject({
        status: 400,
        stack: 'invalid signature',
      });
    }
  };
  app.post('/createSend', bodyParserJson, (req, res, next) => {
    const {body} = req;

    if (
      body &&
      typeof body.asset === 'string' &&
      typeof body.quantity === 'number' &&
      typeof body.srcAddress === 'string' &&
      typeof body.dstAddress === 'string' &&
      typeof body.timestamp === 'number' &&
      typeof body.privateKey === 'string'
    ) {
      const {asset, quantity, srcAddress, dstAddress, timestamp, privateKey} = body;

      _createSend({asset, quantity, srcAddress, dstAddress, timestamp, privateKey})
        .then(() => {
          res.json({ok: true});
        })
        .catch(err => {
          res.status(err.status || 500);
          res.json({error: err.stack});
        });
    } else {
      res.status(400);
      res.send({error: 'invalid parameters'});
    }
  });

  const _createMinter = ({address, asset, timestamp, privateKey}) => {
    const privateKeyBuffer = new Buffer(privateKey, 'base64');

    if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === address) {
      const minter = _getUnconfirmedMinter(db, mempool, asset);

      if (minter === undefined) {
        const payload = JSON.stringify({type: 'minter', address, asset, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
            const signatureString = signature.toString('base64');
            const message = new Message(payload, signatureString);
            mempool.push(message);
          });
      } else {
        return Promise.reject({
          status: 400,
          stack: 'asset is already minted',
        });
      }
    } else {
      return Promise.reject({
        status: 400,
        stack: 'invalid signature',
      });
    }
  };
  app.post('/createMinter', bodyParserJson, (req, res, next) => {
    const {body} = req;

    if (
      body &&
      typeof body.address === 'string' &&
      typeof body.asset === 'string' &&
      typeof body.timestamp === 'number' &&
      typeof body.privateKey === 'string'
    ) {
      const {address, asset, timestamp, privateKey} = body;

      _createMinter({address, asset, timestamp, privateKey})
        .then(() => {
          res.json({ok: true});
        })
        .catch(err => {
          res.status(err.status || 500);
          res.json({error: err.stack});
        });
    } else {
      res.status(400);
      res.send({error: 'invalid parameters'});
    }
  });

  const _createMint = ({asset, quantity, address, timestamp, privateKey}) => {
    const privateKeyBuffer = new Buffer(privateKey, 'base64');

    if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === address) {
      const minter = _getUnconfirmedMinter(db, mempool, asset);

      if (minter === address) {
        const payload = JSON.stringify({type: 'mint', asset, quantity, address, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
            const signatureString = signature.toString('base64');
            const message = new Message(payload, signatureString);
            mempool.push(message);
          });
      } else {
        return Promise.reject({
          status: 400,
          stack: 'address is not minter of this asset',
        });
      }
    } else {
      return Promise.reject({
        status: 400,
        stack: 'invalid signature',
      });
    }
  };
  app.post('/createMint', bodyParserJson, (req, res, next) => {
    const {body} = req;

    if (
      body &&
      typeof body.asset === 'string' &&
      typeof body.quantity === 'number' &&
      typeof body.address === 'string' &&
      typeof body.timestamp === 'number' &&
      typeof body.privateKey === 'string'
    ) {
      const {asset, quantity, address, timestamp, privateKey} = body;

      _createMint({asset, quantity, address, timestamp, privateKey})
        .then(() => {
          res.json({ok: true});
        })
        .catch(err => {
          res.status(err.status || 500);
          res.json({error: err.stack});
        });
    } else {
      res.status(400);
      res.send({error: 'invalid parameters'});
    }
  });

  const _createCharge = ({asset, quantity, srcAddress, dstAddress, timestamp}) => {
    if (_getUnconfirmedUnsettledBalance(db, mempool, srcAddress, asset) >= quantity) {
      const payload = JSON.stringify({type: 'charge', asset, quantity, srcAddress, dstAddress, timestamp});
      const message = new Message(payload, null);
      mempool.push(message);

      return Promise.resolve();
    } else {
      return Promise.reject({
        status: 400,
        stack: 'insufficient funds',
      });
    }
  };
  app.post('/createCharge', bodyParserJson, (req, res, next) => {
    const {body} = req;

    if (
      body &&
      typeof body.asset === 'string' &&
      typeof body.quantity === 'number' &&
      typeof body.srcAddress === 'string' &&
      typeof body.dstAddress === 'string' &&
      typeof body.timestamp === 'number'
    ) {
      const {asset, quantity, srcAddress, dstAddress, timestamp} = body;

      _createCharge({asset, quantity, srcAddress, dstAddress, timestamp})
        .then(() => {
          res.json({ok: true});
        })
        .catch(err => {
          res.status(err.status || 500);
          res.json({error: err.stack});
        });
    } else {
      res.status(400);
      res.send({error: 'invalid parameters'});
    }
  });

  const _createChargeback = ({chargeSignature, timestamp, privateKey}) => {
    const chargeMessaage = _findUnconfirmedChargeMessage(db, mempool, chargeSignature);

    if (chargeMessaage) {
      const privateKeyBuffer = new Buffer(privateKey, 'base64');
      const {srcAddress} = JSON.parse(chargeMessaage.payload);

      if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === srcAddress) {
        const payload = JSON.stringify({type: 'chargeback', chargeSignature, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
            const signatureString = signature.toString('base64');
            const message = new Message(payload, signatureString);
            mempool.push(message);
          });
      } else {
        return Promise.reject({
          status: 400,
          stack: 'invalid signature',
        });
      }
    } else {
      return Promise.reject({
        status: 400,
        stack: 'no such charge to chargeback',
      });
    }
  };
  app.post('/createChargeback', bodyParserJson, (req, res, next) => {
    const {body} = req;

    if (
      body &&
      typeof body.chargeSignature === 'string' &&
      typeof body.timestamp === 'number' &&
      typeof body.privateKey === 'string'
    ) {
      const {chargeSignature, timestamp, privateKey} = body;

      _createChargeback({chargeSignature, timestamp, privateKey})
        .then(() => {
          res.json({ok: true});
        })
        .catch(err => {
          res.status(err.status || 500);
          res.json({error: err.stack});
        });
    } else {
      res.status(400);
      res.send({error: 'invalid parameters'});
    }
  });

  const _getBlocks = ({skip, limit}) => db.blocks.slice(skip, skip + limit);
  app.get('/blocks', (req, res, next) => {
    const {skip: skipString, limit: limitString} = req.query;
    let skip = parseInt(skipString, 10);
    if (isNaN(skip)) {
      skip = 0;
    }
    let limit = parseInt(limitString, 10);
    if (isNaN(limit)) {
      limit = Infinity;
    }

    const blocks = _getBlocks({skip, limit});
    res.json({
      blocks,
    });
  });
  app.get('/blockcount', (req, res, next) => {
    const blockcount = db.blocks.length;

    res.json({
      blockcount,
    });
  });
  app.get('/db', (req, res, next) => {
    const {skip: skipString, limit: limitString} = req.query;
    const skip = parseInt(skipString, 10) || 0;
    const limit = parseInt(limitString, 10) || Infinity;

    if ((skip >= 0) && (skip >= (db.blocks.length - 10)) && ((skip + limit) <= db.blocks.length)) { // XXX hold a write lock here
      res.type('application/json');
      res.write('[');

      const _recurse = i => {
        const dbIndex = skip + i;

        if (i < limit && dbIndex < db.blocks.length) {
          const _next = () => {
            _recurse(i + 1);
          };

          if (i !== 0) {
            res.write(',\n');
          }

          if (dbIndex === (db.blocks.length - 1)) {
            res.write(JSON.stringify(db, null, 2));

            _next();
          } else {
            const rs = fs.createReadStream(path.join(dbPath, `db-${dbIndex + 1}.json`));
            rs.pipe(res, {end: false});
            rs.on('end', () => {
              _next();
            });
          }
        } else {
          res.end(']');
        }
      };
      _recurse(0);
    } else {
      res.status(404);
      res.send({error: 'skip/limit out of range'});
    }
  });

  http.createServer(app)
    .listen(port);

  const r = repl.start({
    prompt: '> ',
    terminal: true,
    eval: (cmd, context, filename, callback) => {
      const split = cmd.split(/\s/);
      const command = split[0];

      switch (command) {
        case 'db': {
          console.log(JSON.stringify(db, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'blocks': {
          console.log(JSON.stringify(db.blocks, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'blockcount': {
          console.log(JSON.stringify(db.blocks.length, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'mempool': {
          console.log(JSON.stringify(mempool, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'balances': {
          const [, address] = split;
          const balances = _getConfirmedBalances(db, address);
          console.log(JSON.stringify(balances, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'balances': {
          const [, address, asset] = split;
          const balance = _getConfirmedBalance(db, address, asset);
          console.log(JSON.stringify(balance, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'minter': {
          const [, asset] = split;
          const minter = _getUnconfirmedMinter(db, mempool, asset);
          console.log(JSON.stringify(minter, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'minters': {
          const [, asset] = split;
          console.log(JSON.stringify(db.minters, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'send': {
          const [, asset, quantityString, srcAddress, dstAddress, privateKey] = split;
          const quantityNumber = parseInt(quantityString, 10);
          const timestamp = Date.now();

          _createSend({asset, quantity: quantityNumber, srcAddress, dstAddress, timestamp, privateKey})
            .then(() => {
              console.log('ok');
              process.stdout.write('> ');
            })
            .catch(err => {
              console.warn(err);
            });
          break;
        }
        case 'minter': {
          const [, address, asset, privateKey] = split;
          const timestamp = Date.now();

          _createMinter({address, asset, timestamp, privateKey})
            .then(() => {
              console.log('ok');
              process.stdout.write('> ');
            })
            .catch(err => {
              console.warn(err);
            });
          break;
        }
        case 'mint': {
          const [, asset, quantityString, address, privateKey] = split;
          const quantityNumber = parseInt(quantityString, 10);
          const timestamp = Date.now();

          _createMint({asset, quantity: quantityNumber, address, timestamp, privateKey})
            .then(() => {
              console.log('ok');
              process.stdout.write('> ');
            })
            .catch(err => {
              console.warn(err);
            });
          break;
        }
        case 'charge': {
          const [, asset, quantity, srcAddress, dstAddress] = split;
          quantity = parseInt(quantity, 10);
          const timestamp = Date.now();

          _createCharge({asset, quantity, srcAddress, dstAddress, timestamp})
            .then(() => {
              console.log('ok');
              process.stdout.write('> ');
            })
            .catch(err => {
              console.warn(err);
            });
          break;
        }
        case 'chargeback': {
          const [, chargeSignature, privateKey] = split;
          const timestamp = Date.now();

          _createChargeback({chargeSignature, timestamp, privateKey})
            .then(() => {
              console.log('ok');
              process.stdout.write('> ');
            })
            .catch(err => {
              console.warn(err);
            });
          break;
        }
        case 'mine': {
          const [, flag] = split;

          if (flag === String(true)) {
            _startMine();
            process.stdout.write('> ');
          } else if (flag === String(false)) {
            _stopMine();
            process.stdout.write('> ');
          } else {
            console.log(mineImmediate !== null);
            process.stdout.write('> ');
          }
          break;
        }
        case 'connect': {
          const [, url] = split;
          peers.push(url);

          _sync();
          break;
        }
        default: {
          console.warn('invalid command');
          process.stdout.write('> ');
          // process.stdout.write('> ');
          break;
        }
      }
    },
  });
  replHistory(r, path.join(__dirname, 'history.txt'));
  r.on('exit', () => {
    console.log();
    process.exit(0);
  });
};

let mineImmediate = null;
const _mine = () => {
  doHash()
    .then(block => {
      if (block !== null) {
        const now = Date.now();
        const timeDiff = now - lastBlockTime;
        const timeTaken = timeDiff / 1000;
        lastBlockTime = now;
        numHashes = 0;

        mempool = _commitBlock(db, mempool, block);

        _save();
      }

      mineImmediate = setImmediate(_mine);
    });
};
const _startMine = () => {
  mineImmediate = setImmediate(_mine);
};
const _stopMine = () => {
  clearImmediate(mineImmediate);
  mineImmediate = null;
};

const _sync = () => {
  const peer = peers[Math.floor(Math.random() * peers.length)];

  const _requestBlockCount = () => new Promise((accept, reject) => {
    request(peer + '/blockcount', {
      json: true,
    }, (err, res, body) => {
      if (!err) {
        const {blockcount} = body;
        accept(blockcount);
      } else {
        reject(err);
      }
    });
  });
  const _requestSaveDb = (height, db) => new Promise((accept, reject) => {
    writeFileAtomic(path.join(dbPath, `db-${height}.json`), JSON.stringify(db, null, 2), err => {
      if (!err) {
        accept();
      } else {
        reject(err);
      }
    });
  });
  const _requestSaveDbs = (height, dbs) => {
    const promises = [];
    for (let i = 0; i < dbs.length; i++) {
      const db = dbs[i];
      promises.push(_requestSaveDb(height + i, db));
    }
    return Promise.all(promises);
  };
  const _requestDbs = ({skip, limit}) => new Promise((accept, reject) => {
    request(peer + '/db?' + querystring.stringify({
      skip,
      limit,
    }), {
      json: true,
    }, (err, res, body) => {
      if (!err) {
        const dbs = body;
        accept(dbs);
      } else {
        reject(err);
      }
    });
  });
  const _requestMempool = () => new Promise((accept, reject) => {
    request(peer + '/mempool', {
      json: true,
    }, (err, res, body) => {
      if (!err) {
        const mempool = body;
        accept(mempool);
      } else {
        reject(err);
      }
    });
  });

  _requestBlockCount()
    .then(blockcount => {
      const skip = Math.max(blockcount - 10, 0);
      const limit = 10;

      Promise.all([
        _requestDbs({skip, limit}),
        _requestMempool(),
      ])
        .then(([
          dbs,
          remoteMempool,
        ]) => {
          const _saveDbs = () => _ensureDbPath()
            .then(() => _requestSaveDbs(skip, dbs));
          const _saveDb = () => {
            if (dbs.length > 0) {
              db = dbs[dbs.length - 1];
              _decorateDb(db);
            }

            return Promise.resolve();
          };
          const _saveMempool = () => {
            for (let i = 0; i < remoteMempool.length; i++) {
              const remoteMessage = Message.from(remoteMempool[i]);

              if (!mempool.some(message => message.equals(remoteMessage))) {
                mempool.push(remoteMessage);
              }
            }
            return Promise.resolve();
          };

          Promise.all([
            _saveDbs(),
            _saveDb(),
            _saveMempool(),
          ])
            .then(() => {
              console.log('synced'); // XXX
            })
            .catch(err => {
              console.warn(err);
            });
        })
  });
};

_load()
  .then(() => _listen())
  .catch(err => {
    console.warn(err);
    process.exit(1);
  });
