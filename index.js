const events = require('events');
const {EventEmitter} = events;
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
const ws = require('ws');
const writeFileAtomic = require('write-file-atomic');
const replHistory = require('repl.history');
const bigint = require('big-integer');
const eccrypto = require('eccrypto-sync');

const BLOCK_VERSION = '0.0.1';
const WORK_TIME = 20;
const UNDO_HEIGHT = 10;
const CHARGE_SETTLE_BLOCKS = 100;
const DEFAULT_DB = {
  balances: {},
  charges: [],
  minters: {
    'CRD': null,
  },
};

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
  constructor(hash, prevHash, height, difficulty, version, timestamp, messages, nonce) {
    this.hash = hash;
    this.f = prevHash;
    this.height = height;
    this.difficulty = difficulty;
    this.version = version;
    this.timestamp = timestamp;
    this.messages = messages;
    this.nonce = nonce;
  }

  static from(o) {
    const {hash, prevHash, height, difficulty, version, timestamp, messages, nonce} = o;
    return new Block(hash, prevHash, height, difficulty, version, timestamp, messages.map(message => Message.from(message)), nonce);
  }

  equals(block) {
    return this.hash === block.hash;
  }

  getHash() {
    const {prevHash, height, difficulty, version, timestamp, messages} = this;
    const messagesJson = messages
      .map(message => JSON.stringify(message))
      .join('\n');

    const uint64Array = new Uint64Array(1);
    const hashRoot = (() => {
      const hasher = crypto.createHash('sha256');
      hasher.update(prevHash);
      hasher.update(':');
      uint64Array[0] = height;
      hasher.update(uint64Array);
      hasher.update(':');
      uint64Array[0] = difficulty;
      hasher.update(uint64Array);
      hasher.update(':');
      hasher.update(version);
      hasher.update(':');
      uint64Array[0] = timestamp;
      hasher.update(uint64Array);
      hasher.update(':');
      hasher.update(messagesJson);
      hasher.update(':');
      return hasher.digest();
    })();

    const hasher = crypto.createHash('sha256');
    hasher.update(hashRoot);
    uint64Array[0] = nonce;
    hasher.update(uint64Array);
    return hasher.digest('hex');
  }

  verify(db, blocks, mempool = null) { // XXX this needs to check against a previous block
    const _checkHash = () => this.getHash() === this.hash;
    const _checkDifficulty = () => _checkHashMeetsTarget(this.hash, _getDifficultyTarget(this.difficulty));
    const _checkMessages = () => Promise.all(messages.map(message => message.verify(db, blocks, mempool)));

    const checks = [
      _checkHash,
      _checkDifficulty,
      _checkMessages,
    ];
    for (let i = 0; i < checks.length; i++) {
      const check = checks[i];
      const error = check();

      if (error !== null) {
        return error;
      }
    }
    return null;
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

  verify(db, blocks, mempool = null) {
    const {payload, signature} = this;
    const payloadJson = JSON.parse(payload);
    const {type} = payloadJson;

    switch (type) {
      case 'send': {
        const {asset, quantity, srcAddress} = payloadJson;
        const publicKey = srcAddress;
        const publicKeyBuffer = new Buffer(publicKey, 'base64');
        const payloadHash = crypto.createHash('sha256').update(payload).digest();
        const signatureBuffer = new Buffer(signature, 'base64');

        if (eccrypto.verify(publicKeyBuffer, payloadHash, signatureBuffer)) {
          if (confirmed) {
            if (_getConfirmedBalance(db, srcAddress, asset) >= quantity) { // XXX these need to also consider contents of the current block
              return null;
            } else {
              return {
                status: 400,
                error: 'insufficient funds',
              };
            }
          } else {
            if (_getUnconfirmedBalance(db, mempool, srcAddress, asset) >= quantity) {
              return null;
            } else {
              return {
                status: 400,
                error: 'insufficient funds',
              };
            }
          }
        } else {
          return {
            status: 400,
            error: 'invalid signature',
          };
        }
      }
      case 'minter': {
        const {asset, quantity, address} = payloadJson;
        const publicKey = address;
        const publicKeyBuffer = new Buffer(publicKey, 'base64');
        const payloadHash = crypto.createHash('sha256').update(payload).digest();
        const signatureBuffer = new Buffer(signature, 'base64');

        if (eccrypto.verify(publicKeyBuffer, payloadHash, signatureBuffer)) {
          const minter = confirmed ? _getConfirmedMinter(db, asset) : _getUnconfirmedMinter(db, mempool, asset);

          if (minter === undefined) {
            return null;
          } else {
            return {
              status: 400,
              stack: 'asset is already minted',
            };
          }
        } else {
          return {
            status: 400,
            error: 'invalid signature',
          };
        }
      }
      case 'mint': {
        const {asset, quantity, address} = payloadJson;
        const publicKey = address;
        const publicKeyBuffer = new Buffer(publicKey, 'base64');
        const payloadHash = crypto.createHash('sha256').update(payload).digest();
        const signatureBuffer = new Buffer(signature, 'base64');

        if (eccrypto.verify(publicKeyBuffer, payloadHash, signatureBuffer)) {
          const minter = confirmed ? _getConfirmedMinter(db, asset) : _getUnconfirmedMinter(db, mempool, asset);

          if (minter === address) {
            return null;
          } else {
            return {
              status: 400,
              stack: 'address is not minter of this asset',
            };
          }
        } else {
          return {
            status: 400,
            error: 'invalid signature',
          };
        }
      }
      case 'charge': {
        const {asset, quantity, srcAddress} = payloadJson;

        if (confirmed) {
          if (_getConfirmedBalance(db, srcAddress, asset) >= quantity) {
            return Promise.resolve();
          } else {
            return {
              status: 400,
              stack: 'insufficient funds',
            };
          }
        } else {
          if (_getUnconfirmedUnsettledBalance(db, mempool, srcAddress, asset) >= quantity) {
            return null;
          } else {
            return {
              status: 400,
              stack: 'insufficient funds',
            };
          }
        }
      }
      case 'chargeback': {
        const {chargeSignature} = payloadJson;
        const chargeMessaage = confirmed ? _findConfirmedChargeMessage(blocks, chargeSignature) : _findUnconfirmedChargeMessage(blocks, mempool, chargeSignature);

        if (chargeMessaage) {
          const chargeMessagePayloadJson = JSON.parse(chargeMessaage.payload);
          const {srcAddress, dstAddress} = chargeMessagePayloadJson;
          const payloadHash = crypto.createHash('sha256').update(payload).digest();
          const signatureBuffer = new Buffer(signature, 'base64');

          const _checkSignature = publicKey => {
            const publicKeyBuffer = new Buffer(publicKey, 'base64');
            return eccrypto.verify(publicKeyBuffer, payloadHash, signatureBuffer);
          };
          if (_checkSignature(srcAddress) && _checkSignature(dstAddress)) {
            return null;
          } else {
            return {
              status: 400,
              error: 'invalid signature',
            };
          }
        } else {
          return {
            status: 400,
            stack: 'no such charge to chargeback',
          };
        }
      }
      default: {
        return Promise.reject(new Error('unknown message type: ' + type));
      }
    }
  }
}

let dbs = [];
let blocks = [];
let mempool = {
  blocks: [],
  messages: [],
};
let peers = [];
const api = new EventEmitter();

const _getLatestDb = () => dbs.length > 0 ? dbs[dbs.length - 1] : DEFAULT_DB;

/* const privateKey = new Buffer('9reoEGJiw+5rLuH6q9Z7UwmCSG9UUndExMPuWzrc50c=', 'base64');
const publicKey = eccrypto.getPublic(privateKey); // BCqREvEkTNfj0McLYve5kUi9cqeEjK4d4T5HQU+hv+Dv+EsDZ5HONk4lcQVImjWDV5Aj8Qy+ALoKlBAk0vsvq1Q=

const privateKey2 = new Buffer('0S5CM+e3u2Y1vx6kM/sVHUcHaWHoup1pSZ0ty1lxZek=', 'base64');
const publicKey2 = eccrypto.getPublic(privateKey); // BL6r5/T6dVKfKpeh43LmMJQrOXYOjbDX1zcwgA8hyK6ScDFUUf35NAyFq8AgQfNsMuP+LPiCreOIjdOrDV5eAD4= */

const _clone = o => JSON.parse(JSON.stringify(o));

const _getDifficultyTarget = difficulty => bigint('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16).divide(bigint(difficulty));
const _getHashDifficulty = (hash, target) => bigint(hash).divide(target).valueOf();
const _checkHashMeetsTarget = (hash, target) => bigint(hash, 16).leq(target);
const difficulty = 1e5;
const target = _getDifficultyTarget(difficulty);

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

  for (let i = 0; i < mempool.messages.length; i++) {
    const message = mempool.messages[i];
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

  for (let i = 0; i < mempool.messages.length; i++) {
    const message = mempool.messages[i];
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

  for (let i = 0; i < mempool.messages.length; i++) {
    const message = mempool.messages[i];
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

  for (let i = 0; i < mempool.messages.length; i++) {
    const message = mempool.messages[i];
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
const _findChargeBlockIndex = (blocks, chargeSignature) => {
  for (let i = blocks.length - 1; i >= 0; i--) {
    const block = blocks[i];
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
const _findConfirmedChargeMessage = (blocks, chargeSignature) => {
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
const _findUnconfirmedChargeMessage = (blocks, mempool, chargeSignature) => {
  const confirmedChargeMessage = _findConfirmedChargeMessage(blocks, chargeSignature);

  if (confirmedChargeMessage !== null) {
    return confirmedChargeMessage;
  } else {
    return _findLocalChargeMessage(messages, mempool.messages);
  }
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
const _getConfirmedInvalidatedCharges = (db, blocks, block) => {
  const charges = db.charges.slice();
  const chargebacks = block.messages.filter(({type}) => type === 'chargeback');
  const directlyInvalidatedCharges = chargebacks.map(chargeback => {
    const {chargeSignature} = JSON.parse(chargeback.payload);
    const chargeMessage = _findConfirmedChargeMessage(blocks, chargeSignature);
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
  const charges = db.charges.concat(mempool.messages.filter(({type}) => type === 'charge'));
  const chargebacks = mempool.messages.filter(({type}) => type === 'chargeback');
  const directlyInvalidatedCharges = chargebacks.map(chargeback => {
    const {chargeSignature} = JSON.parse(chargeback.payload);
    const chargeMessage = _findUnconfirmedChargeMessage(blocks, mempool, chargeSignature);
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
const _getConfirmedMinter = (db, asset) => db.minters[asset];
const _getUnconfirmedMinter = (db, mempool, asset) => {
  let minter = db.minters[asset];

  const mintMessages = mempool.messages.filter(message =>
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
const _checkBlockExists = (blocks, mempool, block) => {
  const {height} = block;
  const comittedBlock = blocks[height - 1];

  if (comittedBlock.hash === block.hash) {
    return true;
  } else {
    return mempool.blocks.some(mempoolBlock => mempoolBlock.hash === block.hash && mempoolBlock.height === block.height);
  }
};
const _findBlockAttachPoint = (blocks, mempool, block) => {
  const {prevHash, height} = block;

  if (((height - 1) >= (blocks.length - UNDO_HEIGHT)) && ((height - 1) < blocks.length)) {
    const candidateMainChainBlock = blocks[blocks.length - 1];

    if (candidateMainChainBlock.hash === prevHash) {
      return { // valid on main chain
        type: 'mainChain',
      };
    } else {
      const candidateSideChainBlock = mempool.blocks.find(mempoolBlock => mempoolBlock.hash === prevHash && mempoolBlock.height === (height - 1));

      if (candidateSideChainBlock) {
        return { // valid side chain
          type: 'sideChain',
          prevBlock: candidateSideChainBlock, // XXX return the chain leading up to this block for verification
        };
      } else {
        return null; // in range, invalid previous hash
      }
    }
  } else {
    if ((height - 1) < (blocks.length - UNDO_HEIGHT)) {
      return {
        type: 'outOfRange',
        direction: -1,
      };
    } else {
      return {
        type: 'outOfRange',
        direction: 1,
      };
    }
  }
};

const _commitMainChainBlock = (db, blocks, mempool, block) => {
  const newDb = _clone(db);

  // update balances
  for (let i = 0; i < block.messages.length; i++) {
    const message = block.messages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
      const {asset, quantity, dstAddress} = payloadJson;

      let dstAddressEntry = newDb.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        newDb.balances[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAssetEntry += quantity;
      dstAddressEntry[asset] = dstAssetEntry;
    } else if (type === 'send') {
      const {asset, quantity, srcAddress, dstAddress} = payloadJson;

      let srcAddressEntry = newDb.balances[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        newDb.balances[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAssetEntry -= quantity;
      srcAddressEntry[asset] = srcAssetEntry;

      let dstAddressEntry = newDb.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        newDb.balances[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAssetEntry += quantity;
      dstAddressEntry[asset] = dstAssetEntry;

      if (/:mint$/.test(asset)) {
        newDb.minters[asset] = dstAddress;
      }
    } else if (type === 'charge') { // XXX disallow mint assets here
      const {asset, quantity, srcAddress, dstAddress} = payloadJson;

      let srcAddressEntry = newDb.balances[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        newDb.balances[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAssetEntry -= quantity;
      srcAddressEntry[asset] = srcAssetEntry;

      let dstAddressEntry = newDb.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        newDb.balances[dstAddress] = dstAddressEntry;
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

      let addressEntry = newDb.balances[address];
      if (addressEntry === undefined){
        addressEntry = {};
        newDb.balances[address] = addressEntry;
      }
      let assetEntry = addressEntry[mintAsset];
      if (assetEntry === undefined) {
        assetEntry = 0;
      }
      assetEntry += 1;
      addressEntry[mintAsset] = assetEntry;

      newDb.minters[asset] = address;
    } else if (type === 'mint') {
      const {asset, quantity, address} = payloadJson;

      let addressEntry = newDb.balances[address];
      if (addressEntry === undefined){
        addressEntry = {};
        newDb.balances[address] = addressEntry;
      }
      let assetEntry = addressEntry[asset];
      if (assetEntry === undefined) {
        assetEntry = 0;
      }
      assetEntry += quantity;
      addressEntry[asset] = assetEntry;
    }
  }

  // add new charges
  for (let i = 0; i < block.messages.length; i++) {
    const message = block.messages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'charge') {
      db.charges.push(message);
    }
  }

  // apply chargebacks
  const invalidatedCharges = _getConfirmedInvalidatedCharges(db, blocks, block);
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
    const chargeBlockIndex = _findChargeBlockIndex(blocks, signature);

    if (chargeBlockIndex !== -1 && ((db.blocks.length + 1) - chargeBlockIndex) >= CHARGE_SETTLE_BLOCKS) {
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

  // remove old messages from the mempool
  // XXX move this outside of this function
  for (let i = 0; i < block.messages.length; i++) {
    const blockMessage = block.messages[i];
    const mempoolMessageIndex = mempool.messages.findIndex(mempoolMessage => mempoolMessage.equals(blockMessage));

    if (mempoolMessageIndex !== -1) {
      mempool.messages.splice(mempoolMessageIndex, 1);
    }
  }

  // XXX expire invalid messages
  // XXX move that outside of this function

  return {
    newDb,
  };
};
const _commitSideChainBlock = (db, blocks, mempool, block) => {
  // add block to mempool
  if (!mempool.blocks.some(mempoolBlock => mempoolBlock.hash === block.hash)) {
    mempool.blocks.push(block);
  }

  // consider sidechain reorg
  const _getPreviousMainChainBlock = block => {
    const {prevHash, height} = block;

    if (((height - 1) >= 0) && ((height - 1) < blocks.length)) {
      const candidateMainChainBlock = blocks[height - 1];

      if (candidateMainChainBlock.hash === prevHash) {
        return candidateMainChainBlock;
      } else {
        return null;
      }
    } else {
      return null;
    }
  };
  const _getPreviousMempoolBlock = block => {
    const {prevHash} = block;
    return mempool.blocks.find(mempoolBlock => mempoolBlock.hash === prevHash) || null;
  };
  const forkedBlock = (() => {
    let b = block;

    for (;;) {
      const previousMainChainBlock = _getPreviousMainChainBlock(b);

      if (previousMainChainBlock !== null) {
        return previousMainChainBlock;
      } else {
        const previousMempoolBlock = _getPreviousMempoolBlock(b);

        if (previousMempoolBlock !== null) {
          b = previousMempoolBlock;

          continue;
        } else {
          return null;
        }
      }
    }
  })();
  const {height: forkedBlockHeight} = forkedBlock;

  const _getBlocksDifficulty = blocks => {
    let result = 0;

    for (let i = 0; i < blocks.length; i++) {
      const block = blocks[i];
      const {hash} = block;

      result += _getHashDifficulty(hash, target);
    }

    return result;
  };
  const _getSideChainBlocks = (block, forkedBlock) => {
    const result = [block];

    let b = block;
    for (;;) {
      const prevBlock = _getPreviousMempoolBlock(b) || _getPreviousMempoolBlock(b);

      result.push(prevBlock);

      if (prevBlock.hash === forkedBlock.hash) {
        break;
      }
    }
    return result;
  };
  const mainChainDifficulty = _getBlocksDifficulty(blocks.slice(forkedBlockHeight - 1));
  const sideChainDifficulty = _getBlocksDifficulty(_getSideChainBlocks(block, forkedBlock));
  if (sideChainDifficulty > mainChainDifficulty) {
    // XXX reorg
  }
};
const _addBlock = block => {
  if (!_checkBlockExists(blocks, mempool, block)) {
    const attachPoint = _findBlockAttachPoint(blocks, mempool, block);

    if (attachPoint !== null) {
      const {type} = attachPoint;

      if (type === 'mainChain') {
        const db = _getLatestDb();
        const error = block.verify(db, blocks);
        if (!error) {
          const {newDb} = _commitMainChainBlock(db, blocks, mempool, block);
          dbs.push(newDb);
          blocks.push(block);

          _save();

          api.emit('block', block);

          return null;
        } else {
          return error;
        }
      } else if (type === 'sideChain') {
        const {prevBlock} = attachPoint; // XXX verify the block first and return the error

        _commitSideChainBlock(db, blocks, mempool, block);
      } else if (type === 'outOfRange') {
        const {direction} = attachPoint;

        if (direction === -1) {
          return {
            status: 400,
            error: 'stale block',
          };
        } else {
          return {
            status: 400,
            error: 'desynchronized block',
          };
        }
      } else {
        return {
          status: 400,
          error: 'internal block attach error',
        };
      }
    } else {
      return {
        status: 400,
        error: 'invalid block',
      };
    }
  } else {
    return {
      status: 400,
      error: 'block exists',
    };
  }
};
const _addMessage = message => {
  const db = _getLatestDb();
  const error = message.verify(db, blocks, mempool);
  if (!error) {
    if (!mempool.messages.some(message => message.equals(message))) {
      mempool.messages.push(message); // XXX need to protect against replay attacks
    }

    api.emit('message', message);
  }
  return error;
};

let lastBlockTime = Date.now();
let numHashes = 0;
const doHash = () => new Promise((accept, reject) => {
  const version = BLOCK_VERSION;
  const timestamp = Date.now();
  const prevHash = blocks.length > 0 ? blocks[blocks.length - 1].hash : bigint(0).toString(16);
  const height = blocks.length + 1;
  const coinbaseMessage = new Message(JSON.stringify({type: 'coinbase', asset: 'CRD', quantity: 50, dstAddress: publicKey.toString('base64'), timestamp: Date.now()}), null);
  const allMessages = mempool.messages.concat(coinbaseMessage);
  const allMessagesJson = allMessages
    .map(message => JSON.stringify(message))
    .join('\n');

  const uint64Array = new Uint64Array(1);
  const hashRoot = (() => {
    const hasher = crypto.createHash('sha256');
    hasher.update(prevHash);
    hasher.update(':');
    uint64Array[0] = height;
    hasher.update(uint64Array);
    hasher.update(':');
    uint64Array[0] = difficulty;
    hasher.update(uint64Array);
    hasher.update(':');
    hasher.update(version);
    hasher.update(':');
    uint64Array[0] = timestamp;
    hasher.update(uint64Array);
    hasher.update(':');
    hasher.update(allMessagesJson);
    hasher.update(':');
    return hasher.digest();
  })();

  for (let nonce = 0;; nonce++) {
    const hasher = crypto.createHash('sha256');
    hasher.update(hashRoot);
    uint64Array[0] = nonce;
    hasher.update(uint64Array);
    const hash = hasher.digest('hex');

    if (_checkHashMeetsTarget(hash, target)) {
      const block = new Block(hash, prevHash, height, difficulty, version, timestamp, blockMessages, nonce);
      accept(block);

      return;
    } else {
      const now = Date.now();
      const timeDiff = now - timestamp;

      if (timeDiff > WORK_TIME) {
        accept(null);

        return;
      } else {
        numHashes++;
      }
    }
  }
});

const dataPath = path.join(__dirname, dataDirectory);
const dbDataPath = path.join(dataPath, 'db');
const blocksDataPath = path.join(dataPath, 'blocks');
const _decorateDb = db => {
  db.charges = db.charges.map(b => Message.from(b));
};
const _decorateDbs = dbs => {
  for (let i = 0; i < dbs.length; i++) {
    const db = dbs[i];
    _decorateDb(db);
  }
};
const _decorateBlocks = blocks => {
  for (let i = 0; i < blocks.length; i++) {
    blocks[i] = Block.from(blocks[i]);
  }
};
const _load = () => {
  const _readdirDbs = () => new Promise((accept, reject) => {
    fs.readdir(dbDataPath, (err, files) => {
      if (!err || err.code === 'ENOENT') {
        files = files || [];

        accept(files);
      } else {
        reject(err);
      }
    });
  });
  const _readdirBlocks = () => new Promise((accept, reject) => {
    fs.readdir(blocksDataPath, (err, files) => {
      if (!err || err.code === 'ENOENT') {
        files = files || [];

        accept(files);
      } else {
        reject(err);
      }
    });
  });

  return Promise.resolve([
    _readdirDbs(),
    _readdirBlocks(),
  ])
    .then(([
      dbFiles,
      blockFiles,
    ]) => {
      const bestBlockHeight = (() => {
        for (let height = 1; height < blockFiles.length; height++) {
          const foundBlockAtThisHeight = blockFiles.some(file => {
            const match = file.match(/^block-([0-9]+)\.json$/);
            return Boolean(match) && parseInt(match[1], 10) === height;
          });

          if (!foundBlockAtThisHeight) {
            return height - 1;
          }
        }
      })();

      if (bestBlockHeight > 0) { // load dbs and blocks from disk
        const _readDbFiles = {
          const candidateHeights = (() => {
            const result = [];

            const _haveDbFile = height => dbFiles.some(file => {
              const match = file.match(/^db-([0-9]+)\.json$/);
              return Boolean(match) && parseInt(match[1], 10) === height;
            });
            for (let i = bestBlockHeight; (i >= (bestBlockHeight - UNDO_HEIGHT)) && (i > 0) && _haveDbFile(i); i--) {
              result.push(i);
            }
            return result;
          })();
          const _readDbFile = height => new Promise((accept, reject) => {
            fs.readFile(path.join(dbDataPath, `db-${height}.json`), 'utf8', (err, s) => {
              if (!err) {
                const db = JSON.parse(s);
                accept(db);
              } else {
                reject(err);
              }
            });
          });
          return candidateHeights.map(height => _readDbFile(height))
        };
        const _readBlockFiles = () => new Promise((accept, reject) => {
          const blocks = [];

          const _readBlockFile = height => new Promise((accept, reject) => {
            fs.readFile(path.join(blocksDataPath, `block-${height}.json`), 'utf8', (err, s) => {
              if (!err) {
                const block = JSON.parse(s);
                accept(block);
              } else {
                reject(err);
              }
            });
          });
          const _recurse = height => {
            if (height <= bestBlockHeight) {
              _readBlockFile()
                .then(block => {
                  blocks.push(block);

                  _recurse(height + 1);
                })
                .catch(reject);
            } else {
              accept(blocks);
            }
          };
          _recurse(1);
        });

        return Promise.all([
          _readDbFiles(),
          _readBlockFiles(),
        ])
          .then(([
            newDbs,
            newBlocks,
          ]) => {
            // NOTE: we are assuming no file corruption
            dbs = newDbs;
            _decorateDbs(db);

            blocks = newBlocks;
            _decorateBlocks(blocks);
          });
      } else { // nothing to salvage; bootstrap db and do a full sync
        dbs = [];
        _decorateDbs(dbs);

        blocks = [];
        _decorateBlocks(blocks);

        return Promise.resolve();
      }
    });
  });
});
const _ensureDbPath = () => new Promise((accept, reject) => {
  mkdirp(dataPath, err => {
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
    const _writeNewFiles = () => new Promise((accept, reject) => {
      const promises = [];
      const _writeFile = (p, d) => new Promise((accept, reject) => {
        writeFileAtomic(p, d, err => {
          if (!err || err.code === 'ENOENT') {
            accept();
          } else {
            reject(err);
          }
        });
      });
      for (let i = 0; i < blocks.length; i++) {
        const block = blocks[i];
        const {height} = block;
        promises.push(_writeFile(path.join(dbPath, `block-${height}.json`)), JSON.stringify(block, null 2));

        const db = dbs[i];
        promises.push(_writeFile(path.join(dbPath, `db-${height}.json`)), JSON.stringify(db, null 2));
      }

      return Promise.all(promises);
    });
    const _removeOldFiles = () => new Promise((accept, reject) => {
      const _removeDbFiles = () => new Promise((accept, reject) => {
        fs.readdir(dbDataPath, (err, dbFiles) => {
          if (!err || err.code === 'ENOENT') {
            dbFiles = dbFiles || [];

            const keepDbFiles = [];
            for (let i = 0; i < blocks.length; i++) {
              const block = blocks[i];
              const {height} = block;
              keepDbFiles.push(`db-${height}.json`);
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
            for (let i = 0; i < dbFiles.length; i++) {
              const dbFile = dbFiles[i];

              if (!keepDbFiles.includes(dbFile)) {
                promises.push(_removeFile(path.join(dbDataPath, dbFile)));
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
      const _removeBlockFiles = new Promise((accept, reject) => {
        fs.readdir(blocksDataPath, (err, blockFiles) => {
          if (!err || err.code === 'ENOENT') {
            blockFiles = blockFiles || [];

            const topBlockHeight = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;

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
            for (let i = 0; i < blockFiles.length; i++) {
              const blockFile = blockFiles[i];
              const match = blockFile.match(/^block-([0-9]+)\.json$/);

              const _remove = () => {
                promises.push(_removeFile(path.join(blocksDataPath, blockFile)));
              };

              if (match) {
                const height = parseInt(match[1], 10);

                if (height >= 1 && height <= topBlockHeight) {
                  // nothing
                } else {
                  _remove();
                } 
              } else {
                _remove();
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

      return Promise.all([
        _removeDbFiles(),
        _removeBlockFiles(),
      ]);
    });

    _ensureDbPath()
      .then(() => _writeNewFiles())
      .then(() => _removeOldFiles())
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
    const db = _getLatestDb();
    const balance = _getConfirmedBalances(db, address);
    res.json({balance});
  });
  app.get('/balance/:address/:asset', (req, res, next) => {
    const {address, asset} = req.params;
    const db = _getLatestDb();
    const balance = _getConfirmedBalance(db, address, asset);
    res.json({balance});
  });
  app.get('/unconfirmedBalances/:address', (req, res, next) => {
    const {address, asset} = req.params;
    const db = _getLatestDb();
    const balance = _getUnconfirmedUnsettledBalances(db, address);
    res.json({balance});
  });
  app.get('/unconfirmedBalance/:address/:asset', (req, res, next) => {
    const {address, asset} = req.params;
    const db = _getLatestDb();
    const balance = _getUnconfirmedUnsettledBalance(db, address, asset);
    res.json({balance});
  });

  const _createSend = ({asset, quantity, srcAddress, dstAddress, timestamp, privateKey}) => {
    const privateKeyBuffer = new Buffer(privateKey, 'base64');
    const payload = JSON.stringify({type: 'send', asset, quantity, srcAddress, dstAddress, timestamp});
    const payloadHash = crypto.createHash('sha256').update(payload).digest();

    const signature = eccrypto.sign(privateKeyBuffer, payloadHash)
    const signatureString = signature.toString('base64');
    const message = new Message(payload, signatureString);
    const db = _getLatestDb();
    const error = message.verify(db, blocks, mempool);
    if (!error) {
      _addMessage(message);

      return Promise.resolve();
    } else {
      return Promise.reject(error);
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
    const payload = JSON.stringify({type: 'minter', address, asset, timestamp});
    const payloadHash = crypto.createHash('sha256').update(payload).digest();
    const signature = eccrypto.sign(privateKeyBuffer, payloadHash)
    const signatureString = signature.toString('base64');
    const message = new Message(payload, signatureString);
    const db = _getLatestDb();
    const error = message.verify(db, blocks, mempool);
    if (!error) {
      _addMessage(message);

      return Promise.resolve();
    } else {
      return Promise.reject(error);
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
    const payload = JSON.stringify({type: 'mint', asset, quantity, address, timestamp});
    const payloadHash = crypto.createHash('sha256').update(payload).digest();
    const signature = eccrypto.sign(privateKeyBuffer, payloadHash)
    const signatureString = signature.toString('base64');
    const message = new Message(payload, signatureString);
    const db = _getLatestDb();
    const error = message.verify(db, blocks, mempool);
    if (!error) {
      _addMessage(message);

      return Promise.resolve();
    } else {
      return Promise.reject(error);
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
    const payload = JSON.stringify({type: 'charge', asset, quantity, srcAddress, dstAddress, timestamp});
    const message = new Message(payload, null);
    const db = _getLatestDb();
    const error = message.verify(db, blocks, mempool);
    if (!error) {
      _addMessage(message);

      return Promise.resolve();
    } else {
      return Promise.reject(error);
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
    const payload = JSON.stringify({type: 'chargeback', chargeSignature, timestamp});
    const payloadHash = crypto.createHash('sha256').update(payload).digest();
    const signature = eccrypto.sign(privateKeyBuffer, payloadHash)
    const signatureString = signature.toString('base64');
    const message = new Message(payload, signatureString);
    const db = _getLatestDb();
    const error = message.verify(db, blocks, mempool);
    if (!error) {
      _addMessage(message);

      return Promise.resolve();
    } else {
      return Promise.reject(error);
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

    const blocks = blocks.slice(skip, skip + limit);
    res.json({
      blocks,
    });
  });
  app.get('/blockcount', (req, res, next) => {
    const blockcount = blocks.length;

    res.json({
      blockcount,
    });
  });

  const server = http.createServer(app)
  const wss = new ws.Server({
    noServer: true,
  });
  const connections = [];
  wss.on('connection', c => {
    const {url} = c.upgradeReq;

    if (url === '/listen') {
      connections.push(c);

      c.on('close', () => {
        connections.splice(connections.indexOf(c), 1);
      });
    } else {
      c.close();
    }
  });
  server.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, c => {
      c.upgradeReq = req;

      wss.emit('connection', c);
    });
  });
  server.listen(port);

  api.on('block', block => {
    const e = {
      type: 'block',
      block: block,
    };
    const es = JSON.stringify(e);

    for (let i = 0; i < connections.length; i++) {
      const connection = connections[i];
      connection.send(es);
    }
  });
  api.on('message', message => {
    const e = {
      type: 'message',
      message: message,
    };
    const es = JSON.stringify(e);

    for (let i = 0; i < connections.length; i++) {
      const connection = connections[i];
      connection.send(es);
    }
  });

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
          console.log(JSON.stringify(blocks, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'blockcount': {
          console.log(JSON.stringify(blocks.length, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'mempool': {
          console.log(JSON.stringify(mempool.messages, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'forks': {
          console.log(JSON.stringify(mempool.blocks, null, 2));
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

        _commitMainChainBlock(db, blocks, mempool, block);

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

  const _requestSaveDb = (height, db) => new Promise((accept, reject) => {
    writeFileAtomic(path.join(dataPath, `db-${height}.json`), JSON.stringify(db, null, 2), err => {
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
  const _requestBlocks = ({skip, limit}) => new Promise((accept, reject) => {
    const q = {};
    if (skip !== undefined) {
      q.skip = skip;
    }
    if (limit !== undefined) {
      q.limit = limit;
    }
    request(peer + '/blocks?' + querystring.stringify(q), {
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
  const _connect = () => {
    const c = new ws(peer.replace(/^http/, 'ws') + '/listen');
    c.on('open', () => {
      console.log('peer connection open', peer);

      c.on('message', s => {
        const m = JSON.parse(s);
        const {type} = m;

        switch (type) {
          case 'block': {
            const {block} = m;
            const error = _addBlock(block);
            if (error) {
              console.warn('add remote block error:', err);
            }
            break;
          }
          case 'message': {
            const {message} = m;
            const error = _addMessage(message);
            if (error) {
              console.warn('add remote message error:', err);
            }
            break;
          }
          default: {
            console.warn('unknown message type:', msg);
            break;
          }
        }
      });
      c.on('close', () => {
        console.log('peer connection closed', peer);
      });
    });
    c.on('error', err => {
      console.warn(err);
    });
  };

  Promise.all([
    _requestBlocks({
      skip: Math.max(blocks.length - 10, 0),
    }),
    _requestMempool(),
  ])
    .then(([
      remoteBlocks,
      remoteMempool,
    ]) => {
      const _addBlocks = () => {
        for (let i = 0; i < remoteBlocks.length; i++) {
          const block = remoteBlocks[i];
          const error = _addBlock(block);
          if (error) {
            console.warn(error);
          }
        }
        return Promise.resolve();
      };
      const _addMempool = () => {
        const {blocks, messages} = remoteMempool;

        for (let i = 0; i < blocks.length; i++) {
          const block = Block.from(blocks[i]);
          const error = _addBlock(block);
          if (error) {
            console.warn(error);
          }
        }
        for (let i = 0; i < messages.length; i++) {
          const message = Message.from(messages[i]);
          const error = _addMessage(message);
          if (error) {
            console.warn(error);
          }
        }
        return Promise.resolve();
      };

      Promise.all([
        _addBlocks(),
        _addMempool(),
      ])
        .then(() => {
          _connect();

          console.log('synced'); // XXX
        })
        .catch(err => {
          console.warn(err);
        });
    });
};

_load()
  .then(() => _listen())
  .catch(err => {
    console.warn(err);
    process.exit(1);
  });
