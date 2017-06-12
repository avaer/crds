const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const repl = require('repl');
const replHistory = require('repl.history');

const mkdirp = require('mkdirp');
const express = require('express');
const bodyParser = require('body-parser');
const bodyParserJson = bodyParser.json();
const writeFileAtomic = require('write-file-atomic');
const bigint = require('big-integer');
const eccrypto = require('eccrypto');

const WORK_TIME = 20;

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
    const msg = mempool[i];
    const {type} = msg;

    if (type === 'coinbase') {
      const {asset, quantity, address} = JSON.parse(msg.payload);
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
      const {asset, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

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
      const {address, asset} = JSON.parse(msg.payload);
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
    const msg = mempool[i];
    const {type} = msg;

    if (type === 'coinbase') {
      const {asset: a, quantity} = JSON.parse(msg.payload);
      if (a === asset && dstAddress === address) {
        result += quantity;
      }
    } else if (type === 'send') {
      const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

      if (a === asset) {
        if (srcAddress === address) {
          result -= quantity;
        }
        if (dstAddress === address) {
          result += quantity;
        }
      }
    } else if (type === 'mint') {
      const {address: mintAddress, asset} = JSON.parse(msg.payload);
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
    const msg = mempool[i];
    const {type} = msg;

    if (type === 'coinbase') {
      const {asset: a, quantity, address} = JSON.parse(msg.payload);
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
      const {asset, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

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
      const {address, asset} = JSON.parse(msg.payload);
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

  const invalidatedCharges = _getUnconmfirmedInvalidatedCharges(db, mempool);
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
    const msg = mempool[i];
    const {type} = msg;

    if (type === 'coinbase') {
      const {asset: a, quantity} = JSON.parse(msg.payload);
      if (a === asset && dstAddress === address) {
        result += quantity;
      }
    } else if (type === 'send') {
      const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

      if (a === asset) {
        if (srcAddress === address) {
          result -= quantity;
        }
        if (dstAddress === address) {
          result += quantity;
        }
      }
    } else if (type === 'charge') {
      const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

      if (a === asset) {
        if (srcAddress === address) {
          result -= quantity;
        }
        if (dstAddress === address) {
          result += quantity;
        }
      }
    } else if (type === 'mint') {
      const {address: mintAddress, asset} = JSON.parse(msg.payload);
      const mintAsset = asset + ':mint';

      if (mintAsset === asset && mintAddress === address) {
        result += 1;
      }
    }
  }

  const invalidatedCharges = _getUnconmfirmedInvalidatedCharges(db, mempool);
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
const _findChargeMessage = (db, mempool, chargeSignature) => {
  const _findLocalChargeMessage = (message, signature) => {
    for (let i = 0; i < messages.length; i++) {
      const message = messages[i];
      const {type, signature} = message;

      if (message.type === 'charge' && signature === chargeSignature) {
        return message;
      }
    }
    return null;
  };

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
const _getUnconmfirmedInvalidatedCharges = (db, mempool) => {
  const charges = (() => {
    const result = [];

    for (let i = 0; i < db.charges.length; i++) {
      const charge = db.charges[i];
      const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

      if (a === asset) {
        result.push(msg);
      }
    }

    for (let i = 0; i < mempool.length; i++) {
      const msg = mempool[i];
      const {type} = msg;

      if (type === 'charge') {
        const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

        if (a === asset) {
          result.push(msg);
        }
      }
    }

    return result;
  })();
  const chargebacks = (() => {
    const result = [];

    for (let i = 0; i < mempool.length; i++) {
      const msg = mempool[i];
      const {type} = msg;

      if (type === 'chargeback') {
        result.push(msg);
      }
    }

    return result;
  })();
  const directlyInvalidatedCharges = chargebacks.map(chargeback => {
    const {chargeSignature} = JSON.parse(chargeback.payload);
    const chargeMessage = _findChargeMessage(db, mempool, chargeSignature);
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
  for (let i = 0; i < blockMessages.length; i++) {
    const msg = blockMessages[i];
    const {type} = msg;

    if (type === 'coinbase') {
      const {asset, quantity, dstAddress} = JSON.parse(msg.payload);

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
      const {asset, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

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
      const {asset, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

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
      const {asset, address} = JSON.parse(msg.payload);

      db.minters[asset] = address;
    } else if (type === 'mint') {
      const {asset, quantity, address} = JSON.parse(msg.payload);

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

  db.blocks.push(block);

  // XXX commit charges
  // XXX resolve chargebacks

  return mempool.filter(message => !blockMessages.some(blockMessage => blockMessage.signature === message.signature));
};

class Block {
  constructor(hash, prevHash, timestamp, messages, nonce) {
    this.hash = hash;
    this.prevHash = prevHash;
    this.timestamp = timestamp;
    this.messages = messages;
    this.nonce = nonce;
  }
}
class Message {
  constructor(type, payload, signature) {
    this.type = type;
    this.payload = payload;
    this.signature = signature;
  }
}

let lastBlockTime = Date.now();
let numHashes = 0;
const doHash = () => new Promise((accept, reject) => {
  const start = Date.now();
  const startString = String(start);
  const prevHash = db.blocks.length > 0 ? db.blocks[db.blocks.length - 1].hash : bigint(0).toString(16);
  const coinbaseMessage = new Message('coinbase', JSON.stringify({asset: 'CRD', quantity: 50, dstAddress: publicKey.toString('base64'), timestamp: Date.now()}), null);
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
    // hash.update(':');
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

const dbPath = path.join(__dirname, 'db');
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
const _save = (() => {
  let running = false;
  let queued = false;

  const _ensureDbPath = () => new Promise((accept, reject) => {
    mkdirp(dbPath, err => {
      if (!err) {
        accept();
      } else {
        reject(err);
      }
    });
  });
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

  /* app.post('/send', bodyParserJson, (req, res, next) => {
    const {body} = req;

    if (
      body &&
      typeof body.asset === 'string' &&
      typeof body.quantity === 'number' &&
      typeof body.srcAddress === 'string' &&
      typeof body.dstAddress === 'string' &&
      typeof body.timestamp === 'number' &&
      typeof body.signature === 'string'
    ) {
      const {asset, quantity, srcAddress, dstAddress, timestamp, signature} = body;

      if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === srcAddress) {
        if (_getUnconfirmedBalance(db, mempool, srcAddress, asset) >= quantity) {
          const payload = JSON.stringify({asset, quantity, srcAddress, dstAddress, timestamp});
          const payloadHash = crypto.createHash('sha256').update(payload).digest();

          eccrypto.verify(srcAddress, payloadHash, signature)
            .then(() => {
              const message = new Message('send', payload, signature);
              mempool.push(message);

              res.json({ok: true});
            }).catch(err => {
              res.status(500);
              res.json({error: err.stack});
            });
        } else {
          res.status(400);
          res.send({error: 'insufficient funds'});
        }
      } else {
        res.status(400);
        res.send({error: 'invalid signature'});
      }
    } else {
      res.status(400);
      res.send({error: 'invalid parameters'});
    }
  }); */
  const _createSend = ({asset, quantity, srcAddress, dstAddress, timestamp, privateKey}) => {
    const privateKeyBuffer = new Buffer(privateKey, 'base64');

    if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === srcAddress) {
      if (_getUnconfirmedBalance(db, mempool, srcAddress, asset) >= quantity) {
        const payload = JSON.stringify({asset, quantity, srcAddress, dstAddress, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
            const signatureString = signature.toString('base64');
            const message = new Message('send', payload, signatureString);
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
        const payload = JSON.stringify({address, asset, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
            const signatureString = signature.toString('base64');
            const message = new Message('mint', payload, signatureString);
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
        const payload = JSON.stringify({asset, quantity, address, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
            const signatureString = signature.toString('base64');
            const message = new Message('mint', payload, signatureString);
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
      const payload = JSON.stringify({asset, quantity, srcAddress, dstAddress, timestamp});
      const message = new Message('charge', payload, null);
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
    const chargeMessaage = _findChargeMessage(db, mempool, chargeSignature);

    if (chargeMessaage) {
      const privateKeyBuffer = new Buffer(privateKey, 'base64');
      const {srcAddress} = JSON.parse(chargeMessaage.payload);

      if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === srcAddress) {
        const payload = JSON.stringify({chargeSignature, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
            const signatureString = signature.toString('base64');
            const message = new Message('chargeback', payload, signatureString);
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

  http.createServer(app)
    .listen(9999);

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

      setImmediate(_mine);
    });
};

_load()
  .then(() => {
    _listen();
    _mine();
  })
  .catch(err => {
    console.warn(err);
    process.exit(1);
  });
