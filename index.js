const http = require('http');
const crypto = require('crypto');

const express = require('express');
const bodyParser = require('body-parser');
const bodyParserJson = bodyParser.json();
const bigint = require('big-integer');
const eccrypto = require('eccrypto');

const WORK_TIME = 100;

const db = {
  balances: {},
  minters: {
    'CRD': null,
  },
};
const blocks = [];
let mempool = [];

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
      const {asset: a, quantity} = JSON.parse(msg.payload);
      if (dstAddress === address) {
        result[asset] = (result[asset] !== undefined ? result[asset] : 0) + quantity;
      }
    } else if (type === 'send') {
      const {asset: a, quantity, srcAddress, dstAddress} = JSON.parse(msg.payload);

      if (a === asset) {
        if (srcAddress === address) {
          result[asset] = (result[asset] !== undefined ? result[asset] : 0) - quantity;
        }
        if (dstAddress === address) {
          result[asset] = (result[asset] !== undefined ? result[asset] : 0) + quantity;
        }
      }
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
    }
  }

  return result;
};
const _getUnconfirmedMinter = (db, mempool, asset) => {
  let minter = db.minters[asset];

  const mintMessages = mempool.filter(message =>
    message.type === 'mint' && message.asset === asset ||
    message.type === 'send' && message.asset === (asset + ':mint')
  );

  let done = false;
  while (mintMessages.length > 0 && !done) {
    done = true;

    for (let i = 0; i < mintMessages.length; i++) {
      const mintMessage = mintMessages[i];
      const {type} = mintMessage;

      if (type === 'mint') {
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
const _commitBlock = (db, mempool, blocks, block) => {
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

      if (/:mint$/.test(asset)) {
        db.minters[asset] = address;
      }
    }
  }

  blocks.push(block);

  console.log('new db', JSON.stringify(db, null, 2));

  return mempool.filter(message => !blockMessages.some(blockMessage => blockMessage.signature === message.signature));
};

const privateKey = new Buffer('9reoEGJiw+5rLuH6q9Z7UwmCSG9UUndExMPuWzrc50c=', 'base64');
const publicKey = eccrypto.getPublic(privateKey); // BCqREvEkTNfj0McLYve5kUi9cqeEjK4d4T5HQU+hv+Dv+EsDZ5HONk4lcQVImjWDV5Aj8Qy+ALoKlBAk0vsvq1Q=

const privateKey2 = new Buffer('0S5CM+e3u2Y1vx6kM/sVHUcHaWHoup1pSZ0ty1lxZek=', 'base64');
const publicKey2 = eccrypto.getPublic(privateKey); // BL6r5/T6dVKfKpeh43LmMJQrOXYOjbDX1zcwgA8hyK6ScDFUUf35NAyFq8AgQfNsMuP+LPiCreOIjdOrDV5eAD4=

const difficulty = 1e5;
const target = bigint('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16).divide(bigint(difficulty))

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
  const prevHash = blocks.length > 0 ? blocks[blocks.length - 1].hash : bigint(0).toString(16);
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

const _recurse = () => {
  doHash()
    .then(block => {
      if (block !== null) {
        const now = Date.now();
        const timeDiff = now - lastBlockTime;
        const timeTaken = timeDiff / 1000;
        console.log('block', block.hash, timeTaken + 's', Math.floor(numHashes / timeTaken) + ' h/s');
        lastBlockTime = now;
        numHashes = 0;

        mempool = _commitBlock(db, mempool, blocks, block);
      } /* else {
        console.log('no block yet');
      } */

      setImmediate(_recurse);
    });
};
_recurse();

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
  const balance = _getUnconfirmedBalances(db, address);
  res.json({balance});
});
app.get('/unconfirmedBalance/:address/:asset', (req, res, next) => {
  const {address, asset} = req.params;
  const balance = _getUnconfirmedBalance(db, address, asset);
  res.json({balance});
});

app.post('/send', bodyParserJson, (req, res, next) => {
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
});
app.post('/createSend', bodyParserJson, (req, res, next) => {
  const {body} = req;

  console.log('got body', body);

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
    const privateKeyBuffer = new Buffer(privateKey, 'base64');

    if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === srcAddress) {
      if (_getUnconfirmedBalance(db, mempool, srcAddress, asset) >= quantity) {
        const payload = JSON.stringify({asset, quantity, srcAddress, dstAddress, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        eccrypto.sign(privateKeyBuffer, payloadHash)
          .then(signature => {
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
});

app.post('/mint', bodyParserJson, (req, res, next) => {
  const {body} = req;

  if (
    body &&
    typeof body.asset === 'string' &&
    typeof body.quantity === 'number' &&
    typeof body.address === 'string' &&
    typeof body.timestamp === 'number' &&
    typeof body.signature === 'string'
  ) {
    const {asset, quantity, address, timestamp, signature} = body;

    const minter = _getUnconfirmedMinter(db, mempool, asset);
    const isNewMinter = minter === undefined;
    const isOldMinter = minter === address;
    if (isNewMinter || isOldMinter) {
      const _requestMintAsset = () => {
        const payload = JSON.stringify({asset: asset + ':mint', quantity: 1, address, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.verify(srcAddress, payloadHash, signature)
          .then(() => {
            const message = new Message('mint', payload, signature);
            mempool.push(message);
          });
      };
      const _requestBaseAsset = () => {
        const payload = JSON.stringify({asset, quantity, address, timestamp});
        const payloadHash = crypto.createHash('sha256').update(payload).digest();

        return eccrypto.verify(srcAddress, payloadHash, signature)
          .then(() => {
            const message = new Message('mint', payload, signature);
            mempool.push(message);
          });
      };

      Promise.all([
        isNewMinter ? _requestMintAsset() : Promise.resolve(),
        _requestBaseAsset(),
      ])
        .then(() => {
          res.json({ok: true});
        })
        .catch(err => {
          res.status(500);
          res.json({error: err.stack});
        });
    } else {
      res.status(400);
      res.send({error: 'address is not minter of this asset'});
    }
  } else {
    res.status(400);
    res.send({error: 'invalid parameters'});
  }
});
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
    const privateKeyBuffer = new Buffer(privateKey, 'base64');

    if (eccrypto.getPublic(privateKeyBuffer).toString('base64') === address) {
      const minter = _getUnconfirmedMinter(db, mempool, asset);
      const isNewMinter = minter === undefined;
      const isOldMinter = minter === address;

      if (isNewMinter || isOldMinter) {
        const _requestMintAsset = () => {
          const payload = JSON.stringify({asset: asset + ':mint', quantity: 1, address, timestamp});
          const payloadHash = crypto.createHash('sha256').update(payload).digest();

          return eccrypto.sign(privateKeyBuffer, payloadHash)
            .then(signature => {
              const message = new Message('mint', payload, signature);
              mempool.push(message);
            });
        };
        const _requestBaseAsset = () => {
          const payload = JSON.stringify({asset, quantity, address, timestamp});
          const payloadHash = crypto.createHash('sha256').update(payload).digest();

          return eccrypto.sign(privateKeyBuffer, payloadHash)
            .then(signature => {
              const message = new Message('mint', payload, signature);
              mempool.push(message);
            });
        };

        Promise.all([
          isNewMinter ? _requestMintAsset() : Promise.resolve(),
          _requestBaseAsset(),
        ])
          .then(() => {
            res.json({ok: true});
          })
          .catch(err => {
            res.status(500);
            res.json({error: err.stack});
          });
      } else {
        res.status(400);
        res.send({error: 'address is not minter of this asset'});
      }
    } else {
      res.status(400);
      res.send({error: 'invalid signature'});
    }
  } else {
    res.status(400);
    res.send({error: 'invalid parameters'});
  }
});

http.createServer(app).listen(9999);
