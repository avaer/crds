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
const MESSAGE_TTL = 10;
const UNDO_HEIGHT = 10;
const CHARGE_SETTLE_BLOCKS = 100;
const HASH_WORK_TIME = 20;
const MIN_NUM_LIVE_PEERS = 10;
const CRD = 'CRD';
const COINBASE_QUANTITY = 1;
const COINBASE_PRIVATE_KEY = (() => {
  const result = Buffer.alloc(32);
  result[0] = 0xFF;
  return result;
})();
const COINBASE_PUBLIC_KEY = eccrypto.getPublic(COINBASE_PRIVATE_KEY);
const DEFAULT_DB = {
  balances: {},
  charges: [],
  messageRevocations: [],
  minters: {
    [CRD]: null,
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
const protocol = parseInt(_findArg('protocol')) || 'http';
const host = parseInt(_findArg('host')) || '0.0.0.0';
const port = parseInt(_findArg('port')) || 9999;
const localUrl = `${protocol}://${host}:${port}`;
const dataDirectory = _findArg('dataDirectory') || 'data';

class Block {
  constructor(hash, prevHash, height, difficulty, version, timestamp, messages, nonce) {
    this.hash = hash;
    this.prevHash = prevHash;
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
    const {prevHash, height, difficulty, version, timestamp, messages, nonce} = this;
    const messagesJson = messages
      .map(message => JSON.stringify(message))
      .join('\n');

    const uint64Array = new Uint32Array(1);
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

  verify(db, blocks, mempool = null) {
    const _checkHash = () => this.getHash() === this.hash;
    const _checkDifficulty = () => _checkHashMeetsTarget(this.hash, _getDifficultyTarget(this.difficulty));
    const _checkPrevHash = () => {
      const prevBlockHash = (blocks.length > 0) ? blocks[blocks.length - 1].hash : zeroHash;
      return this.prevHash === prevBlockHash;
    };
    const _checkHeight = () => {
      const nextBlockHeight = ((blocks.length > 0) ? blocks[blocks.length - 1].height : 0) + 1;
      return this.height === nextBlockHeight;
    };
    const _verifyMessages = () => {
      for (let i = 0; i < this.messages.length; i++) {
        const message = this.messages[i];
        const error = message.verify(db, blocks, mempool);
        if (error) {
          return error;
        }
      }
      return null;
    };

    if (!_checkHash()) {
      return {
        status: 400,
        error: 'invalid hash',
      };
    } else if (!_checkDifficulty()) {
      return {
        status: 400,
        error: 'invalid difficulty',
      };
    } else if (!_checkPrevHash()) {
      return {
        status: 400,
        error: 'invalid previous hash',
      };
    } else if (!_checkHeight()) {
      return {
        status: 400,
        error: 'invalid height',
      };
    } else {
      const error = _verifyMessages();

      if (!error) {
        return null;
      } else {
        return error;
      }
    }
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

    if (signature) {
      const payloadJson = JSON.parse(payload);
      const {startHeight} = payloadJson;
      const endHeight = startHeight + MESSAGE_TTL;
      const nextHeight = ((blocks.length > 0) ? blocks[blocks.length - 1].height : 0) + 1;

      if (nextHeight >= startHeight && nextHeight < endHeight) {
        if (!db.messageRevocations.some(signatures => signatures.includes(signature))) {
          const {type} = payloadJson;

          switch (type) {
            case 'coinbase': {
              const {asset, quantity, address} = payloadJson;
              const publicKeyBuffer = COINBASE_PUBLIC_KEY;
              const payloadHash = crypto.createHash('sha256').update(payload).digest();
              const signatureBuffer = new Buffer(signature, 'base64');

              if (eccrypto.verify(publicKeyBuffer, payloadHash, signatureBuffer)) {
                if (asset === CRD && quantity === COINBASE_QUANTITY) {
                  return null;
                } else {
                  return {
                    status: 400,
                    error: 'invalid coinbase',
                  };
                }
              } else {
                return {
                  status: 400,
                  error: 'invalid signature',
                };
              }

              break;
            }
            case 'send': {
              const {asset, quantity, srcAddress} = payloadJson;
              const publicKey = srcAddress;
              const publicKeyBuffer = new Buffer(publicKey, 'base64');
              const payloadHash = crypto.createHash('sha256').update(payload).digest();
              const signatureBuffer = new Buffer(signature, 'base64');

              if (eccrypto.verify(publicKeyBuffer, payloadHash, signatureBuffer)) {
                if (quantity > 0 && _roundToCents(quantity) === quantity) {
                  if (!mempool) {
                    if (_getConfirmedBalance(db, srcAddress, asset) >= quantity) {
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
                    error: 'invalid quantity',
                  };
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
                if (quantity > 0 && _roundToCents(quantity) === quantity) {
                  const minter = !mempool ? _getConfirmedMinter(db, asset) : _getUnconfirmedMinter(db, mempool, asset);

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
                    error: 'invalid quantity',
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
                if (quantity > 0 && _roundToCents(quantity) === quantity) {
                  const minter = !mempool ? _getConfirmedMinter(db, asset) : _getUnconfirmedMinter(db, mempool, asset);

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
                    error: 'invalid quantity',
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

              if (quantity > 0 && _roundToCents(quantity) === quantity) {
                if (!mempool) {
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
              } else {
                return {
                  status: 400,
                  error: 'invalid quantity',
                };
              }
            }
            case 'chargeback': {
              const {chargeSignature} = payloadJson;
              const chargeMessaage = !mempool ? _findConfirmedChargeMessage(blocks, chargeSignature) : _findUnconfirmedChargeMessage(blocks, mempool, chargeSignature);

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
        } else {
          return {
            status: 400,
            error: 'replay detected',
            soft: true,
          };
        }
      } else {
        return {
          status: 400,
          error: 'ttl expired',
        };
      }
    } else {
      return {
        status: 400,
        error: 'missing signature',
      };
    }
  }
}
class Peer {
  constructor(url) {
    this.url = url;

    this._connection = null;
    this._enabled = null;
    this._reconnectTimeout = null;
    this._redownloadInterval = null;
  }

  equals(peer) {
    return this.url === peer.url;
  }

  isEnabled() {
    return this._enabled;
  }

  enable() {
    this._enabled = true;

    const _listen = () => {
      const _recurse = () => {
        const c = new ws(this.url.replace(/^http/, 'ws') + '/listen');
        c.on('open', () => {
          c.on('message', s => {
            const m = JSON.parse(s);
            const {type} = m;

            switch (type) {
              case 'block': {
                const {block: blockJson} = m;
                const block = Block.from(blockJson);
                const error = _addBlock(dbs, blocks, mempool, block);
                if (error && !error.soft) {
                  console.warn('add remote block error:', error);
                }
                break;
              }
              case 'message': {
                const {message: messgeJson} = m;
                const message = Message.from(messgeJson);
                const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
                const error = _addMessage(db, blocks, mempool, message);
                if (error && !error.soft) {
                  console.warn('add remote message error:', error);
                }
                break;
              }
              case 'peer': {
                const {peer} = m;
                _addPeer(peer);
                break;
              }
              default: {
                console.warn('unknown message type:', msg);
                break;
              }
            }
          });
          c.on('close', () => {
            this._connection = null;

            if (this._enabled) {
              _retry();
            }
          });
        });
        c.on('error', err => {
          // console.warn(err);

          this._connection = null;

          if (this._enabled) {
            _retry();
          }
        });

        this._connection = c;
      };
      const _retry = () => {
        this._reconnectTimeout = setTimeout(() => {
          this._reconnectTimeout = null;

          _recurse();
        }, 1000);
      };

      _recurse();
    };
    const _download = () => {
      const _recurse = () => {
        const _requestBlocks = ({startHeight}) => new Promise((accept, reject) => {
          const result = [];

          const _recurse = height => {
            request(this.url + '/blocks/' + height, {
              json: true,
            }, (err, res, body) => {
              if (!err) {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                  const block = body;
                  result.push(block);

                  _recurse(height + 1);
                } else if (res.statusCode === 404) {
                  accept(result);
                } else {
                  reject({
                    status: res.statusCode,
                    error: 'invalid status code',
                  });
                }
              } else {
                reject(err);
              }
            });
          };
          _recurse(startHeight);
        });
        const _requestMempool = () => new Promise((accept, reject) => {
          request(this.url + '/mempool', {
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
        const _requestPeers = () => new Promise((accept, reject) => {
          request(this.url + '/peers', {
            json: true,
          }, (err, res, body) => {
            if (!err) {
              const peers = body;
              accept(peers);
            } else {
              reject(err);
            }
          });
        });

        const topBlockHeight = (blocks.length > 0) ? blocks[blocks.length - 1].height : 0;
        Promise.all([
          _requestBlocks({
            startHeight: Math.max(topBlockHeight - CHARGE_SETTLE_BLOCKS, 1),
          }),
          _requestMempool(),
          _requestPeers(),
        ])
          .then(([
            remoteBlocks,
            remoteMempool,
            remotePeers,
          ]) => {
            const _addBlocks = () => {
              for (let i = 0; i < remoteBlocks.length; i++) {
                const remoteBlock = Block.from(remoteBlocks[i]);
                const error = _addBlock(dbs, blocks, mempool, remoteBlock);
                if (error && !error.soft) {
                  console.warn('add remote block error:', error);
                }
              }
            };
            const _addMempool = () => {
              const {blocks: remoteBlocks, messages: remoteMessages} = remoteMempool;

              for (let i = 0; i < remoteBlocks.length; i++) {
                const remoteBlock = Block.from(remoteBlocks[i]);
                const error = _addBlock(dbs, blocks, mempool, remoteBlock);
                if (error && !error.soft) {
                  console.warn('add remote block error:', error);
                }
              }
              for (let i = 0; i < remoteMessages.length; i++) {
                const remoteMessage = Message.from(remoteMessages[i]);
                const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
                const error = _addMessage(db, blocks, mempool, remoteMessage);
                if (error && !error.soft) {
                  console.warn('add remote message error:', error);
                }
              }
            };
            const _addPeers = () => {
              for (let i = 0; i < remotePeers.length; i++) {
                const url = remotePeers[i];
                _addPeer(url);
              }
            };

            _addBlocks();
            _addMempool();
            _addPeers();
          })
          .catch(err => {
            // console.warn(err);
          });
      };

      this._redownloadInterval = setInterval(() => {
        this._redownloadInterval = null;

        _recurse();
      }, 30 * 1000);

      _recurse();
    };

    _listen();
    _download();
  }

  disable() {
    this._enabled = false;

    if (this._reconnectTimeout) {
      clearTimeout(this._reconnectTimeout);

      this._reconnectTimeout = null;
    }
    if (this._redownloadInterval) {
      clearInterval(this._redownloadInterval);

      this._redownloadInterval = null;
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

/* const privateKey = new Buffer('9reoEGJiw+5rLuH6q9Z7UwmCSG9UUndExMPuWzrc50c=', 'base64');
const publicKey = eccrypto.getPublic(privateKey); // BCqREvEkTNfj0McLYve5kUi9cqeEjK4d4T5HQU+hv+Dv+EsDZ5HONk4lcQVImjWDV5Aj8Qy+ALoKlBAk0vsvq1Q=

const privateKey2 = new Buffer('0S5CM+e3u2Y1vx6kM/sVHUcHaWHoup1pSZ0ty1lxZek=', 'base64');
const publicKey2 = eccrypto.getPublic(privateKey); // BL6r5/T6dVKfKpeh43LmMJQrOXYOjbDX1zcwgA8hyK6ScDFUUf35NAyFq8AgQfNsMuP+LPiCreOIjdOrDV5eAD4= */

const _clone = o => JSON.parse(JSON.stringify(o));
const _roundToCents = n => Math.round(n * 100) / 100;

const _getDifficultyTarget = difficulty => bigint('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16).divide(bigint(difficulty));
const _getHashDifficulty = (hash, target) => bigint(hash).divide(target).valueOf();
const _checkHashMeetsTarget = (hash, target) => bigint(hash, 16).leq(target);
const difficulty = 1e5;
const target = _getDifficultyTarget(difficulty);
const zeroHash = bigint(0).toString(16);

const _getAllConfirmedBalances = db => _clone(db.balances);
const _getConfirmedBalances = (db, address) => _clone(db.balances[address] || {});
const _getConfirmedBalance = (db, address, asset) => {
  let balance = (db.balances[address] || {})[asset];
  if (balance === undefined) {
    balance = 0;
  }
  return balance;
};
const _getAllUnconfirmedBalances = (db, mempool) => {
  const result = _getAllConfirmedBalances(db);

  for (let i = 0; i < mempool.messages.length; i++) {
    const message = mempool.messages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
      const {asset, quantity, address} = payloadJson;

      let addressEntry = result[address];
      if (addressEntry === undefined){
        addressEntry = {};
        result[address] = addressEntry;
      }
      let assetEntry = addressEntry[asset];
      if (assetEntry === undefined) {
        assetEntry = 0;
      }
      addressEntry[asset] = _roundToCents(assetEntry + quantity);
    } else if (type === 'send') {
      const {asset, quantity, srcAddress, dstAddress} = payloadJson;

      let srcAddressEntry = result[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        result[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAddressEntry[asset] = _roundToCents(srcAssetEntry - quantity);

      let dstAddressEntry = result[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        result[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAddressEntry[asset] = _roundToCents(dstAssetEntry + quantity);
    } else if (type === 'minter') {
      const {address, asset} = payloadJson;
      const mintAsset = asset + ':mint';

      let addressEntry = result[address];
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
const _getUnconfirmedBalances = (db, mempool, address) => {
  let result = _getConfirmedBalances(db, address);

  for (let i = 0; i < mempool.messages.length; i++) {
    const message = mempool.messages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
      const {asset, quantity, address: localAddress} = payloadJson;

      if (localAddress === address) {
        let assetEntry = result[asset];
        if (assetEntry === undefined) {
          assetEntry = 0;
        }
        result[asset] = _roundToCents(assetEntry + quantity);
      }
    } else if (type === 'send') {
      const {asset, quantity, srcAddress, dstAddress} = payloadJson;

      if (srcAddress === address) {
        let srcAssetEntry = result[asset];
        if (srcAssetEntry === undefined) {
          srcAssetEntry = 0;
        }
        result[asset] = _roundToCents(srcAssetEntry - quantity);
      }

      if (dstAddress === address) {
        let dstAssetEntry = result[asset];
        if (dstAssetEntry === undefined) {
          dstAssetEntry = 0;
        }
        result[asset] = _roundToCents(dstAssetEntry + quantity);
      }
    } else if (type === 'minter') {
      const {address: localAddress, asset} = payloadJson;

      if (localAddress === address) {
        const mintAsset = asset + ':mint';

        let assetEntry = result[mintAsset];
        if (assetEntry === undefined) {
          assetEntry = 0;
        }
        assetEntry += 1;
        result[mintAsset] = assetEntry;
      }
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
      const {asset: localAsset, quantity, address: localAddress} = payloadJson;

      if (localAsset === asset && localAddress === address) {
        result = _roundToCents(result + quantity);
      }
    } else if (type === 'send') {
      const {asset: a, quantity, srcAddress, dstAddress} = payloadJson;

      if (a === asset) {
        if (srcAddress === address) {
          result = _roundToCents(result - quantity);
        }
        if (dstAddress === address) {
          result = _roundToCents(result + quantity);
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

      let addressEntry = db.balances[address];
      if (addressEntry === undefined){
        addressEntry = {};
        result[address] = addressEntry;
      }
      let assetEntry = addressEntry[asset];
      if (assetEntry === undefined) {
        assetEntry = 0;
      }
      addressEntry[asset] = _roundToCents(assetEntry + quantity);
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
      srcAddressEntry[asset] = _roundToCents(srcAssetEntry - quantity);

      let dstAddressEntry = db.balances[dstAddress];
      if (dstAddressEntry === undefined){
        dstAddressEntry = {};
        result[dstAddress] = dstAddressEntry;
      }
      let dstAssetEntry = dstAddressEntry[asset];
      if (dstAssetEntry === undefined) {
        dstAssetEntry = 0;
      }
      dstAddressEntry[asset] = _roundToCents(dstAssetEntry + quantity);
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
    srcAddressEntry[asset] = _roundToCents(srcAssetEntry + quantity);

    let dstAddressEntry = db.balances[dstAddress];
    if (dstAddressEntry === undefined){
      dstAddressEntry = {};
      result[dstAddress] = dstAddressEntry;
    }
    let dstAssetEntry = dstAddressEntry[asset];
    if (dstAssetEntry === undefined) {
      dstAssetEntry = 0;
    }
    dstAddressEntry[asset] = _roundToCents(dstAssetEntry - quantity);
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
      const {asset: localAsset, quantity, address: localAddress} = payloadJson;

      if (localAsset === asset && localAddress === address) {
        result = _roundToCents(result + quantity);
      }
    } else if (type === 'send') {
      const {asset: a, quantity, srcAddress, dstAddress} = payloadJson;

      if (a === asset) {
        if (srcAddress === address) {
          result = _roundToCents(result - quantity);
        }
        if (dstAddress === address) {
          result = _roundToCents(result + quantity);
        }
      }
    } else if (type === 'charge') {
      const {asset: a, quantity, srcAddress, dstAddress} = payloadJson;

      if (a === asset) {
        if (srcAddress === address) {
          result = _roundToCents(result - quantity);
        }
        if (dstAddress === address) {
          result = _roundToCents(result + quantity);
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
        result = _roundToCents(result + quantity);
      }
      if (dstAddress === address) {
        result = _roundToCents(result - quantity);
      }
    }
  }

  return result;
};
const _getConfirmedCharges = (db, address) => db.charges.filter(charge => {
  const payloadJson = JSON.parse(charge.payload);
  const {srcAddress, dstAddress} = payloadJson;
  return srcAddress === address || dstAddress === address;
});
const _getUnconfirmedCharges = (db, mempool, address) => {
  const result = _getConfirmedCharges(db, address);

  for (let i = 0; i < mempool.messages.length; i++) {
    const message = mempool.messages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'charge') {
      result.push(message);
    }
  }

  const invalidatedCharges = _getUnconfirmedInvalidatedCharges(db, mempool);
  for (let i = 0; i < invalidatedCharges.length; i++) {
    const invalidatedCharge = invalidatedCharges[i];
    const index = result.findIndex(charge => charge.signature === invalidatedCharge.signature);

    if (index !== -1) {
      result.splice(index, 1);
    }
  }

  return result;
};
const _findChargeBlockHeight = (blocks, chargeSignature) => {
  for (let i = blocks.length - 1; i >= 0; i--) {
    const block = blocks[i];
    const {messages} = block;
    const chargeMessage = _findLocalChargeMessage(messages, chargeSignature);

    if (chargeMessage) {
      return block.height;
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
            balance = _roundToCents(balance - quantity);
            applied = true;
          }
          if (dstAddress === address) {
            balance = _roundToCents(balance + quantity);
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
          balance = _roundToCents(balance + quantity);
        }
        if (dstAddress === address) {
          balance = _roundToCents(balance - quantity);
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
            balance = _roundToCents(balance - quantity);
            applied = true;
          }
          if (dstAddress === address) {
            balance = _roundToCents(balance + quantity);
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
          balance = _roundToCents(balance + quantity);
        }
        if (dstAddress === address) {
          balance = _roundToCents(balance - quantity);
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
  const checkBlockIndex = block.height - 1;
  const mainChainBlock = (checkBlockIndex < blocks.length) ? blocks[checkBlockIndex] : null;

  if (mainChainBlock && mainChainBlock.hash === block.hash) {
    return true;
  } else {
    return mempool.blocks.some(mempoolBlock => mempoolBlock.hash === block.hash && mempoolBlock.height === block.height);
  }
};
const _findBlockAttachPoint = (blocks, mempool, block) => {
  const {prevHash, height} = block;
  const blockIndex = height - 1;
  const topBlockHeight = (blocks.length > 0) ? blocks[blocks.length - 1].height : 0;
  const topBlockIndex = topBlockHeight - 1;

  if ((blockIndex >= Math.max(topBlockIndex - UNDO_HEIGHT, 0)) && (blockIndex <= (topBlockIndex + 1))) {
    const candidateTopMainChainBlockHash = (blocks.length > 0) ? blocks[blocks.length - 1].hash : zeroHash;

    if (blockIndex === (topBlockIndex + 1) && candidateTopMainChainBlockHash === prevHash) {
      return { // valid on main chain
        type: 'mainChain',
      };
    } else {
      const forkedBlock = _getBlockForkOrigin(blocks, mempool, block);

      if (forkedBlock) {
        const extraBlocks = (() => {
          const result = [];
          for (let b = block; b.hash !== forkedBlock.hash; b = mempool.blocks.find(mempoolBlock => mempoolBlock.hash === b.prevHash)) {
            result.unshift(b);
          }
          return result;
        })();

        return { // valid indirect side chain
          type: 'sideChain',
          forkedBlock: forkedBlock,
          sideChainBlocks: blocks.slice(0, forkedBlock.height).concat(extraBlocks),
        };
      } else {
        if (height === 1) {
          return { // valid initial block
            type: 'sideChain',
            forkedBlock: null,
            sideChainBlocks: [block],
          };
        } else {
          return {
            type: 'dangling',
          };
        }
      }
    }
  } else {
    if (blockIndex < Math.max((topBlockIndex - UNDO_HEIGHT), 0)) {
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
const _getBlockForkOrigin = (blocks, mempool, block) => {
  const _getPreviousMainChainBlock = block => {
    const {prevHash, height} = block;
    const blockIndex = height - 1;
    const previousBlockIndex = blockIndex - 1;

    if ((previousBlockIndex >= 0) && (previousBlockIndex < blocks.length)) {
      const candidateMainChainBlock = blocks[previousBlockIndex];

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

  return forkedBlock;
};

const _commitMainChainBlock = (db, blocks, mempool, block) => {
  const newDb = _clone(db);
  _decorateDb(newDb);

  // update balances
  for (let i = 0; i < block.messages.length; i++) {
    const message = block.messages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'coinbase') {
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
      assetEntry = _roundToCents(assetEntry + quantity);
      addressEntry[asset] = assetEntry;
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
      srcAssetEntry = _roundToCents(srcAssetEntry - quantity);
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
      dstAssetEntry = _roundToCents(dstAssetEntry + quantity);
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
      srcAssetEntry = _roundToCents(srcAssetEntry - quantity);
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
      dstAssetEntry = _roundToCents(dstAssetEntry + quantity);
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
      assetEntry = _roundToCents(assetEntry + quantity);
      addressEntry[asset] = assetEntry;
    }
  }

  // add new charges
  for (let i = 0; i < block.messages.length; i++) {
    const message = block.messages[i];
    const payloadJson = JSON.parse(message.payload);
    const {type} = payloadJson;

    if (type === 'charge') {
      newDb.charges.push(message);
    }
  }

  // apply chargebacks
  const invalidatedCharges = _getConfirmedInvalidatedCharges(newDb, blocks, block);
  for (let i = 0; i < invalidatedCharges.length; i++) {
    const charge = invalidatedCharges[i];
    newDb.charges.splice(newDb.charges.indexOf(charge), 1);
  }

  // settle charges
  const oldCharges = newDb.charges.slice();
  const nextBlockHeight = ((blocks.length > 0) ? blocks[blocks.length - 1].height : 0) + 1;
  for (let i = 0; i < oldCharges.length; i++) {
    const charge = oldCharges[i];
    const chargePayload = JSON.parse(charge.payload);
    const {signature} = chargePayload;
    const chargeBlockHeight = _findChargeBlockHeight(blocks, signature);

    if (chargeBlockHeight !== -1 && (nextBlockHeight - chargeBlockHeight) >= CHARGE_SETTLE_BLOCKS) {
      const {asset, quantity, srcAddress, dstAddress} = chargePayload;

      let srcAddressEntry = newDb.balances[srcAddress];
      if (srcAddressEntry === undefined){
        srcAddressEntry = {};
        newDb.balances[srcAddress] = srcAddressEntry;
      }
      let srcAssetEntry = srcAddressEntry[asset];
      if (srcAssetEntry === undefined) {
        srcAssetEntry = 0;
      }
      srcAssetEntry = _roundToCents(srcAssetEntry - quantity);
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
      dstAssetEntry = _roundToCents(dstAssetEntry + quantity);
      dstAddressEntry[asset] = dstAssetEntry;

      newDb.charges.splice(newDb.charges.indexOf(charge), 1);
    }
  }

  // update message revocations
  newDb.messageRevocations.push(block.messages.map(({signature}) => signature));
  while (newDb.messageRevocations.length > MESSAGE_TTL) {
    newDb.messageRevocations.shift();
  }

  const newMempool = mempool && {
    blocks: mempool.blocks.filter(mempoolBlock => mempoolBlock.hash !== block.hash),
    messages: mempool.messages.filter(mempoolMessage => !block.messages.some(blockMessage => blockMessage.signature === mempoolMessage.signature)),
  };

  return {
    newDb,
    newMempool,
  };
};
const _commitSideChainBlock = (dbs, blocks, mempool, block, forkedBlock, sideChainBlocks) => {
  const _getBlocksDifficulty = blocks => {
    let result = 0;
    for (let i = 0; i < blocks.length; i++) {
      const block = blocks[i];
      const {hash} = block;
      result += _getHashDifficulty(hash, target);
    }
    return result;
  };
  const forkedBlockHeight = forkedBlock ? forkedBlock.height : 0;
  const mainChainDifficulty = _getBlocksDifficulty(blocks.slice(forkedBlockHeight));
  const sideChainDifficulty = _getBlocksDifficulty(sideChainBlocks.slice(forkedBlockHeight));
  const needsReorg = sideChainDifficulty > mainChainDifficulty;

  const _getBlocksMessages = blocks => {
    const result = [];
    for (let i = 0; i < blocks.length; i++) {
      const block = blocks[i];
      const {messages} = block;

      for (let j = 0; j < messages; j++) {
        const message = messages[j];
        result.push(message);
      }
    }
    return result;
  };
  const forkedBlockIndex = forkedBlockHeight - 1;
  const topBlockIndex = blocks.length - 1;
  const numSlicedBlocks = topBlockIndex - forkedBlockIndex;
  const slicedBlocks = blocks.slice(-numSlicedBlocks);
  const slicedMessages = _getBlocksMessages(slicedBlocks);
  const topSideChainBlockIndex = sidechainBlocks.length - 1;
  const numAddedSideChainBlocks = topSideChainBlockIndex - forkedBlockIndex;
  const addedSideChainBlocks = sideChainBlocks.slice(-numAddedSideChainBlocks);
  const addedSideChainMessages = _getBlocksMessages(addedSideChainBlocks);

  const newDbs = (() => {
    if (needsReorg) {
      const result = dbs.slice(0, -numSlicedBlocks);

      let localDb = (numSlicedBlocks < dbs.length) ? dbs[dbs.length - (numSlicedBlocks + 1)] : DEFAULT_DB;
      let localBlocks = blocks.slice(0, -numSlicedBlocks);
      for (let i = 0; i < addedSideChainBlocks; i++) {
        const addedSideChainBlock = addedSideChainBlocks;
        const {newDb} = _commitMainChainBlock(localDb, localBlocks, null, addedSideChainBlock);
        localDb = newDb;
        localBlocks.push(addedSideChainBlock);

        result.push(localDb);
      }

      return result;
    } else {
      return dbs.slice();
    }
  })();

  const newBlocks = needsReorg ? sideChainBlocks.slice() : blocks.slice();
  const newMempool = (() => {
    if (needsReorg) {
      const newMempool = {
        blocks: mempool.blocks
          .filter(mempoolBlock => !addedSideChainBlocks.some(addedSideChainBlock => addedSideChainBlock.hash === mempoolBlock.hash))
          .concat(slicedBlocks),
        messages: mempool.messages
          .filter(mempoolMessage => !addedSideChainMessages.some(addedSideChainMessage => addedSideChainMessage.signature === mempoolMessage.signature)),
      };
      // try to re-add sliced messges; they might not be valid anymore so we can't just append them
      for (let i = 0; i < slicedMessages.length; i++) {
        const slicedMessage = slicedMessages[i];
        _addMessage(newDb, newBlocks, newMempool, slicedMessage);
      }

      return newMempool;
    } else {
      return {
        blocks: mempool.blocks.concat(block),
        messages: mempool.messages.slice(),
      };
    }
  })();

  return {
    newDbs,
    newBlocks,
    newMemPool,
  };
};
const _addBlock = (dbs, blocks, mempool, block) => {
  if (!_checkBlockExists(blocks, mempool, block)) {
    const attachPoint = _findBlockAttachPoint(blocks, mempool, block);

    if (attachPoint !== null) {
      const {type} = attachPoint;

      if (type === 'mainChain') {
        const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
        const error = block.verify(db, blocks);
        if (!error) {
          const {newDb, newMempool} = _commitMainChainBlock(db, blocks, mempool, block);
          dbs.push(newDb);
          while (dbs.length > UNDO_HEIGHT) {
            dbs.shift();
          }
          blocks.push(block);
          while (block.length > CHARGE_SETTLE_BLOCKS) {
            block.shift();
          }
          mempool.blocks = newMempool.blocks;
          mempool.messages = newMempool.messages;

          _saveState();

          api.emit('block', block);

          return null;
        } else {
          return error;
        }
      } else if (type === 'sideChain') {
        const {forkedBlock, sideChainBlocks} = attachPoint;

        const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
        const error = block.verify(db, sideChainBlocks);
        if (!error) {
          const {newDbs, newBlocks, newMempool} = _commitSideChainBlock(dbs, blocks, mempool, block, forkedBlock, sideChainBlocks);
          dbs = newDbs;
          while (dbs.length > UNDO_HEIGHT) {
            dbs.shift();
          }
          blocks = newBlocks;
          while (block.length > CHARGE_SETTLE_BLOCKS) {
            block.shift();
          }
          mempool.blocks = newMempool.blocks;
          mempool.messages = newMempool.messages;

          _saveState();

          api.emit('block', block);

          return null;
        } else {
          return error;
        }
      } else if (type === 'outOfRange') {
        const {direction} = attachPoint;

        if (direction === -1) {
          return {
            status: 400,
            error: 'stale block',
            soft: true,
          };
        } else {
          return {
            status: 400,
            error: 'desynchronized block',
            soft: true,
          };
        }
      } else if (type === 'dangling') {
        return {
          status: 400,
          error: 'dangling block',
        };
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
      soft: true,
    };
  }
};
const _addMessage = (db, blocks, mempool, message) => {
  if (!mempool.messages.some(mempoolMessage => mempoolMessage.equals(message))) {
    const error = message.verify(db, blocks, mempool);
    if (!error) {
      mempool.messages.push(message);

      api.emit('message', message);
    }
    return error;
  } else {
    return null;
  }
};

let lastBlockTime = Date.now();
let numHashes = 0;
const doHash = () => new Promise((accept, reject) => {
  const version = BLOCK_VERSION;
  const timestamp = Date.now();
  const prevHash = blocks.length > 0 ? blocks[blocks.length - 1].hash : zeroHash;
  const topBlockHeight = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;
  const height = topBlockHeight + 1;
  const payload = JSON.stringify({type: 'coinbase', asset: CRD, quantity: COINBASE_QUANTITY, address: minePublicKey, startHeight: height, timestamp: Date.now()});
  const payloadHash = crypto.createHash('sha256').update(payload).digest();
  const privateKeyBuffer = COINBASE_PRIVATE_KEY;
  const signature = eccrypto.sign(privateKeyBuffer, payloadHash);
  const signatureString = signature.toString('base64');
  const coinbaseMessage = new Message(payload, signatureString);
  const allMessages = mempool.messages.concat(coinbaseMessage);
  const allMessagesJson = allMessages
    .map(message => JSON.stringify(message))
    .join('\n');

  const uint64Array = new Uint32Array(1);
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
      const block = new Block(hash, prevHash, height, difficulty, version, timestamp, allMessages, nonce);
      accept(block);

      return;
    } else {
      const now = Date.now();
      const timeDiff = now - timestamp;

      if (timeDiff > HASH_WORK_TIME) {
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
const peersDataPath = path.join(dataPath, 'peers.txt');
const _decorateDb = db => {
  db.charges = db.charges.map(charge => Message.from(charge));
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
const _loadState = () => {
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

  return Promise.all([
    _readdirDbs(),
    _readdirBlocks(),
  ])
    .then(([
      dbFiles,
      blockFiles,
    ]) => {
      const bestBlockHeight = (() => {
        for (let height = 1; height <= blockFiles.length; height++) {
          const foundBlockAtThisHeight = blockFiles.some(file => {
            const match = file.match(/^block-([0-9]+)\.json$/);
            return Boolean(match) && parseInt(match[1], 10) === height;
          });

          if (!foundBlockAtThisHeight) {
            return height - 1;
          }
        }
        return blockFiles.length;
      })();

      if (bestBlockHeight > 0) { // load dbs and blocks from disk
        const _readDbFiles = () => {
          const candidateHeights = (() => {
            const result = [];

            const _haveDbFile = height => dbFiles.some(file => {
              const match = file.match(/^db-([0-9]+)\.json$/);
              return Boolean(match) && parseInt(match[1], 10) === height;
            });
            for (let i = bestBlockHeight; (i >= (bestBlockHeight - UNDO_HEIGHT)) && (i > 0) && _haveDbFile(i); i--) {
              result.unshift(i);
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
          return Promise.all(candidateHeights.map(height => _readDbFile(height)));
        };
        const _readBlockFiles = () => {
          const candidateHeights = (() => {
            const result = [];
            for (let i = Math.max(bestBlockHeight - CHARGE_SETTLE_BLOCKS, 1); i <= bestBlockHeight; i++) {
              result.push(i);
            }
            return result;
          })();
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
          return Promise.all(candidateHeights.map(height => _readBlockFile(height)));
        };

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
            _decorateDbs(dbs);

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
};
const _ensureDataPaths = () => {
  const dataDirectories = [
    dataPath,
    dbDataPath,
    blocksDataPath,
  ];
  const _ensureDirectory = p => new Promise((accept, reject) => {
    mkdirp(p, err => {
      if (!err) {
        accept();
      } else {
        reject(err);
      }
    });
  });
  return Promise.all(dataDirectories.map(p => _ensureDirectory(p)));
};
const _saveState = (() => {
  const _doSave = cb => {
    const _writeNewFiles = () => {
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
      const zerothDbLocalBlockIndex = Math.max(blocks.length - UNDO_HEIGHT, 0);
      for (let i = 0; i < blocks.length; i++) {
        const block = blocks[i];
        const {height} = block;
        promises.push(_writeFile(path.join(blocksDataPath, `block-${height}.json`), JSON.stringify(block, null, 2)));

        if (i >= zerothDbLocalBlockIndex) {
          const dbIndex = i - zerothDbLocalBlockIndex;
          const db = dbs[dbIndex];
          promises.push(_writeFile(path.join(dbDataPath, `db-${height}.json`), JSON.stringify(db, null, 2)));
        }
      }

      return Promise.all(promises);
    };
    const _removeOldFiles = () => {
      const _removeDbFiles = () => new Promise((accept, reject) => {
        fs.readdir(dbDataPath, (err, dbFiles) => {
          if (!err || err.code === 'ENOENT') {
            dbFiles = dbFiles || [];

            const keepDbFiles = [];
            const zerothDbLocalBlockIndex = Math.max(blocks.length - UNDO_HEIGHT, 0);
            for (let i = 0; i < blocks.length; i++) {
              if (i >= zerothDbLocalBlockIndex) {
                const height = i + 1;
                keepDbFiles.push(`db-${height}.json`);
              }
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
      const _removeBlockFiles = () => new Promise((accept, reject) => {
        fs.readdir(blocksDataPath, (err, blockFiles) => {
          if (!err || err.code === 'ENOENT') {
            blockFiles = blockFiles || [];

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
            const topBlockHeight = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;
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
    };

    _writeNewFiles()
      .then(() => _removeOldFiles())
      .then(() => {
        cb();
      })
      .catch(err => {
        cb(err);
      });
  };

  let running = false;
  let queued = false;
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
const _loadPeers = () => new Promise((accept, reject) => {
  fs.readFile(peersDataPath, 'utf8', (err, s) => {
    if (!err) {
      const newPeers = s.split('\n')
        .filter(url => url)
        .map(url => new Peer(url));
      peers = newPeers;

      accept();
    } else if (err.code === 'ENOENT') {
      peers = [];

      accept();
    } else {
      reject(err);
    }
  });
});
const _savePeers = (() => {
  const _doSave = cb => {
    const peersString = peers.map(({url}) => url).join('\n') + '\n';

    fs.writeFile(peersDataPath, peersString, err => {
      if (!err) {
        cb();
      } else {
        cb(err);
      }
    });
  };

  let running = false;
  let queued = false;
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

const _addPeer = url => {
  const peer = new Peer(url);
  if (peer.url !== localUrl && !peers.some(p => p.equals(peer))) {
    peers.push(peer);

    api.emit('peer', peer.url);

    _refreshLivePeers();

    _savePeers();
  }
};
const _removePeer = url => {
  const index = peers.findIndex(peer => peer.url === url);
  if (index !== -1) {
    const peer = peers[index];
    peer.disable();
    peers.splice(index, 1);

    _refreshLivePeers();

    _savePeers();
  }
};
const _refreshLivePeers = () => {
  const enabledPeers = peers.filter(peer => peer.isEnabled());
  const disabledPeers = peers.filter(peer => !peer.isEnabled());

  while (enabledPeers.length < MIN_NUM_LIVE_PEERS && disabledPeers.length > 0) {
    const disabledPeerIndex = Math.floor(disabledPeers.length * Math.random());
    const peer = disabledPeers[disabledPeerIndex];
    peer.enable();

    disabledPeers.splice(disabledPeerIndex, 1);
    enabledPeers.push(peer);
  }
};

const _listen = () => {
  const app = express();

  app.get('/balances/:address', (req, res, next) => {
    const {address} = req.params;
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const balance = _getConfirmedBalances(db, address);
    res.json({balance});
  });
  app.get('/balance/:address/:asset', (req, res, next) => {
    const {address, asset} = req.params;
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const balance = _getConfirmedBalance(db, address, asset);
    res.json({balance});
  });
  app.get('/unconfirmedBalances/:address', (req, res, next) => {
    const {address} = req.params;
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const balance = _getUnconfirmedUnsettledBalances(db, mempool, address);
    res.json({balance});
  });
  app.get('/unconfirmedBalance/:address/:asset', (req, res, next) => {
    const {address, asset} = req.params;
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const balance = _getUnconfirmedUnsettledBalance(db, mempool, address, asset);
    res.json({balance});
  });
  app.get('/charges/:address', (req, res, next) => {
    const {address} = req.params;
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const balance = _getConfirmedCharges(db, address);
    res.json({balance});
  });
  app.get('/unconfirmedCharges/:address', (req, res, next) => {
    const {address} = req.params;
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const balance = _getUnconfirmedCharges(db, mempool, address);
    res.json({balance});
  });

  const _createSend = ({asset, quantity, srcAddress, dstAddress, startHeight, timestamp, privateKey}) => {
    const privateKeyBuffer = new Buffer(privateKey, 'base64');
    const payload = JSON.stringify({type: 'send', startHeight, asset, quantity, srcAddress, dstAddress, timestamp});
    const payloadHash = crypto.createHash('sha256').update(payload).digest();

    const signature = eccrypto.sign(privateKeyBuffer, payloadHash)
    const signatureString = signature.toString('base64');
    const message = new Message(payload, signatureString);
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const error = _addMessage(db, blocks, mempool, message);
    if (!error) {
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
      typeof body.startHeight === 'number' &&
      typeof body.timestamp === 'number' &&
      typeof body.privateKey === 'string'
    ) {
      const {asset, quantity, srcAddress, dstAddress, timestamp, startHeight, privateKey} = body;

      _createSend({asset, quantity, srcAddress, dstAddress, timestamp, startHeight, privateKey})
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

  const _createMinter = ({address, asset, startHeight, timestamp, privateKey}) => {
    const privateKeyBuffer = new Buffer(privateKey, 'base64');
    const payload = JSON.stringify({type: 'minter', address, asset, startHeight, timestamp});
    const payloadHash = crypto.createHash('sha256').update(payload).digest();
    const signature = eccrypto.sign(privateKeyBuffer, payloadHash)
    const signatureString = signature.toString('base64');
    const message = new Message(payload, signatureString);
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const error = _addMessage(db, blocks, mempool, message);
    if (!error) {
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
      typeof body.startHeight === 'number' &&
      typeof body.timestamp === 'number' &&
      typeof body.privateKey === 'string'
    ) {
      const {address, asset, startHeight, timestamp, privateKey} = body;

      _createMinter({address, asset, startHeight, timestamp, privateKey})
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

  const _createMint = ({asset, quantity, address, startHeight, timestamp, privateKey}) => {
    const privateKeyBuffer = new Buffer(privateKey, 'base64');
    const payload = JSON.stringify({type: 'mint', asset, quantity, address, startHeight, timestamp});
    const payloadHash = crypto.createHash('sha256').update(payload).digest();
    const signature = eccrypto.sign(privateKeyBuffer, payloadHash)
    const signatureString = signature.toString('base64');
    const message = new Message(payload, signatureString);
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const error = _addMessage(db, blocks, mempool, message);
    if (!error) {
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
      typeof body.startHeight === 'number' &&
      typeof body.timestamp === 'number' &&
      typeof body.privateKey === 'string'
    ) {
      const {asset, quantity, address, startHeight, timestamp, privateKey} = body;

      _createMint({asset, quantity, address, startHeight, timestamp, privateKey})
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

  const _createCharge = ({asset, quantity, srcAddress, dstAddress, startHeight, timestamp}) => {
    const payload = JSON.stringify({type: 'charge', asset, quantity, srcAddress, dstAddress, startHeight, timestamp});
    const message = new Message(payload, null);
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const error = _addMessage(db, blocks, mempool, message);
    if (!error) {
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
      typeof body.startHeight === 'number' &&
      typeof body.timestamp === 'number'
    ) {
      const {asset, quantity, srcAddress, dstAddress, startHeight,  timestamp} = body;

      _createCharge({asset, quantity, srcAddress, dstAddress, startHeight, timestamp})
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

  const _createChargeback = ({chargeSignature, startHeight, timestamp, privateKey}) => {
    const payload = JSON.stringify({type: 'chargeback', chargeSignature, startHeight, timestamp});
    const payloadHash = crypto.createHash('sha256').update(payload).digest();
    const signature = eccrypto.sign(privateKeyBuffer, payloadHash)
    const signatureString = signature.toString('base64');
    const message = new Message(payload, signatureString);
    const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
    const error = _addMessage(db, blocks, mempool, message);
    if (!error) {
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
      typeof body.startHeight === 'number' &&
      typeof body.timestamp === 'number' &&
      typeof body.privateKey === 'string'
    ) {
      const {chargeSignature, startHeight, timestamp, privateKey} = body;

      _createChargeback({chargeSignature, startHeight, timestamp, privateKey})
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

  app.get('/blocks/:height', (req, res, next) => {
    const {height: heightStirng} = req.params;
    const height = parseInt(heightStirng, 10);

    if (!isNaN(height)) {
      const topBlockHeight = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;

      if (height >= 1 && height <= topBlockHeight) {
        const firstBlockHeight = blocks[0].height;

        if (height >= firstBlockHeight) {
          const blockIndex = height - firstBlockHeight;
          const block = blocks[blockIndex];
          res.type('application/json');
          res.send(JSON.stringify(block, null, 2));
        } else {
          const rs = fs.createReadStream(path.join(blocksDataPath, `block-${height}.json`));
          res.type('application/json');
          rs.pipe(res);
          rs.on('error', err => {
            console.warn(err);

            res.status(500);
            res.send(err.stack);
          });
        }
      } else {
        res.status(404);
        res.json({
          error: 'height out of range',
        });
      }
    } else {
      res.status(400);
      res.json({
        error: 'invalid height',
      });
    }
  });
  /* app.get('/blockcount', (req, res, next) => {
    const blockcount = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;

    res.json({
      blockcount,
    });
  }); */
  app.get('/blockcache', (req, res, next) => {
    res.json(blocks);
  });
  app.get('/mempool', (req, res, next) => {
    res.json(mempool);
  });
  app.get('/peers', (req, res, next) => {
    const urls = peers.map(({url}) => url);

    res.json(urls);
  });

  _refreshLivePeers();

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
  server.listen(port, host);

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
  api.on('peer', peer => {
    const e = {
      type: 'peer',
      peer: peer,
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
          const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
          console.log(JSON.stringify(db, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'blockcount': {
          const blockcount = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;
          console.log(JSON.stringify(blockcount, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'blockcache': {
          console.log(JSON.stringify(blocks, null, 2));
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
        case 'balance': {
          const [, address, asset] = split;

          if (address && asset) {
            const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
            const balance = _getUnconfirmedBalance(db, mempool, address, asset);
            console.log(JSON.stringify(balance, null, 2));
            const blockcount = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;
            console.log(`Blocks: ${blockcount} Mempool: ${mempool.messages.length}`);
            process.stdout.write('> ')
          } else if (address) {
            const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
            const balances = _getUnconfirmedBalances(db, mempool, address);
            console.log(JSON.stringify(balances, null, 2));
            const blockcount = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;
            console.log(`Blocks: ${blockcount} Mempool: ${mempool.messages.length}`);
            process.stdout.write('> ');
          } else {
            const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
            console.log(JSON.stringify(_getAllUnconfirmedBalances(db, mempool), null, 2));
            const blockcount = blocks.length > 0 ? blocks[blocks.length - 1].height : 0;
            console.log(`Blocks: ${blockcount} Mempool: ${mempool.messages.length}`);
            process.stdout.write('> ');
          }

          break;
        }
        case 'minter': {
          const [, asset] = split;
          const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
          const minter = _getUnconfirmedMinter(db, mempool, asset);
          console.log(JSON.stringify(minter, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'minters': {
          const [, asset] = split;
          const db = (dbs.length > 0) ? dbs[dbs.length - 1] : DEFAULT_DB;
          console.log(JSON.stringify(db.minters, null, 2));
          process.stdout.write('> ');
          break;
        }
        case 'send': {
          const [, asset, quantityString, srcAddress, dstAddress, privateKey] = split;
          const quantityNumber = parseFloat(quantityString);
          const startHeight = blocks.length + 1;
          const timestamp = Date.now();

          _createSend({asset, quantity: quantityNumber, srcAddress, dstAddress, startHeight, timestamp, privateKey})
            .then(() => {
              console.log('ok');
              process.stdout.write('> ');
            })
            .catch(err => {
              console.warn(err);
            });
          break;
        }
        case 'addminter': {
          const [, address, asset, privateKey] = split;
          const startHeight = blocks.length + 1;
          const timestamp = Date.now();

          _createMinter({address, asset, startHeight, timestamp, privateKey})
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
          const quantityNumber = parseFloat(quantityString);
          const startHeight = blocks.length + 1;
          const timestamp = Date.now();

          _createMint({asset, quantity: quantityNumber, address, startHeight, timestamp, privateKey})
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
          const quantityNumber = parseFloat(quantity);
          const startHeight = blocks.length + 1;
          const timestamp = Date.now();

          _createCharge({asset, quantity: quantityNumber, srcAddress, dstAddress, startHeight, timestamp})
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
          const startHeight = blocks.length + 1;
          const timestamp = Date.now();

          _createChargeback({chargeSignature, startHeight, timestamp, privateKey})
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
          console.log(minePublicKey !== null);
          process.stdout.write('> ');

          break;
        }
        case 'startmine': {
          const [, publicKey] = split;

          _startMine(publicKey);
          process.stdout.write('> ');

          break;
        }
        case 'stopmine': {
          _stopMine();
          process.stdout.write('> ');

          break;
        }
        case 'peers': {
          if (peers.length > 0) {
            console.log(peers.map(({url}) => url).join('\n'));
          }
          process.stdout.write('> ');

          break;
        }
        case 'addpeer': {
          const [, url] = split;

          _addPeer(url);
          process.stdout.write('> ');

          break;
        }
        case 'removepeer': {
          const [, url] = split;

          _removePeer(url);
          process.stdout.write('> ');

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
  replHistory(r, path.join(dataPath, 'history.txt'));
  r.on('exit', () => {
    console.log();
    process.exit(0);
  });
};

let minePublicKey = null;
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

        const error = _addBlock(dbs, blocks, mempool, block);
        if (error) {
          console.warn('add mined block error:', error);
        }
      }

      mineImmediate = setImmediate(_mine);
    });
};
const _startMine = publicKey => {
  _stopMine();

  minePublicKey = publicKey;
  mineImmediate = setImmediate(_mine);
};
const _stopMine = () => {
  minePublicKey = null;

  clearImmediate(mineImmediate);
  mineImmediate = null;
};

Promise.all([
  _loadState(),
  _loadPeers(),
])
  .then(() => _ensureDataPaths())
  .then(() => _listen())
  .catch(err => {
    console.warn(err);
    process.exit(1);
  });
