const crypto = require('crypto');
const bigint = require('big-integer');

const db = {};
const blocks = [];
const mempool = [];

const difficulty = 1e6;
const target = bigint('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16).divide(bigint(difficulty))

class Block {
  constructor(hash, prevHash, timestamp, txs, nonce) {
    this.hash = hash;
    this.prevHash = prevHash;
    this.timestamp = timestamp;
    this.txs = txs;
    this.nonce = nonce;
  }
}

let lastBlockTime = Date.now();
let numHashes = 0;
const doHash = () => new Promise((accept, reject) => {
  const start = Date.now();
  const startString = String(start);
  const prevHash = blocks.length > 0 ? blocks[blocks.length - 1].hash : bigint(0).toString(16);
  const mempoolJson = mempool.map(tx => JSON.stringify(tx)).join('\n');
  const hashRoot = (() => {
    const hash = crypto.createHash('sha256');
    hash.update(prevHash);
    hash.update(':');
    hash.update(startString);
    hash.update(':');
    hash.update(mempoolJson);
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
      const block = new Block(digest, prevHash, start, mempool, nonce);
      accept(block);

      return;
    } else {
      const now = Date.now();
      const timeDiff = now - start;

      if (timeDiff > 1000) {
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

        blocks.push(block);

        mempool.length = 0;
      } else {
        console.log('no block yet');
      }

      setImmediate(_recurse);
    });
};
_recurse();
