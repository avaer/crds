const crds = require('.');
const tmp = require('tmp');
const getport = require('getport');
const fetch = require('node-fetch');
const {Headers} = fetch;
const fastSha256 = require('fast-sha256');
const secp256k1 = require('eccrypto-sync/secp256k1');

const jsonHeaders = (() => {
  const headers = new Headers();
  headers.append('Content-Type', 'application/json');
  return headers;
})();

const privateKey = new Buffer('MXNo7tDiY1soVtglOo7Va1HH06i6d6r7cizypViPPxs=', 'base64');
const publicKey = new Buffer('BFIrtpnhr6PWm4jzBzMJjFphs4WZwGsaqSk2Y+4zDJa9aK/kJByIBleRWDdBM6TgwuQ0DirXCulpKmzlfI2ytUU=', 'base64');
const address = 'EvfZY8ic4vz97A93MhuKkNi79i75AH1RtAeZcPN77NqC';

const _getPublicKey = privateKey => Buffer.from(secp256k1.keyFromPrivate(privateKey).getPublic('arr'));
const _sha256 = o => {
  if (typeof o === 'string') {
    o = new Buffer(o, 'utf8');
  }
  return new Buffer(fastSha256(o));
};
const _makeMinterMessage = (asset, privateKey) => {
  const startHeight = 0;
  const timestamp = 0;
  const publicKey = _getPublicKey(privateKey);
  const publicKeyString = publicKey.toString('base64');
  const payload = JSON.stringify({type: 'minter', asset, publicKey: publicKeyString, startHeight, timestamp});
  const payloadBuffer = new Buffer(payload, 'utf8');
  const payloadHash = _sha256(payloadBuffer);
  const payloadHashString = payloadHash.toString('hex');
  const signature = Buffer.from(secp256k1.sign(payloadHash, privateKey).toDER());
  const signatureString = signature.toString('base64');
  const message = {
    payload: payload,
    hash: payloadHashString,
    signature: signatureString,
  };
  return message;
};
const _resJson = res => {
  if (res.status >= 200 && res.status < 300) {
    return res.json();
  } else {
    return Promise.reject({
      status: res.status,
      stack: 'API returned failure status code: ' + res.status,
    });
  }
};

const _boot = () => {
  const cleanups = [];

  return Promise.all([
    Promise.resolve('127.0.0.1'),
    new Promise((accept, reject) => {
      getport((err, p) => {
        if (!err) {
          accept(p);
        } else {
          reject(err);
        }
      });
    }),
    new Promise((accept, reject) => {
      tmp.dir({
        unsafeCleanup: true,
      }, (err, p, cleanup) => {
        if (!err) {
          cleanups.push(cleanup);

          accept(p);
        } else {
          reject(err);
        }
      });
    }),
  ])
    .then(([
      host,
      port,
      tmpdir,
    ]) => {
      const c = crds({
        dataDirectory: tmpdir,
      });
      return c.listen({
        host,
        port,
      })
      .then(destroy => {
        cleanups.push(destroy);

        return {
          c,
          host,
          port,
          tmpdir,
          cleanup: () => Promise.all(cleanups.map(cleanup => new Promise((accept, reject) => {
            cleanup(err => {
              if (!err) {
                accept();
              } else {
                reject(err);
              }
            });
          }))),
        };
      });
    });
};

// mining

describe('mining', () => {
  let b;
  before(() => {
    return _boot()
      .then(newB => {
        b = newB;
      });
  });
  after(() => b.cleanup());

  it('should mine a block', () => {
    const message = _makeMinterMessage('ITEM', privateKey);

    return Promise.all([
      new Promise((accept, reject) => {
        b.c.once('block', block => {
          accept(block);
        });
      }),
      fetch(`http://${b.host}:${b.port}/mine`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({address}),
      })
        .then(_resJson),
    ]);
  });
});

// messages

describe('messages', () => {
  let b;
  before(() => {
    return _boot()
      .then(newB => {
        b = newB;
      });
  });
  after(() => b.cleanup());

  it('should add message', () => {
    const message = _makeMinterMessage('ITEM', privateKey);

    return fetch(`http://${b.host}:${b.port}/submitMessage`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify(message),
    })
      .then(_resJson);
  });
});
