const crds = require('.');
const expect = require('expect');
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

const privateKey2 = new Buffer('LtD8mL4xPNV0NAoVzqNpXDIXpWt2Xb2Sg7zr/0LaStY=', 'base64');
const publicKey2 = new Buffer('BBWXfrjN5NL7Y+Ws8vj3n8qOUi8cu3vQhRYi7/Qj4gAiznJyqIhunTIbmJW7o3mnW2TerlGkunfZie95/VWVKWk=', 'base64');
const address2 = '4btZmuP1YpzsmCuz9n3k6K9bpqNptnSH29jjjcdu2yjp';

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
const _makeMintMessage = (asset, quantity, privateKey) => {
  const startHeight = 0;
  const timestamp = 0;
  const publicKey = _getPublicKey(privateKey);
  const publicKeyString = publicKey.toString('base64');
  const payload = JSON.stringify({type: 'mint', asset, quantity, publicKey: publicKeyString, startHeight, timestamp});
  const payloadHash = _sha256(payload);
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
const _makeSendMessage = (asset, quantity, srcAddress, dstAddress, privateKey) => {
  const startHeight = 0;
  const timestamp = 0;
  const publicKey = _getPublicKey(privateKey);
  const publicKeyString = publicKey.toString('base64');
  const payload = JSON.stringify({type: 'send', startHeight, asset, quantity, srcAddress, dstAddress, publicKey: publicKeyString, timestamp});
  const payloadHash = _sha256(payload);
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
const _makePriceMessage = (asset, price, privateKey) => {
  const startHeight = 0;
  const timestamp = 0;
  const publicKey = _getPublicKey(privateKey);
  const publicKeyString = publicKey.toString('base64');
  const payload = JSON.stringify({type: 'price', asset, price, publicKey: publicKeyString, startHeight, timestamp});
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
const _makeBuyMessage = (asset, quantity, price, privateKey) => {
  const startHeight = 0;
  const timestamp = 0;
  const publicKey = _getPublicKey(privateKey);
  const publicKeyString = publicKey.toString('base64');
  const payload = JSON.stringify({type: 'buy', asset, quantity, price, publicKey: publicKeyString, startHeight, timestamp});
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

const _boot = (startport = 6777) => {
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

describe('crds', function() {
this.timeout(10 * 1000);

// mining

describe('mining', () => {
  let b;
  beforeEach(() => {
    return _boot()
      .then(newB => {
        b = newB;
      });
  });
  afterEach(() => b.cleanup());

  it('should mine block', () => {
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

  it('should mine multiple blocks', () => {
    return Promise.all([
      new Promise((accept, reject) => {
        let numBlocks = 0;
        const _block = block => {
          if (++numBlocks >= 2) {
            b.c.removeListener('block', _block);

            accept(block);
          }
        };
        b.c.on('block', _block);
      }),
      fetch(`http://${b.host}:${b.port}/mine`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({address}),
      })
        .then(_resJson),
    ]);
  });

  it('should have correct balance after mining', () => {
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
    ])
    .then(() => Promise.all([
      fetch(`http://${b.host}:${b.port}/balance/${address}/CRD`)
        .then(_resJson)
        .then(balance => {
          expect(balance).toBe(100);
        }),
      fetch(`http://${b.host}:${b.port}/balances/${address}`)
        .then(_resJson)
        .then(balances => {
          expect(balances['CRD']).toBe(100);
        }),
    ]))
  });
});

// messages

describe('messages', () => {
  let b;
  beforeEach(() => {
    return _boot()
      .then(newB => {
        b = newB;
      });
  });
  afterEach(() => b.cleanup());

  it('should minter', () => {
    return fetch(`http://${b.host}:${b.port}/submitMessage`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify(_makeMinterMessage('ITEM', privateKey)),
    })
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/mempool`))
      .then(_resJson)
      .then(mempool => {
        expect(mempool.messages.length).toBe(1);
        expect(JSON.parse(mempool.messages[0].payload).type).toBe('minter');
      });
  });

  it('should minter, mint, and send', () => {
    return fetch(`http://${b.host}:${b.port}/submitMessage`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify(_makeMinterMessage('ITEM', privateKey)),
    })
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeMintMessage('ITEM.WOOD', 100, privateKey)),
      }))
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeSendMessage('ITEM.WOOD', 2, address, address2, privateKey)),
      }))
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/mempool`))
      .then(_resJson)
      .then(mempool => {
        expect(mempool.messages.length).toBe(3);
        expect(JSON.parse(mempool.messages[0].payload).type).toBe('minter');
        expect(JSON.parse(mempool.messages[1].payload).type).toBe('mint');
        expect(JSON.parse(mempool.messages[2].payload).type).toBe('send');
      });
  });

  it('should reject invalid mint', () => {
    return fetch(`http://${b.host}:${b.port}/submitMessage`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify(_makeMinterMessage('ITEM', privateKey)),
    })
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeMintMessage('ITEM.WOOD', 100, privateKey2)),
      }))
      .then(_resJson)
      .then(() => {
        return Promise.reject(new Error('did not reject message'));
      })
      .catch(err => {
        if (err.status === 400) {
          return Promise.resolve();
        } else {
          return Promise.reject(err);
        }
      });
  });
});

// balances

describe('balances', () => {
  let b;
  beforeEach(() => {
    return _boot()
      .then(newB => {
        b = newB;
      });
  });
  afterEach(() => b.cleanup());

  it('should return unconfirmed balances', () => {
    return fetch(`http://${b.host}:${b.port}/submitMessage`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify(_makeMinterMessage('ITEM', privateKey)),
    })
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeMintMessage('ITEM.WOOD', 100, privateKey)),
      }))
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeSendMessage('ITEM.WOOD', 2, address, address2, privateKey)),
      }))
      .then(_resJson)
      .then(() => Promise.all([
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(1);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address}/ITEM.WOOD`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(98);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalances/${address}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['ITEM:mint']).toBe(1);
            expect(balances['ITEM.WOOD']).toBe(98);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address2}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address2}/ITEM.WOOD`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(2);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalances/${address2}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['ITEM:mint']).toBe(undefined);
            expect(balances['ITEM.WOOD']).toBe(2);
          }),
      ]));
  });

  it('should return confirmed balances', () => {
    return fetch(`http://${b.host}:${b.port}/submitMessage`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify(_makeMinterMessage('ITEM', privateKey)),
    })
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeMintMessage('ITEM.WOOD', 100, privateKey)),
      }))
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeSendMessage('ITEM.WOOD', 2, address, address2, privateKey)),
      }))
      .then(_resJson)
      .then(() => Promise.all([
        fetch(`http://${b.host}:${b.port}/balance/${address}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/balance/${address}/ITEM.WOOD`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/balances/${address}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['ITEM:mint']).toBe(undefined);
            expect(balances['ITEM.WOOD']).toBe(undefined);
          }),
        fetch(`http://${b.host}:${b.port}/balance/${address2}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/balance/${address2}/ITEM.WOOD`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/balances/${address2}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['ITEM:mint']).toBe(undefined);
            expect(balances['ITEM.WOOD']).toBe(undefined);
          }),
      ]))
      .then(() => Promise.all([
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
      ]))
      .then(() => Promise.all([
        fetch(`http://${b.host}:${b.port}/balance/${address}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(1);
          }),
        fetch(`http://${b.host}:${b.port}/balance/${address}/ITEM.WOOD`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(98);
          }),
        fetch(`http://${b.host}:${b.port}/balances/${address}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['ITEM:mint']).toBe(1);
            expect(balances['ITEM.WOOD']).toBe(98);
          }),
        fetch(`http://${b.host}:${b.port}/balance/${address2}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/balance/${address2}/ITEM.WOOD`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(2);
          }),
        fetch(`http://${b.host}:${b.port}/balances/${address2}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['ITEM:mint']).toBe(undefined);
            expect(balances['ITEM.WOOD']).toBe(2);
          }),
      ]));
  });

  it('should mint free asset', () => {
    return fetch(`http://${b.host}:${b.port}/submitMessage`, {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify(_makeMinterMessage('ITEM', privateKey)),
    })
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makePriceMessage('ITEM', 0, privateKey)),
      }))
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeMintMessage('ITEM.WOOD', 100, privateKey2)),
      }))
      .then(_resJson)
      .then(() => Promise.all([
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(1);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address}/ITEM.WOOD`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalances/${address}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['ITEM:mint']).toBe(1);
            expect(balances['ITEM.WOOD']).toBe(undefined);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address2}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address2}/ITEM.WOOD`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(100);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalances/${address2}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['ITEM:mint']).toBe(undefined);
            expect(balances['ITEM.WOOD']).toBe(100);
          }),
      ]));
  });

  it('should buy priced asset', () => {
    return Promise.all([
      new Promise((accept, reject) => {
        b.c.once('block', block => {
          accept(block);
        });
      }),
      fetch(`http://${b.host}:${b.port}/mine`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({address: address2}),
      })
        .then(_resJson),
    ])
      .then(() => fetch(`http://${b.host}:${b.port}/mine`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({address: null}),
      }))
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeMinterMessage('ITEM', privateKey)),
      }))
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makePriceMessage('ITEM', 40, privateKey)),
      }))
      .then(_resJson)
      .then(() => fetch(`http://${b.host}:${b.port}/submitMessage`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify(_makeBuyMessage('ITEM', 2, 40, privateKey2)),
      }))
      .then(_resJson)
      .then(() => Promise.all([
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(1);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address}/ITEM`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalances/${address}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['CRD']).toBe(80);
            expect(balances['ITEM:mint']).toBe(1);
            expect(balances['ITEM']).toBe(undefined);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address2}/ITEM:mint`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(0);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalance/${address2}/ITEM`)
          .then(_resJson)
          .then(balance => {
            expect(balance).toBe(2);
          }),
        fetch(`http://${b.host}:${b.port}/unconfirmedBalances/${address2}`)
          .then(_resJson)
          .then(balances => {
            expect(balances['CRD'] % 100).toBe(20);
            expect(balances['ITEM:mint']).toBe(undefined);
            expect(balances['ITEM']).toBe(2);
          }),
      ]));
  });
});

// peers

describe('peers', () => {
  let b1;
  let b2;
  beforeEach(() => {
    return _boot()
      .then(b => {
        b1 = b;

        return _boot(b1.port + 1)
          .then(b => {
            b2 = b;
          });
      });
  });
  afterEach(() => Promise.all([
    b1.cleanup(),
    b2.cleanup(),
  ]));

  it('should sync blocks', () => {
    return Promise.all([
      new Promise((accept, reject) => {
        b1.c.once('block', block => {
          accept(block);
        });
      }),
      fetch(`http://${b1.host}:${b1.port}/mine`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({address}),
      })
        .then(_resJson),
    ])
      .then(() => fetch(`http://${b1.host}:${b1.port}/mine`, {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({address: null}),
      }))
      .then(_resJson)
      .then(() => Promise.all([
        new Promise((accept, reject) => {
          b2.c.once('block', block => {
            accept(block);
          });
        }),
        fetch(`http://${b2.host}:${b2.port}/peer`, {
          method: 'POST',
          headers: jsonHeaders,
          body: JSON.stringify({url: `http://${b1.host}:${b1.port}`}),
        })
          .then(_resJson),
      ]));
  });
});

});
