const crds = require('.');
const tmp = require('tmp');
const getport = require('getport');

const cleanups = [];

let tmpdir;
const host = '127.0.0.1';
let port;
before(() => {
  return Promise.all([
    new Promise((accept, reject) => {
      tmp.dir({
        unsafeCleanup: true,
      }, (err, p, cleanup) => {
        if (!err) {
          tmpdir = p;

          cleanups.push(cleanup);

          accept();
        } else {
          reject(err);
        }
      });
    }),
    new Promise((accept, reject) => {
      getport((err, p) => {
        if (!err) {
          port = p;

          accept();
        } else {
          reject(err);
        }
      });
    }),
  ]);
});
after(() => {
  return Promise.all(cleanups.map(cleanup => new Promise((accept, reject) => {
    cleanup(err => {
      if (!err) {
        accept();
      } else {
        reject(err);
      }
    });
  })));
});

describe('messages', () => {
  let cleanup;

  before(() => {
    return crds({
      dataDirectory: tmpdir,
    })
      .listen({
        host,
        port,
      })
      .then(destroyServer => {
        cleanup = destroyServer;
      });
  });
  after(cb => {
    cleanup(cb);
  })

  it('should add message', () => {
    
  });
});
