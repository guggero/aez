
const Buffer = require('safe-buffer').Buffer;
const State = require('./state');

const VERSION = 'v5';

const BLOCK_SIZE = 16;

function encrypt(key, nonce, additionalData, tau, plaintext) {
  let delta = Buffer.alloc(BLOCK_SIZE);
  const xSz = plaintext.length + tau;

  let x = Buffer.alloc(xSz);
  let state = new State();
  state.reset();
  //state.init(key);
  //state.aezHash(nonce, additionalData, tau * 8, delta);
}

function decrypt() {

}

module.exports = {
  VERSION,
  encrypt,
  decrypt,
};
