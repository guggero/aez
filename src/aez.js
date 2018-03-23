const Buffer = require('safe-buffer').Buffer;
const AEZState = require('./aez_state');
const { BLOCK_SIZE } = require('./functions');

const VERSION = 'v5';

function encrypt(key, nonce, additionalData, tau, plaintext) {
  let delta = Buffer.alloc(BLOCK_SIZE);
  const xSz = plaintext.length + tau;

  let x = Buffer.alloc(xSz);
  let state = new AEZState();
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
