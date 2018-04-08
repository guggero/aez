const AEZState = require('./aez_state');
const { mkBlock } = require('./functions');

const VERSION = 'v5';

function encrypt(key, nonce, additionalData, tau, plaintext) {
  let state = new AEZState();
  state.reset();
  state.init(key);
  let delta = state.aezHash(nonce, additionalData || [], tau * 8);
  let x = mkBlock(plaintext.length + tau);

  if (!plaintext || plaintext.length === 0) {
    state.aezPRF(delta, tau, x);
  } else {
    plaintext.copy(x);
    state.encipher(delta, x, x);
  }

  return x;
}

function decrypt(key, nonce, additionalData, tau, ciphertext) {
  let state = new AEZState();
  state.reset();
  state.init(key);
  let delta = state.aezHash(nonce, additionalData || [], tau * 8);
  let sum = 0;
  let x = mkBlock(ciphertext.length);

  if (ciphertext && ciphertext.length === tau) {
    state.aezPRF(delta, tau, x);
    for (let i = 0; i < tau; i++) {
      sum |= x[i] ^ ciphertext[i];
    }
    x = x.slice(0, ciphertext.length - tau);
  } else {
    state.decipher(delta, ciphertext, x);
    for (let i = 0; i < tau; i++) {
      sum |= x[ciphertext.length - tau + i];
    }
    if (sum === 0) {
      x = x.slice(0, ciphertext.length - tau);
    }
  }

  if (sum !== 0) {
    return null;
  }

  return x;
}

module.exports = {
  VERSION,
  encrypt,
  decrypt,
};
