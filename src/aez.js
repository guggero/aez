const AEZState = require('./aez_state');

const VERSION = 'v5';

function encrypt(key, nonce, additionalData, tau, plaintext) {
  let state = new AEZState();
  state.reset();
  state.init(key);
  let delta = state.aezHash(nonce, additionalData, tau * 8);

  if (!plaintext || plaintext.length === 0) {
    return state.aezPRF(delta, tau);
  } else {
    return state.encipher(delta, plaintext);
  }
}

function decrypt(key, nonce, additionalData, tau, ciphertext) {
  let state = new AEZState();
  state.reset();
  state.init(key);
  let delta = state.aezHash(nonce, additionalData, tau * 8);
  let sum = 0;
  let x = null;

  if (ciphertext && ciphertext.length === tau) {
    x = state.aezPRF(delta, tau);
    for (let i = 0; i < tau; i++) {
      sum |= x[i] ^ ciphertext[i];
    }
  } else {
    x = state.decipher(delta, ciphertext);
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
