/* global describe, it, beforeEach */

const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const aez = require('../src/aez');
const { extractKey, mkBlock } = require('../src/functions');
const AEZState = require('../src/aez_state');

const testVectors = {
  hash: require('./test-vectors/hash.json'),
  prf: require('./test-vectors/prf.json'),
  extract: require('./test-vectors/extract.json'),
  encrypt: require('./test-vectors/encrypt.json'),
};

describe('test vectors', () => {
  describe('aezHash', () => {
    testVectors.hash.forEach(vec => {
      it(vec.key, () => {
        // given
        const key = Buffer.from(vec.key, 'hex');
        const ad = vec.ad.map(a => Buffer.from(a, 'hex'));

        const state = new AEZState();
        state.reset();
        state.init(key);

        // when
        const result = state.aezHash(ad.shift(), ad, vec.tau);

        // then
        assert.strictEqual(result.toString('hex'), vec.result);
      });
    });
  });

  describe('aezPRF', () => {
    testVectors.prf.forEach(vec => {
      it(vec.key, () => {
        // given
        const key = Buffer.from(vec.key, 'hex');
        const delta = Buffer.from(vec.delta, 'hex');

        const state = new AEZState();
        state.reset();
        state.init(key);
        const result = mkBlock(vec.tau);

        // when
        state.aezPRF(delta, vec.tau, result);

        // then
        assert.strictEqual(result.toString('hex'), vec.result);
      });
    });
  });

  describe('extractKey', () => {
    testVectors.extract.forEach(vec => {
      it(vec.key, () => {
        // given
        const key = Buffer.from(vec.key, 'hex');

        // when
        const result = extractKey(key);

        // then
        assert.strictEqual(result.toString('hex'), vec.result);
      });
    });
  });

  describe('encrypt', () => {
    testVectors.encrypt.forEach(vec => {
      it(vec.key, () => {
        // given
        const key = Buffer.from(vec.key, 'hex');
        const nonce = Buffer.from(vec.nonce, 'hex');
        const ad = vec.ad.map(a => Buffer.from(a, 'hex'));
        const message = Buffer.from(vec.message, 'hex');

        // when
        const result = aez.encrypt(key, nonce, ad, vec.tau, message);

        // then
        assert.strictEqual(result.toString('hex'), vec.result);
      });
    });
  });

  describe('decrypt', () => {
    testVectors.encrypt.forEach(vec => {
      it(vec.key, () => {
        // given
        const key = Buffer.from(vec.key, 'hex');
        const nonce = Buffer.from(vec.nonce, 'hex');
        const ad = vec.ad.map(a => Buffer.from(a, 'hex'));
        const message = Buffer.from(vec.message, 'hex');
        const ciphertext = aez.encrypt(key, nonce, ad, vec.tau, message);

        // when
        const result = aez.decrypt(key, nonce, ad, vec.tau, ciphertext);

        // then
        assert.strictEqual(result.toString('hex'), vec.message);
      });
    });
  });
});
