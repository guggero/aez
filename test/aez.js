/* global describe, it, beforeEach */

const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const aez = require('../src/aez');
const { extractKey } = require('../src/functions');
const AEZState = require('../src/aez_state');

const testVectors = {
  hash: require('./test-vectors/hash.json'),
  prf: require('./test-vectors/prf.json'),
  extract: require('./test-vectors/extract.json'),
  encrypt: require('./test-vectors/encrypt.json'),
};

describe('test vectors', () => {
  it('aezHash', () => {
    testVectors.hash.forEach(vec => {
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

  it('aezPRF', () => {
    testVectors.prf.forEach(vec => {
      // given
      const key = Buffer.from(vec.key, 'hex');
      const delta = Buffer.from(vec.delta, 'hex');

      const state = new AEZState();
      state.reset();
      state.init(key);

      // when
      const result = state.aezPRF(delta, vec.tau);

      // then
      assert.strictEqual(result.toString('hex'), vec.result);
    });
  });

  it('extractKey', () => {
    testVectors.extract.forEach(vec => {
      // given
      const key = Buffer.from(vec.key, 'hex');

      // when
      const result = extractKey(key);

      // then
      assert.strictEqual(result.toString('hex'), vec.result);
    });
  });

  it('encrypt', () => {
    testVectors.encrypt.forEach(vec => {
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
