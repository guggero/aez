/* global describe, it, beforeEach */

const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const { extractKey } = require('../src/functions');
const AEZState = require('../src/aez_state');

const testVectors = {
  hash: require('./test-vectors/hash.json'),
  prf: require('./test-vectors/prf.json'),
  extract: require('./test-vectors/extract.json'),
};

describe('test vectors', () => {
  it('aezHash', () => {
    testVectors.hash.forEach(vec => {
      // given
      const k = Buffer.from(vec.k, 'hex');
      const ad = vec.ad.map(a => Buffer.from(a, 'hex'));

      const state = new AEZState();
      state.reset();
      state.init(k);

      // when
      const result = state.aezHash(ad.shift(), ad, vec.tau);

      // then
      assert.strictEqual(result.toString('hex'), vec.result);
    });
  });

  it('aezPRF', () => {
    testVectors.prf.forEach(vec => {
      // given
      const k = Buffer.from(vec.k, 'hex');
      const delta = Buffer.from(vec.delta, 'hex');

      const state = new AEZState();
      state.reset();
      state.init(k);

      // when
      const result = state.aezPRF(delta, vec.tau);

      // then
      assert.strictEqual(result.toString('hex'), vec.result);
    });
  });

  it('extractKey', () => {
    testVectors.extract.forEach(vec => {
      // given
      const k = Buffer.from(vec[0], 'hex');

      // when
      const result = extractKey(k);

      // then
      assert.strictEqual(result.toString('hex'), vec[1]);
    })
  });
});
