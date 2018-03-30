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

describe('edge cases', () => {
  it('resets the state', () => {
    // given
    const state = new AEZState();
    state.init(Buffer.from('abcdef', 'hex'));

    // when
    state.reset();

    // then
    assert.strictEqual(state.I[0].toString('hex'), '00000000000000000000000000000000');
  });

  it('returns null for empty input to encipher', () => {
    // given
    const state = new AEZState();

    // when
    state.encipher(null, null, null);

    // then
    assert.strictEqual(state.I[0].toString('hex'), '00000000000000000000000000000000');
  });

  it('returns null for empty input to decipher', () => {
    // given
    const state = new AEZState();

    // when
    state.decipher(null, null, null);

    // then
    assert.strictEqual(state.I[0].toString('hex'), '00000000000000000000000000000000');
  });

  it('returns null if decrypt is unsuccessful', () => {
    // given
    const key = Buffer.from('abcdef', 'hex');
    const ciphertext = Buffer.from('0000000000000000', 'hex');

    // when
    const result = aez.decrypt(key, null, [], 123, ciphertext);

    // then
    assert.strictEqual(result, null);
  });

  it('checks the code example', () => {
    // given

    // sha256 of 'my-secret-key', but you should use a key derivation function like scrypt or PBKDF2!
    const key = Buffer.from('1311f8fc80a7ea28d78dd7723f09c44c1754cd35160ca8e7133ae3d7f636a19a', 'hex');
    const salt = Buffer.from('abba0110', 'hex'); // some random salt
    const plaintext = Buffer.from('please encrypt me!', 'utf8');
    const tau = 4;

    // when
    const cipherText = aez.encrypt(key, null, [salt], tau, plaintext);
    const decryptedText = aez.decrypt(key, null, [salt], tau, cipherText);

    // then
    assert.strictEqual(decryptedText.toString(), plaintext.toString());
  });
});
