/* global describe, it, beforeEach */

const assert = require('assert');
const Buffer = require('safe-buffer').Buffer;
const aez = require('../src/aez');

describe('encrypt', () => {
  it('should encrypt', () => {

    const plaintext = Buffer.from('aez implementation rocks', 'UTF-8');

    aez.encrypt(null, null, null, null, plaintext);
  });
});
