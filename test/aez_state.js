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

