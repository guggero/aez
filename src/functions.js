const Buffer = require('safe-buffer').Buffer;
const blake = require('blakejs');

const BLOCK_SIZE = 16;
const EXTRACTED_KEY_SIZE = 3 * 16;

function mkBlock(size) {
  return Buffer.alloc(size || BLOCK_SIZE, 0);
}

function xorBytes1x16(a, b, dst) {
  for (let i = 0; i < BLOCK_SIZE; i++) {
    dst[i] = a[i] ^ b[i];
  }
}

function xorBytes4x16(a, b, c, d, dst) {
  for (let i = 0; i < BLOCK_SIZE; i++) {
    dst[i] = a[i] ^ b[i] ^ c[i] ^ d[i];
  }
}

function xorBytes(a, b, dst) {
  if (a.length < dst.length || b.length < dst.length) {
    throw new Error('aez: xorBytes: len');
  }
  for (let i = 0; i < dst.length; i++) {
    dst[i] = a[i] ^ b[i]
  }
}

function uint32(i) {
  return i >>> 0;
}

function uint8(i) {
  return 0x000000ff & i;
}

function extractKey(k) {
  if (k && k.length && k.length === EXTRACTED_KEY_SIZE) {
    return k;
  } else {
    const context = blake.blake2bInit(EXTRACTED_KEY_SIZE);
    blake.blake2bUpdate(context, k);
    return Buffer.from(blake.blake2bFinal(context));
  }
}

function multBlock(x, src, dst) {
  const [t, r] = [mkBlock(), mkBlock()];

  src.copy(t);

  while (x !== 0) {
    if (x & 1 !== 0) {
      xorBytes1x16(r, t, r);
    }
    doubleBlock(t);
    x >>= 1
  }

  r.copy(dst);
}

function doubleBlock(p) {
  const tmp = p[0];
  for (let i = 0; i < 15; i++) {
    p[i] = (p[i] << 1) | (p[i + 1] >> 7);
  }
  p[15] = (p[15] << 1) ^ ((tmp >> 7) ? 135 : 0);
}

function oneZeroPad(src, size, dst) {
  dst.fill(0);
  src.slice(0, size).copy(dst);
  dst[size] = 0x80;
}

module.exports = {
  BLOCK_SIZE,
  EXTRACTED_KEY_SIZE,
  mkBlock,
  xorBytes1x16,
  xorBytes4x16,
  xorBytes,
  uint32,
  uint8,
  extractKey,
  multBlock,
  doubleBlock,
  oneZeroPad,
};
