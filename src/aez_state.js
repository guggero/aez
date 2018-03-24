const { BLOCK_SIZE, uint32, mkBlock, xorBytes1x16, xorBytes4x16, extractKey, multBlock, doubleBlock } = require('./functions');
const AESRound = require('./aes_round');
const Buffer = require('safe-buffer').Buffer;

const ZERO = mkBlock();

const AEZState = function () {

  this.I = [mkBlock(), mkBlock()];
  this.J = [mkBlock(), mkBlock(), mkBlock()];
  this.L = [
    mkBlock(), mkBlock(), mkBlock(), mkBlock(),
    mkBlock(), mkBlock(), mkBlock(), mkBlock(),
  ];

  this.reset = function () {
    this.I.forEach(buf => buf.fill(0));
    this.J.forEach(buf => buf.fill(0));
    this.L.forEach(buf => buf.fill(0));

    if (this.aes) {
      this.aes.reset();
    }
  };

  this.init = function (key) {

    const extractedKey = extractKey(key);

    extractedKey.slice(0, 16).copy(this.I[0]);
    multBlock(2, this.I[0], this.I[1]);

    extractedKey.slice(16, 32).copy(this.J[0]);
    multBlock(2, this.J[0], this.J[1]);
    multBlock(2, this.J[1], this.J[2]);

    extractedKey.slice(32, 48).copy(this.L[1]);
    multBlock(2, this.L[1], this.L[2]);
    xorBytes1x16(this.L[2], this.L[1], this.L[3]);
    multBlock(2, this.L[2], this.L[4]);
    xorBytes1x16(this.L[4], this.L[1], this.L[5]);
    multBlock(2, this.L[3], this.L[6]);
    xorBytes1x16(this.L[6], this.L[1], this.L[7]);

    this.aes = new AESRound(extractedKey);
  };

  this.aezHash = function (nonce, ad, tau) {
    const [buf, sum, I, J] = [mkBlock(), mkBlock(), mkBlock(), mkBlock()];

    buf.writeInt32BE(uint32(tau), 12);
    xorBytes1x16(this.J[0], this.J[1], J);
    this.aes.AES4(J, this.I[1], this.L[1], buf, sum);

    const empty = !nonce || nonce.length === 0;
    let n = nonce;
    let nBytes = empty ? 0 : nonce.length;
    this.I[1].copy(I);
    for (let i = 1; nBytes >= BLOCK_SIZE; i++, nBytes -= BLOCK_SIZE) {
      this.aes.AES4(this.J[2], I, this.L[i % 8], n.slice(0, BLOCK_SIZE), buf);
      xorBytes1x16(sum, buf, sum);
      n = n.slice(BLOCK_SIZE);
      if (i % 8 === 0) {
        doubleBlock(I);
      }
    }

    if (nBytes > 0 || empty) {
      buf.fill(0);
      if (!empty) {
        n.copy(buf);
      }
      buf[nBytes] = 0x80;
      this.aes.AES4(this.J[2], this.I[0], this.L[0], buf, buf);
      xorBytes1x16(sum, buf, sum);
    }

    const self = this;
    ad.forEach((p, k) => {
      const empty = !p || p.length === 0;
      let bytes = empty ? 0 : p.length;
      self.I[1].copy(I);
      multBlock(5 + k, self.J[0], J);
      for (let i = 1; bytes >= BLOCK_SIZE; i++, bytes -= BLOCK_SIZE) {
        self.aes.AES4(J, I, self.L[i % 8], p.slice(0, BLOCK_SIZE), buf);
        xorBytes1x16(sum, buf, sum);
        p = p.slice(BLOCK_SIZE);
        if (i % 8 === 0) {
          doubleBlock(I);
        }
      }
      if (bytes > 0 || empty) {
        buf.fill(0);
        if (!empty) {
          p.copy(buf);
        }
        buf[bytes] = 0x80;
        self.aes.AES4(J, self.I[0], self.L[0], buf, buf);
        xorBytes1x16(sum, buf, sum);
      }
    });

    return sum;
  };

  this.aezPRF = function (delta, tau) {
    const [buf, ctr] = [mkBlock(), mkBlock()];
    const result = Buffer.alloc(tau, 0);

    let off = 0;
    while (tau >= BLOCK_SIZE) {
      xorBytes1x16(delta, ctr, buf);
      this.aes.AES10(this.L[3], buf, buf);
      buf.copy(result, off);

      let i = 15;
      while (true) {
        ctr[i]++;
        i--;
        if (ctr[i + 1] !== 0) {
          break;
        }
      }

      tau -= BLOCK_SIZE;
      off += BLOCK_SIZE;
    }
    if (tau > 0) {
      xorBytes1x16(delta, ctr, buf);
      this.aes.AES10(this.L[3], buf, buf);
      buf.copy(result, off);
    }

    return result;
  };

  this.encipher = function (delta, input) {
    if (!input || input.length === 0) {
      return null;
    }

    if (input.length < 32) {
      return this.aezTiny(delta, input, 0);
    } else {
      return this.aezCore(delta, input, 0);
    }
  };

  this.decipher = function (delta, input) {
    if (!input || input.length === 0) {
      return null;
    }

    if (input.length < 32) {
      return this.aezTiny(delta, input, 1);
    } else {
      return this.aezCore(delta, input, 1);
    }
  };

  this.aezTiny = function (delta, input, d) {
    const buf = mkBlock(2 * BLOCK_SIZE);
    const [L, R, tmp] = [mkBlock(), mkBlock(), mkBlock()];
    let mask = 0x00;
    let pad = 0x80;
    let rounds, i, j, step;

    i = 7;
    const inBytes = input.length;
    if (inBytes === 1) {
      rounds = 24;
    } else if (inBytes === 2) {
      rounds = 16;
    } else if (inBytes < 16) {
      rounds = 10;
    } else {
      i = 6;
      rounds = 8;
    }

    input.slice(0, (inBytes + 1) / 2).copy(L);
    input.slice(inBytes / 2, (inBytes / 2) + ((inBytes + 1) / 2)).copy(R);
    if (inBytes & 1 !== 0) {
      for (let k = 0; k < (inBytes / 2); k++) {
        R[k] = (R[k] << 4) | (R[k + 1] >> 4);
      }
      R[inBytes / 2] = R[inBytes / 2] << 4;
      pad = 0x08;
      mask = 0xf0;
    }

    if (d !== 0) {
      if (inBytes < 16) {
        input.slice(0, BLOCK_SIZE).copy(buf);
        buf[0] |= 0x80;
        xorBytes1x16(delta, buf, buf);
        this.aes.AES4(ZERO, this.I[1], this.L[3], buf, tmp);
        this.L[0] ^= (tmp[0] & 0x80);
      }
      j = rounds - 1;
      step = -1;
    } else {
      j = 0;
      step = 1;
    }

    for (let k = 0; k < rounds / 2; k++, j += step * 2) {
      buf.fill(0, 0, BLOCK_SIZE);
      R.slice(0, (inBytes + 1) / 2).copy(buf);
      buf[inBytes / 2] = (buf[inBytes / 2] & mask) | pad;
      xorBytes1x16(buf, delta, buf);
      buf[15] ^= j;
      this.aes.AES4(ZERO, this.I[1], this.L[i], buf, tmp);
      xorBytes1x16(L, tmp, L);

      buf.fill(0, 0, BLOCK_SIZE);
      L.slice(0, (inBytes + 1) / 2).copy(buf);
      buf[inBytes / 2] = (buf[inBytes / 2] & mask) | pad;
      xorBytes1x16(buf, delta, buf);
      buf[15] ^= j + step;
      this.aes.AES4(ZERO, this.I[1], this.L[i], buf, tmp);
      xorBytes1x16(R, tmp, R);
    }

    R.slice(0, inBytes / 2).copy(buf);
    L.slice(0, (inBytes + 1) / 2).copy(buf, inBytes / 2);
    if (inBytes & 1 !== 0) {
      for (let k = inBytes - 1; k > inBytes / 2; k--) {
        buf[k] = (buf[k] >> 4) | (buf[k - 1] << 4);
      }
      buf[inBytes / 2] = (L[0] >> 4) | (R[inBytes / 2] & 0xf0);
    }

    const out = mkBlock(inBytes);
    buf.slice(0, inBytes).copy(out);
    if (inBytes < 16 && d === 0) {
      buf.fill(0, inBytes, BLOCK_SIZE);
      buf[0] |= 0x80;
      xorBytes1x16(delta, buf, buf);
      this.aes.AES4(ZERO, this.I[1], this.L[3], buf, tmp);
      out[0] ^= tmp[0] & 0x80;
    }

    return out;
  };

  this.aezCore = function (delta, input, d) {

  };

  this.aezCorePass1 = function (input, output, X) {
    const [tmp, I] = [mkBlock(), mkBlock()];

    this.I[1].copy(I);
    for (let i = 1, inBytes = input.length; inBytes >= 64; i++, inBytes -= 32) {
      this.aes.AES4(this.J[0], I, this.L[i % 8], input.slice(BLOCK_SIZE, BLOCK_SIZE * 2), tmp);
      xorBytes1x16(input, tmp, output);

      this.aes.AES4(ZERO, this.I[0], this.L[0], output, tmp);
      xorBytes1x16(input.slice(BLOCK_SIZE), tmp, output.slice(BLOCK_SIZE, BLOCK_SIZE * 2));
      xorBytes1x16(output.slice(BLOCK_SIZE), X, X);

      input = input.slice(32);
      output = output.slice(32);
      if (i % 8 === 0) {
        doubleBlock(I);
      }
    }
  };

  this.aezCorePass2 = function (input, output, Y, S) {
    const [tmp, I] = [mkBlock(), mkBlock()];

    this.I[1].copy(I);
    for (let i = 1, inBytes = input.length; inBytes >= 64; i++, inBytes -= 32) {
      this.aes.AES4(this.J[1], I, this.L[i % 8], S, tmp);
      xorBytes1x16(output, tmp, output);
      xorBytes1x16(output.slice(BLOCK_SIZE), tmp, output.slice(BLOCK_SIZE, BLOCK_SIZE * 2));
      xorBytes1x16(output, Y, Y);

      this.aes.AES4(ZERO, this.I[0], this.L[0], output.slice(BLOCK_SIZE, BLOCK_SIZE * 2), tmp);
      xorBytes1x16(output, tmp, output);

      this.aes.AES4(this.J[0], I, this.L[i % 8], output, tmp);
      xorBytes1x16(output.slice(BLOCK_SIZE), tmp, output.slice(BLOCK_SIZE, BLOCK_SIZE * 2));

      output.copy(tmp);
      output.slice(BLOCK_SIZE).copy(output.slice(0, BLOCK_SIZE));
      tmp.copy(output.slice(BLOCK_SIZE));

      input = input.slice(32);
      output = output.slice(32);
      if (i % 8 === 0) {
        doubleBlock(I);
      }
    }
  };
};

module.exports = AEZState;
