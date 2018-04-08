const {
  BLOCK_SIZE, uint32, mkBlock, xorBytes1x16, xorBytes4x16,
  extractKey, multBlock, doubleBlock, oneZeroPad, xorBytes
} = require('./functions');
const AESRound = require('./aes_round');
const floor = Math.floor;

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

  this.aezPRF = function (delta, tau, dst) {
    const [buf, ctr] = [mkBlock(), mkBlock()];

    let off = 0;
    while (tau >= BLOCK_SIZE) {
      xorBytes1x16(delta, ctr, buf);
      this.aes.AES10(this.L[3], buf, buf);
      buf.copy(dst, off);

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
      buf.copy(dst, off);
    }
  };

  this.encipher = function (delta, input, dst) {
    if (!input || input.length === 0) {
      return;
    }

    if (input.length < 32) {
      this.aezTiny(delta, input, 0, dst);
    } else {
      this.aezCore(delta, input, 0, dst);
    }
  };

  this.decipher = function (delta, input, dst) {
    if (!input || input.length === 0) {
      return;
    }

    if (input.length < 32) {
      this.aezTiny(delta, input, 1, dst);
    } else {
      this.aezCore(delta, input, 1, dst);
    }
  };

  this.aezTiny = function (delta, input, d, dst) {
    const inBytes = input.length;
    const buf = mkBlock(2 * BLOCK_SIZE);
    const [L, R, tmp] = [mkBlock(), mkBlock(), mkBlock()];
    let mask = 0x00;
    let pad = 0x80;
    let rounds, i, j, step;

    i = 7;
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
        L[0] ^= (tmp[0] & 0x80);
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
      buf[floor(inBytes / 2)] = (buf[floor(inBytes / 2)] & mask) | pad;
      xorBytes1x16(buf, delta, buf);
      buf[15] ^= j;
      this.aes.AES4(ZERO, this.I[1], this.L[i], buf, tmp);
      xorBytes1x16(L, tmp, L);

      buf.fill(0, 0, BLOCK_SIZE);
      L.slice(0, (inBytes + 1) / 2).copy(buf);
      buf[floor(inBytes / 2)] = (buf[floor(inBytes / 2)] & mask) | pad;
      xorBytes1x16(buf, delta, buf);
      buf[15] ^= j + step;
      this.aes.AES4(ZERO, this.I[1], this.L[i], buf, tmp);
      xorBytes1x16(R, tmp, R);
    }

    R.slice(0, floor(inBytes / 2)).copy(buf);
    L.slice(0, floor((inBytes + 1) / 2)).copy(buf, floor(inBytes / 2));
    if (inBytes & 1 !== 0) {
      for (let k = inBytes - 1; k > inBytes / 2; k--) {
        buf[k] = (buf[k] >> 4) | (buf[k - 1] << 4);
      }
      buf[floor(inBytes / 2)] = (L[0] >> 4) | (R[floor(inBytes / 2)] & 0xf0);
    }

    buf.slice(0, inBytes).copy(dst);
    if (inBytes < 16 && d === 0) {
      buf.fill(0, inBytes, BLOCK_SIZE);
      buf[0] |= 0x80;
      xorBytes1x16(delta, buf, buf);
      this.aes.AES4(ZERO, this.I[1], this.L[3], buf, tmp);
      dst[0] ^= tmp[0] & 0x80;
    }
  };

  this.aezCore = function (delta, input, d, dst) {
    const inBytes = input.length;
    let fragBytes = inBytes % 32;

    const initialBytes = inBytes - fragBytes - 32;
    const [tmp, X, Y, S] = [mkBlock(), mkBlock(), mkBlock(), mkBlock()];

    const outOrig = dst;
    const inOrig = input;

    // Compute X and store intermediate results
    if (inBytes >= 64) {
      this.aezCorePass1(input, dst, X);
    }

    // Finish X calculation
    input = input.slice(initialBytes);
    if (fragBytes >= BLOCK_SIZE) {
      this.aes.AES4(ZERO, this.I[1], this.L[4], input, tmp);
      xorBytes1x16(X, tmp, X);
      oneZeroPad(input.slice(BLOCK_SIZE), fragBytes - BLOCK_SIZE, tmp);
      this.aes.AES4(ZERO, this.I[1], this.L[5], tmp, tmp);
      xorBytes1x16(X, tmp, X);
    } else if (fragBytes > 0) {
      oneZeroPad(input, fragBytes, tmp);
      this.aes.AES4(ZERO, this.I[1], this.L[4], tmp, tmp);
      xorBytes1x16(X, tmp, X);
    }

    // Calculate S
    dst = outOrig.slice(inOrig.length - 32);
    input = inOrig.slice(inOrig.length - 32);
    this.aes.AES4(ZERO, this.I[1], this.L[(1 + d) % 8], input.slice(BLOCK_SIZE, BLOCK_SIZE * 2), tmp);
    xorBytes4x16(X, input, delta, tmp, dst);
    this.aes.AES10(this.L[(1 + d) % 8], dst, tmp);
    xorBytes1x16(input.slice(BLOCK_SIZE), tmp, dst.slice(BLOCK_SIZE, BLOCK_SIZE * 2));
    xorBytes1x16(dst, dst.slice(BLOCK_SIZE), S);

    // Pass 2 over intermediate values in dst[32..]. Final values written
    dst = outOrig;
    input = inOrig;
    if (input.length >= 64) {
      this.aezCorePass2(input, dst, Y, S);
    }

    // Finish Y calculation and finish encryption of fragment bytes
    dst = dst.slice(initialBytes);
    input = input.slice(initialBytes);
    if (fragBytes >= BLOCK_SIZE) {
      this.aes.AES10(this.L[4], S, tmp);
      xorBytes1x16(input, tmp, dst);
      this.aes.AES4(ZERO, this.I[1], this.L[4], dst, tmp);
      xorBytes1x16(Y, tmp, Y);

      dst = dst.slice(BLOCK_SIZE);
      input = input.slice(BLOCK_SIZE);
      fragBytes -= BLOCK_SIZE;

      this.aes.AES10(this.L[5], S, tmp);
      xorBytes(input, tmp, tmp.slice(0, fragBytes));
      tmp.slice(0, fragBytes).copy(dst);
      tmp.slice(fragBytes).fill(0);
      tmp[fragBytes] = 0x80;
      this.aes.AES4(ZERO, this.I[1], this.L[5], tmp, tmp);
      xorBytes1x16(Y, tmp, Y);
    } else if (fragBytes > 0) {
      this.aes.AES10(this.L[4], S, tmp);
      xorBytes(input, tmp, tmp.slice(0, fragBytes));
      tmp.slice(0, fragBytes).copy(dst);
      tmp.slice(fragBytes).fill(0);
      tmp[fragBytes] = 0x80;
      this.aes.AES4(ZERO, this.I[1], this.L[4], tmp, tmp);
      xorBytes1x16(Y, tmp, Y);
    }

    // Finish encryption of last two blocks
    dst = outOrig.slice(inOrig.length - 32);
    this.aes.AES10(this.L[(2 - d) % 8], dst.slice(BLOCK_SIZE), tmp);
    xorBytes1x16(dst, tmp, dst);
    this.aes.AES4(ZERO, this.I[1], this.L[(2 - d) % 8], dst, tmp);
    xorBytes4x16(tmp, dst.slice(BLOCK_SIZE), delta, Y, dst.slice(BLOCK_SIZE));
    dst.slice(0, BLOCK_SIZE).copy(tmp);
    dst.slice(BLOCK_SIZE).copy(dst.slice(0, BLOCK_SIZE));
    tmp.copy(dst.slice(BLOCK_SIZE));
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
