const { BLOCK_SIZE, uint32, mkBlock, xorBytes1x16, xorBytes4x16, extractKey, multBlock, doubleBlock } = require('./functions');
const AESRound = require('./aes_round');
const Buffer = require('safe-buffer').Buffer;

const State = function () {

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
    const [ buf, ctr ] = [mkBlock(), mkBlock()];
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
        if (ctr[i+1] !== 0) {
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

};

module.exports = State;
