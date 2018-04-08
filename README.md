# AEZ implementation for node

[![Build Status](https://travis-ci.org/guggero/aez.svg?branch=master)](https://travis-ci.org/guggero/aez)
[![Coverage Status](https://coveralls.io/repos/github/guggero/aez/badge.svg?branch=master)](https://coveralls.io/github/guggero/aez?branch=master)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)

[![npm version](https://badge.fury.io/js/aez.svg)](https://badge.fury.io/js/aez)
[![Dependency Status](https://david-dm.org/guggero/aez.svg)](https://david-dm.org/guggero/aez)
[![devDependency Status](https://david-dm.org/guggero/aez/dev-status.svg)](https://david-dm.org/guggero/aez#info=devDependencies)

This is an implementation of the [AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/) authenticated-encryption scheme in JavaScript for node.

The code is based upon [Yawning's implementation in Go](https://github.com/Yawning/aez) and the
[reference implementation in C](http://web.cs.ucdavis.edu/~rogaway/aez/code/v5/aez5_software.zip). 

I am by no means an expert in high performance JavaScript or the underlying cryptography. So this library might be really slow.

The current version passes all test vectors generated [with this hacked version of aez](https://github.com/nmathewson/aez_test_vectors).
**But the author does not give any guarantees that the algorithm is implemented correctly for every edge case!**

## How to install

**NPM**:
```bash
npm install --save aez
```

**yarn**:
```bash
yarn add aez
```

## How to use

NOTE: Every parameter that is not a number should be of type `Buffer` (or array of `Buffer`).

```javascript
const aez = require('aez');
const Buffer = require('safe-buffer').Buffer;

const key = Buffer.from('1311f8fc80a7ea28d78dd7723f09c44c1754cd35160ca8e7133ae3d7f636a19a', 'hex'); // sha256 of 'my-secret-key', but you should use a key derivation function like scrypt or PBKDF2!
const salt = Buffer.from('abba0110', 'hex'); // some random salt
const plaintext = Buffer.from('please encrypt me!', 'utf8');
const tau = 4;

const cipherText = aez.encrypt(key, null, [salt], tau, plaintext);
console.log('The encrypted string is: ' + cipherText.toString('hex'));

const decryptedText = aez.decrypt(key, null, [salt], tau, cipherText);
console.log('The decrypted string is: ' + decryptedText.toString());
```

## API

### aez.encrypt(key : Buffer, nonce : Buffer, additionalData : Buffer[], tau : Number, plaintext : Buffer) : Buffer
Encrypts a plaintext buffer with the given key, nonce and additionalData.

### aez.decrypt(key : Buffer, nonce : Buffer, additionalData : Buffer[], tau : Number, ciphertext : Buffer) : Buffer
Decrypts a ciphertext buffer with the given key, nonce and additionalData.

If the key is incorrect, `null` is returned.

## Performance

The code is not yet optimized for performance.

The following throughputs were achieved on an Intel Core i7-6500U running on linux/amd64:

```bash
$ node test/aez_benchmark.js
Message size: 1 bytes x 18,225 ops/sec ±2.01% (79 runs sampled) 60 us/op 16.3 kB/s
Message size: 32 bytes x 18,561 ops/sec ±1.88% (87 runs sampled) 58 us/op 540.6 kB/s
Message size: 512 bytes x 7,669 ops/sec ±1.46% (88 runs sampled) 139 us/op 3.5 MB/s
Message size: 1024 bytes x 4,804 ops/sec ±1.26% (89 runs sampled) 221 us/op 4.4 MB/s
Message size: 2048 bytes x 2,607 ops/sec ±3.51% (84 runs sampled) 406 us/op 4.8 MB/s
Message size: 16384 bytes x 413 ops/sec ±1.27% (87 runs sampled) 2558 us/op 6.1 MB/s
Message size: 32768 bytes x 215 ops/sec ±0.62% (83 runs sampled) 4910 us/op 6.4 MB/s
Message size: 65536 bytes x 109 ops/sec ±0.72% (79 runs sampled) 9642 us/op 6.5 MB/s
Message size: 1024768 bytes x 7.23 ops/sec ±0.82% (22 runs sampled) 140133 us/op 7.0 MB/s
Done in 49.59s.
```
