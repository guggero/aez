# AEZ implementation for node

[![Build Status](https://travis-ci.org/guggero/aez.svg?branch=master)](https://travis-ci.org/guggero/aez)
[![GitHub version](https://badge.fury.io/gh/guggero%2Faez.svg)](http://badge.fury.io/gh/guggero%2Faez)
[![Open Source Love](https://badges.frapsoft.com/os/mit/mit.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)
[![Dependency Status](https://david-dm.org/guggero/aez.svg)](https://david-dm.org/guggero/aez)
[![devDependency Status](https://david-dm.org/guggero/aez/dev-status.svg)](https://david-dm.org/guggero/aez#info=devDependencies)
[![Coverage Status](https://coveralls.io/repos/github/guggero/aez/badge.svg?branch=master)](https://coveralls.io/github/guggero/aez?branch=master)

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