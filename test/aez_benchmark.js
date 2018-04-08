const aez = require('../src/aez');
const Benchmark = require('benchmark');
const microtime = require('microtime');
const randomBytes = require('random-bytes');
const Buffer = require('safe-buffer').Buffer;

const KEY_SIZE = 3 * 16;
const NONCE_SIZE = 16;
const TAU = 16;
const MESSAGE_SIZES = [1, 32, 512, 1024, 2048, 16384, 32768, 65536, 1024768];

let startTime = 0;
let numberOfRuns = 0;
let processedBytes = 0;

function benchmarkEncrypt(messageSize) {
  const key = Buffer.from(randomBytes.sync(KEY_SIZE));
  const nonce = Buffer.alloc(NONCE_SIZE, 0);
  const plaintext = Buffer.alloc(messageSize, 0);

  const encrypted = aez.encrypt(key, nonce, null, TAU, plaintext);
  if (encrypted.length !== plaintext.length + TAU) {
    throw new Error('Encryption failed!');
  }
}

function getReadableFileSizeString(fileSizeInBytes) {
  let i = -1;
  let byteUnits = [' kB', ' MB', ' GB', ' TB', 'PB', 'EB', 'ZB', 'YB'];
  do {
    fileSizeInBytes = fileSizeInBytes / 1024;
    i++;
  } while (fileSizeInBytes > 1024);

  return Math.max(fileSizeInBytes, 0.1).toFixed(1) + byteUnits[i];
}

MESSAGE_SIZES.forEach(size => {
  const fn = () => {
    try {
      benchmarkEncrypt(size);
      processedBytes += size;
      numberOfRuns++;
    } catch (e) {
      console.error(e);
    }
  };
  new Benchmark('Message size: ' + size + ' bytes', fn, {
    onStart: function () {
      startTime = microtime.now();
      processedBytes = 0;
      numberOfRuns = 0;
    },
    onComplete: function (event) {
      const elapsedTime = microtime.now() - startTime;
      const bytesPerSecond = processedBytes / (elapsedTime / 1000000);
      const microsecondsPerRun = elapsedTime / numberOfRuns;
      console.log(String(event.target) + ' ' + Math.round(microsecondsPerRun) + ' us/op ' +
        getReadableFileSizeString(bytesPerSecond) + '/s');
    }
  }).run();
});
