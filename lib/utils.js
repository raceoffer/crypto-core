'use strict';

const assert = require('assert');

const pbkdf2 = require('pbkdf2');
const random_bytes = require('randombytes');
const aesjs = require('aes-js');
const digest = require('hash.js');

const { Buffer } = require('buffer');

const TreeModel = require('tree-model');

const { KeyChain } = require('./primitives/keychain');

const fixedKey = Buffer.from('60206c42416a728cf47889bf8435c7322ecfa2d81d51a3ebfc0018c860ceb110', 'hex');

function deriveAesKey(passwd) {
  const salt = Buffer.from('Spatium Wallet', 'ascii');
  const N = 50000;

  assert(Buffer.isBuffer(passwd), 'passwd must be a buffer');

  return pbkdf2.pbkdf2Sync(passwd, salt, N, 32, 'sha256');
}

function randomBytes(n) {
  return new Buffer(random_bytes(n));
}

function encrypt(buffer, key) {
  const iv = randomBytes(16);
  const aes = new aesjs.ModeOfOperation.cbc(key, iv);
  const ciphertext = new Buffer(aes.encrypt(aesjs.padding.pkcs7.pad(buffer)));
  return Buffer.concat([iv, ciphertext]);
}

function decrypt(ciphertext, key) {
  const iv = ciphertext.slice(0, 16);
  const aes = new aesjs.ModeOfOperation.cbc(key, iv);
  return new Buffer(aesjs.padding.pkcs7.strip(aes.decrypt(ciphertext.slice(16))));
}

function sha256(buffer) {
  return new Buffer(digest.sha256().update(buffer).digest());
}

function checksum(buffer) {
  return sha256(sha256(buffer)).slice(0, 4);
}

function packSeed(seed) {
  return Buffer.concat([checksum(seed), seed]);
}

function tryUnpackSeed(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== 68) {
    return null;
  }
  const seed = secret.slice(4);
  return checksum(seed).equals(secret.slice(0, 4)) ? seed : null;
}

function tryUnpackEncryptedSeed(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== 100) {
    return null;
  }
  const seed = secret.slice(4);
  return checksum(seed).equals(secret.slice(0, 4)) ? seed : null;
}

function packMultiple(array) {
  const header = Buffer.alloc(4*(array.length+1));
  header.writeUInt32BE(array.length, 0);
  for(let i=0; i<array.length; ++i) {
    header.writeUInt32BE(array[i].length, 4*(i+1));
  }
  return Buffer.concat([header].concat(array));
}

function tryUnpackMultiple(buffer) {
  if(!Buffer.isBuffer(buffer) || buffer.length < 4) {
    return [];
  }

  const count = buffer.readUInt32BE(0);
  const headerLenght = 4*(count+1);
  if (headerLenght > buffer.length) {
    return [];
  }

  const lengths = [];
  for (let i=0; i<count; ++i) {
    lengths.push(buffer.readUInt32BE(4*(i+1)));
  }

  const totalLength = lengths.reduce((a, b) => a + b,0) + headerLenght;
  if (count !== lengths.length || totalLength !== buffer.length) {
    return [];
  }

  const buffers = [];
  let start = headerLenght;
  for (let i=0; i<lengths.length; ++i) {
    buffers.push(buffer.slice(start, start + lengths[i]));
    start += lengths[i];
  }

  return buffers;
}

function packTree(tree, seed) {
  const root = new TreeModel().parse(tree);

  let stack = [];
  root.walk({ strategy: 'post' }, (node) => {
    const key = deriveAesKey(node.model.factor);

    let pack = null;
    if (node.children.length < 1) {
      pack = encrypt(packSeed(seed), key);
    } else {
      pack = encrypt(packMultiple(stack.slice(stack.length - node.children.length)), key);
      stack = stack.slice(0, stack.length - node.children.length);
    }

    stack.push(pack);
  });

  return stack[0];
}

function matchPassphrase(chiphertexts, passphase) {
  const result = {
    subtexts: []
  };

  const key = deriveAesKey(passphase);

  for(let i=0; i<chiphertexts.length; ++i) {
    let decrypted = null;
    try {
      decrypted = decrypt(chiphertexts[i], key);
    } catch (e) {
      continue;
    }

    const seed = tryUnpackSeed(decrypted);
    if (seed) {
      result.seed = seed;
      break;
    }

    const pack = tryUnpackMultiple(decrypted);

    result.subtexts = result.subtexts.concat(pack);
  }

  return result;
}

function packLogin(login) {
  const loginBuffer = Buffer.from(login, 'utf-8');

  const data = Buffer.concat([checksum(loginBuffer), loginBuffer]);

  return encrypt(data, fixedKey);
}

function tryUnpackLogin(chiphertext) {
  let data = null;
  try {
    data = decrypt(chiphertext, fixedKey);
  } catch (ignored) {
    return null;
  }

  const login = data.slice(4);
  return checksum(login).equals(data.slice(0, 4)) ? login.toString('utf-8') : null;
}

function reverse(data) {
  assert(typeof data === 'string');
  assert(data.length > 0);
  assert(data.length % 2 === 0);

  let out = '';

  for (let i = 0; i < data.length; i += 2) {
    out = data.slice(i, i + 2) + out;
  }

  return out;
}

function getAccountSecret(userId, accountId) {
  const salt = Buffer.from('Spatium Wallet', 'ascii');
  const seed = pbkdf2.pbkdf2Sync(userId, salt, 128, 64, 'sha256');
  const chain = KeyChain.fromSeed(seed);
  const coin = 60;
  return chain.getAccountSecret(coin, accountId);
}

module.exports = {
  deriveAesKey,
  randomBytes,
  encrypt,
  decrypt,
  sha256,
  checksum,
  packSeed,
  tryUnpackSeed,
  tryUnpackEncryptedSeed,
  packMultiple,
  tryUnpackMultiple,
  packTree,
  matchPassphrase,
  packLogin,
  tryUnpackLogin,
  reverse,
  getAccountSecret
};
