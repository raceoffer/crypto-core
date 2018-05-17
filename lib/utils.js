'use strict';

import assert from 'assert';

const pbkdf2 = require('pbkdf2');
const random_bytes = require('randombytes');
const aesjs = require('aes-js');
const digest = require('hash.js');

const TreeModel = require('tree-model');

import { KeyChain } from './primitives/keychain';

export function deriveAesKey(passwd) {
  const salt = Buffer.from('Spatium Wallet', 'ascii');
  const N = 50000;

  assert(Buffer.isBuffer(passwd), 'passwd must be a buffer');

  return pbkdf2.pbkdf2Sync(passwd, salt, N, 32, 'sha256');
}

const fixedKey = deriveAesKey(Buffer.from('Spatium', 'ascii'));

export function randomBytes(n) {
  return new Buffer(random_bytes(n));
}

export function encrypt(buffer, key) {
  const iv = randomBytes(16);
  const aes = new aesjs.ModeOfOperation.cbc(key, iv);
  const ciphertext = new Buffer(aes.encrypt(aesjs.padding.pkcs7.pad(buffer)));
  return Buffer.concat([iv, ciphertext]);
}

export function decrypt(ciphertext, key) {
  const iv = ciphertext.slice(0, 16);
  const aes = new aesjs.ModeOfOperation.cbc(key, iv);
  return new Buffer(aesjs.padding.pkcs7.strip(aes.decrypt(ciphertext.slice(16))));
}

export function sha256(buffer) {
  return new Buffer(digest.sha256().update(buffer).digest());
}

export function checksum(buffer) {
  return sha256(sha256(buffer)).slice(0, 4);
}

export function packSeed(seed) {
  return Buffer.concat([checksum(seed), seed]);
}

export function tryUnpackSeed(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== 68) {
    return null;
  }
  const seed = secret.slice(4);
  return checksum(seed).equals(secret.slice(0, 4)) ? seed : null;
}

export function tryUnpackEncryptedSeed(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== 100) {
    return null;
  }
  const seed = secret.slice(4);
  return checksum(seed).equals(secret.slice(0, 4)) ? seed : null;
}

export function packMultiple(array) {
  const header = Buffer.alloc(4*(array.length+1));
  header.writeUInt32BE(array.length, 0);
  for(let i=0; i<array.length; ++i) {
    header.writeUInt32BE(array[i].length, 4*(i+1));
  }
  return Buffer.concat([header].concat(array));
}

export function tryUnpackMultiple(buffer) {
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

export function packTree(tree, seed) {
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

export function matchPassphrase(chiphertexts, passphase) {
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

export function packLogin(login) {
  const loginBuffer = Buffer.from(login, 'utf-8');

  const data = Buffer.concat([checksum(loginBuffer), loginBuffer]);

  return encrypt(data, fixedKey);
}

export function tryUnpackLogin(chiphertext) {
  let data = null;
  try {
    data = decrypt(chiphertext, fixedKey);
  } catch (ignored) {
    return null;
  }

  const login = data.slice(4);
  return checksum(login).equals(data.slice(0, 4)) ? login.toString('utf-8') : null;
}

export function reverse(data) {
  assert(typeof data === 'string');
  assert(data.length > 0);
  assert(data.length % 2 === 0);

  let out = '';

  for (let i = 0; i < data.length; i += 2) {
    out = data.slice(i, i + 2) + out;
  }

  return out;
}

export function getAccountSecret(userId, accountId) {
  const seed = deriveAesKey(Buffer.from(userId, 'utf8'));
  const chain = KeyChain.fromSeed(seed);
  const coin = 60;
  return chain.getAccountSecret(coin, accountId || 0);
}
