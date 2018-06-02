const assert = require("assert");

const pbkdf2 = require('pbkdf2');
const random_bytes = require('randombytes');
const aesjs = require('aes-js');
const digest = require('hash.js');

const TreeModel = require('tree-model');
const KeyChain = require('./primitives/keychain');

function Utils() {}

Utils.deriveAesKey = function(passwd) {
  const salt = Buffer.from('Spatium Wallet', 'ascii');
  const N = 50000;

  assert(Buffer.isBuffer(passwd), 'passwd must be a buffer');

  return pbkdf2.pbkdf2Sync(passwd, salt, N, 32, 'sha256');
};

Utils.fixedKey = Utils.deriveAesKey(Buffer.from('Spatium', 'ascii'));

Utils.randomBytes = function(n) {
  return new Buffer(random_bytes(n));
};

Utils.encrypt = function(buffer, key) {
  const iv = Utils.randomBytes(16);
  const aes = new aesjs.ModeOfOperation.cbc(key, iv);
  const ciphertext = new Buffer(aes.encrypt(aesjs.padding.pkcs7.pad(buffer)));
  return Buffer.concat([iv, ciphertext]);
};

Utils.decrypt = function(ciphertext, key) {
  const iv = ciphertext.slice(0, 16);
  const aes = new aesjs.ModeOfOperation.cbc(key, iv);
  return new Buffer(aesjs.padding.pkcs7.strip(aes.decrypt(ciphertext.slice(16))));
};

Utils.sha256 = function(buffer) {
  return new Buffer(digest.sha256().update(buffer).digest());
};

Utils.checksum = function(buffer) {
  return Utils.sha256(Utils.sha256(buffer)).slice(0, 4);
};

Utils.packSeed = function(seed) {
  return Buffer.concat([Utils.checksum(seed), seed])
};

Utils.tryUnpackSeed = function(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== 68) {
    return null;
  }
  const seed = secret.slice(4);
  return Utils.checksum(seed).equals(secret.slice(0, 4)) ? seed : null;
};

Utils.tryUnpackEncryptedSeed = function(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== 100) {
    return null;
  }
  const seed = secret.slice(4);
  return Utils.checksum(seed).equals(secret.slice(0, 4)) ? seed : null;
};

Utils.packMultiple = function(array) {
  const header = Buffer.alloc(4*(array.length+1));
  header.writeUInt32BE(array.length, 0);
  for(let i=0; i<array.length; ++i) {
    header.writeUInt32BE(array[i].length, 4*(i+1));
  }
  return Buffer.concat([header].concat(array));
};

Utils.tryUnpackMultiple = function(buffer) {
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
};

Utils.packTree = function(tree, seed) {
  const root = new TreeModel().parse(tree);

  let stack = [];
  root.walk({ strategy: 'post' }, (node) => {
    const key = Utils.deriveAesKey(node.model.factor);

    let pack = null;
    if (node.children.length < 1) {
      pack = Utils.encrypt(Utils.packSeed(seed), key);
    } else {
      pack = Utils.encrypt(Utils.packMultiple(stack.slice(stack.length - node.children.length)), key);
      stack = stack.slice(0, stack.length - node.children.length);
    }

    stack.push(pack);
  });

  return stack[0];
};

Utils.matchPassphrase = function(chiphertexts, passphase) {
  const result = {
    subtexts: []
  };

  const key = Utils.deriveAesKey(passphase);

  for(let i=0; i<chiphertexts.length; ++i) {
    let decrypted = null;
    try {
      decrypted = Utils.decrypt(chiphertexts[i], key);
    } catch (e) {
      continue;
    }

    const seed = Utils.tryUnpackSeed(decrypted);
    if (seed) {
      result.seed = seed;
      break;
    }

    const pack = Utils.tryUnpackMultiple(decrypted);

    result.subtexts = result.subtexts.concat(pack);
  }

  return result;
};

Utils.packLogin = function(login) {
  const loginBuffer = Buffer.from(login, 'utf-8');

  const data = Buffer.concat([Utils.checksum(loginBuffer), loginBuffer]);

  return Utils.encrypt(data, Utils.fixedKey);
};

Utils.tryUnpackLogin = function(chiphertext) {

  let data = null;
  try {
    data = Utils.decrypt(chiphertext, Utils.fixedKey);
  } catch (ignored) {
    return null;
  }

  const login = data.slice(4);
  return Utils.checksum(login).equals(data.slice(0, 4)) ? login.toString('utf-8') : null;
};

Utils.reverse = function(data) {
  assert(typeof data === 'string');
  assert(data.length > 0);
  assert(data.length % 2 === 0);

  let out = '';

  for (let i = 0; i < data.length; i += 2)
    out = data.slice(i, i + 2) + out;

  return out;
};

Utils.getAccountSecret = function (userId, accountId) {
  const salt = Buffer.from('Spatium Wallet', 'ascii');
  const seed = pbkdf2.pbkdf2Sync(userId, salt, 128, 64, 'sha256');
  const chain = KeyChain.fromSeed(seed);
  const coin = 60;
  return chain.getAccountSecret(coin, accountId);
};

module.exports = Utils;
