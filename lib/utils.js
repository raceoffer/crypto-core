const assert = require("assert");
const request = require('request-promise-native');
const pbkdf2 = require('bcoin/lib/crypto/pbkdf2-browser');
const random = require('bcoin/lib/crypto/random-browser');
const aes = require('bcoin/lib/crypto/aes-browser');
const digest = require('bcoin/lib/crypto/digest-browser');
const TreeModel = require('tree-model');

function Utils() {}

Utils.deriveAesKey = function deriveAesKey(passwd) {
  const salt = Buffer.from('Spatium Wallet', 'ascii');
  const N = 50000;

  assert(Buffer.isBuffer(passwd), 'passwd must be a buffer');

  return pbkdf2.derive(passwd, salt, N, 32, 'sha256');
};

Utils.fixedKey = Utils.deriveAesKey(Buffer.from('Spatium', 'ascii'));

Utils.randomBytes = function randomBytes(n) {
  return random.randomBytes(n);
};

Utils.decrypt = function decrypt(ciphertext, key) {
  return aes.decipher(ciphertext.slice(16), key, ciphertext.slice(0, 16));
};

Utils.encrypt = function encrypt(buffer, key) {
  const iv = Utils.randomBytes(16);
  const ciphertext = aes.encipher(buffer, key, iv);
  return Buffer.concat([iv, ciphertext]);
};

Utils.sha256 = function sha256(buffer) {
  return digest.sha256(buffer);
};

Utils.checksum = function checksum(buffer) {
  return Utils.sha256(Utils.sha256(buffer)).slice(0, 4);
};

Utils.packSeed = function packSeed(seed) {
  return Buffer.concat([Utils.checksum(seed), seed])
};

Utils.tryUnpackSeed = function tryUnpackSeed(secret) {
  if (!Buffer.isBuffer(secret) || secret.length !== 68) {
    return null;
  }
  const seed = secret.slice(4);
  return Utils.checksum(seed).equals(secret.slice(0, 4)) ? seed : null;
};

Utils.packMultiple = function packMultiple(array) {
  const header = Buffer.alloc(4*(array.length+1));
  header.writeUInt32BE(array.length, 0);
  for(let i=0; i<array.length; ++i) {
    header.writeUInt32BE(array[i].length, 4*(i+1));
  }
  return Buffer.concat([header].concat(array));
};

Utils.tryUnpackMultiple = function tryUnpackMultiple(buffer) {
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

Utils.packTree = function packTree(tree, transformer, seed) {
  const root = new TreeModel().parse(tree);

  let stack = [];
  root.walk({ strategy: 'post' }, (node) => {
    const key = Utils.deriveAesKey(transformer(node.model));

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

Utils.matchPassphrase = function matchPassphrase(chiphertexts, passphase) {
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

Utils.testNetwork = async function testNetwork() {
  try {
    await request.head({
      uri: 'https://google.com',
      timeout: 1000
    });
    return true;
  } catch (e) {
    return false;
  }
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

module.exports = Utils;
