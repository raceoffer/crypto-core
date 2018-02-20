const assert = require("assert");
const request = require('request-promise-native');
const TreeModel = require('tree-model');

function Utils() {}

Utils.bcoin = (typeof bcoin !== 'undefined') ? bcoin : null;

Utils.set = function (bcoin) {
  Utils.bcoin = bcoin;
  return Utils;
};

Utils.deriveAesKey = function deriveAesKey(passwd) {
  const salt = Buffer.from('Spatium Wallet', 'ascii');
  const N = 50000;

  assert(Buffer.isBuffer(passwd), 'passwd must be a buffer');

  return Utils.bcoin.crypto.pbkdf2.derive(passwd, salt, N, 32, 'sha256');
};

Utils.randomBytes = function randomBytes(n) {
  return Utils.bcoin.crypto.random.randomBytes(n);
};

Utils.decrypt = function decrypt(ciphertext, key) {
  return Utils.bcoin.crypto.aes.decipher(ciphertext.slice(16), key, ciphertext.slice(0, 16));
};

Utils.encrypt = function encrypt(buffer, key) {
  const iv = Utils.randomBytes(16);
  const ciphertext = Utils.bcoin.crypto.aes.encipher(buffer, key, iv);
  return Buffer.concat([iv, ciphertext]);
};

Utils.sha256 = function sha256(buffer) {
  return Utils.bcoin.crypto.digest.sha256(buffer);
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

Utils.fixedKey = Utils.deriveAesKey(Buffer.from('Spatium', 'ascii'));

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

Utils.hashInput = function hashInput(mtx, index, coin, type) {
  const input = mtx.inputs[index];

  assert(input, 'Input does not exist.');
  assert(coin, 'No coin passed.');

  // Get the previous output's script
  const value = coin.value;
  let prev = coin.script;
  let version = 0;

  // Grab regular p2sh redeem script.
  if (prev.isScripthash()) {
    prev = input.script.getRedeem();
    if (!prev)
      throw new Error('Input has not been templated.');
  }

  // If the output script is a witness program,
  // we have to switch the vector to the witness
  // and potentially alter the length. Note that
  // witnesses are stack items, so the `dummy`
  // _has_ to be an empty buffer (what OP_0
  // pushes onto the stack).
  if (prev.isWitnessScripthash()) {
    prev = input.witness.getRedeem();
    if (!prev)
      throw new Error('Input has not been templated.');
    version = 1;
  } else {
    const wpkh = prev.getWitnessPubkeyhash();
    if (wpkh) {
      prev = Script.fromPubkeyhash(wpkh);
      version = 1;
    }
  }

  if (type == null)
    type = Utils.bcoin.script.hashType.ALL;

  if (version == null)
    version = 0;

  return mtx.signatureHash(index, prev, value, type, version);
};

Utils.encodeSignature = function (signature) {
  const sig = Buffer.from(signature.toDER());

  const bw = new Utils.bcoin.utils.StaticWriter(sig.length + 1);

  bw.writeBytes(sig);
  bw.writeU8(Utils.bcoin.script.hashType.ALL);

  return bw.render();
};

Utils.injectInputSignature = function injectInputSignature(sig, mtx, index, coin, ring) {
  const input = mtx.inputs[index];

  // Get the previous output's script
  let prev = coin.script;
  let vector = input.script;
  let redeem = false;

  // Grab regular p2sh redeem script.
  if (prev.isScripthash()) {
    prev = input.script.getRedeem();
    if (!prev)
      throw new Error('Input has not been templated.');
    redeem = true;
  }

  // If the output script is a witness program,
  // we have to switch the vector to the witness
  // and potentially alter the length. Note that
  // witnesses are stack items, so the `dummy`
  // _has_ to be an empty buffer (what OP_0
  // pushes onto the stack).
  if (prev.isWitnessScripthash()) {
    prev = input.witness.getRedeem();
    if (!prev)
      throw new Error('Input has not been templated.');
    vector = input.witness;
    redeem = true;
  } else {
    const wpkh = prev.getWitnessPubkeyhash();
    if (wpkh) {
      prev = Script.fromPubkeyhash(wpkh);
      vector = input.witness;
      redeem = false;
    }
  }

  if (redeem) {
    const stack = vector.toStack();
    const redeem = stack.pop();

    const result = mtx.signVector(prev, stack, sig, ring);

    if (!result)
      return false;

    result.push(redeem);

    vector.fromStack(result);

    return true;
  }

  const stack = vector.toStack();
  const result = mtx.signVector(prev, stack, sig, ring);

  if (!result)
    return false;

  vector.fromStack(result);

  return true;
};

Utils.mapInputs = function mapInputs(mtx, rings) {
  if (!Array.isArray(rings)) {
    rings = [ rings ];
  }

  let inputMap = [];

  for (let i = 0; i < mtx.inputs.length; i++) {
    const { prevout } = mtx.inputs[i];
    const coin = mtx.view.getOutput(prevout);

    if (!coin)
      continue;

    for (let ring of rings) {
      if (ring.ownOutput(coin)) {
        inputMap.push({
          index: i,
          coin,
          ring
        });
        break;
      }
    }
  }

  return inputMap;
};

Utils.prepareScripts = function prepareScripts(mtx, inputMap) {
  for(let input of inputMap) {
    // Build script for input
    if (!mtx.scriptInput(input.index, input.coin, input.ring))
      throw new Error('Failed to prepare a script');
  }
};

Utils.hashInputs = function hashInputs(mtx, inputMap, type) {
  const hashes = [];
  for(let input of inputMap) {
    const hash = Utils.hashInput(mtx, input.index, input.coin, type);
    assert(hash, 'Failed to hash an input');

    hashes.push(hash);
  }
  return hashes;
};

Utils.injectSignatures = function injectSignatures(mtx, signatures, inputMap) {
  for(let i = 0; i < inputMap.length; i++) {
    Utils.injectInputSignature(signatures[i], mtx, inputMap[i].index, inputMap[i].coin, inputMap[i].ring);
  }
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

Utils.reverse = function(hex) {
  return Utils.bcoin.util.revHex(hex);
};

module.exports = Utils;
