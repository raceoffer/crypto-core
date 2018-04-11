const Utils = require('../lib/utils');
const assert = require('assert');

(() => {
  const key = Utils.deriveAesKey(Buffer.from('test', 'utf-8'));

  assert(key.length === 32);

  const data = Utils.randomBytes(59);

  assert(data.length === 59);

  const ciphertext = Utils.encrypt(data, key);

  const source = Utils.decrypt(ciphertext, key);

  assert(source.equals(data));
  assert(data.equals(source));

  const seed = Utils.randomBytes(64);

  assert(seed.length === 64);

  const packed = Utils.packSeed(seed);

  assert(packed.length === 68);

  const unpacked = Utils.tryUnpackSeed(packed);

  assert(unpacked.equals(seed));
  assert(seed.equals(unpacked));

  const encrypted = Utils.encrypt(seed, key);

  assert(encrypted.length === 96);

  const packedEncrypted = Utils.packSeed(encrypted);

  assert(packedEncrypted.length === 100);

  const unpackedEncrypted = Utils.tryUnpackEncryptedSeed(packedEncrypted);

  assert(unpackedEncrypted.equals(encrypted));
  assert(encrypted.equals(unpackedEncrypted));

  const login = 'Lammonaaf';
  const packedLogin = Utils.packLogin(login);
  const unpackedLogin = Utils.tryUnpackLogin(packedLogin);

  assert(login === unpackedLogin);
  assert(unpackedLogin === login);

  console.log('OK');
})();
