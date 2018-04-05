const assert = require('assert');
const hd = require('bcoin/lib/hd');

function KeyChain() {
  this.masterKey = null;
}

KeyChain.prototype.fromOptions = function fromOptions(options) {
  assert(Buffer.isBuffer(options.seed), 'A seed is required');

  this.masterKey = hd.fromSeed(options.seed);

  return this;
};

KeyChain.fromOptions = function fromOptions(options) {
  return new KeyChain().fromOptions(options);
};

KeyChain.fromSeed = function fromSeed(seed) {
  return KeyChain.fromOptions({ seed: seed });
};

KeyChain.prototype.deriveAccountKey = function deriveAccountKey(coin_type, account) {
  return this.masterKey
    .derive(44, true) // BIP 44
    .derive(coin_type, true) // Crypto coin id
    .derive(account, true) // Account index
    .derive(0, true) // External chain
    .derive(0, true) // Single key
};

KeyChain.prototype.getAccountSecret = function getAccountSecret(coin_type, account) {
  return this.deriveAccountKey(coin_type, account).privateKey;
};

module.exports = KeyChain;
