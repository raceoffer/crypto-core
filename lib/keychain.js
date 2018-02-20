const assert = require("assert");

function KeyChain(options) {
  if(!(this instanceof KeyChain))
    return new KeyChain(options);

  this.masterKey = null;

  if(options) {
    this.fromOptions(options);
  }
}

KeyChain.bcoin = (typeof bcoin !== 'undefined') ? bcoin : null;

KeyChain.set = function (bcoin) {
  KeyChain.bcoin = bcoin;
  return KeyChain;
};

KeyChain.prototype.fromOptions = function fromOptions(options) {
  assert(Buffer.isBuffer(options.seed), 'A seed is required');

  this.masterKey = KeyChain.bcoin.hd.fromSeed(options.seed);

  return this;
};

KeyChain.fromOptions = function fromOptions(options) {
  return new KeyChain().fromOptions(options);
};

KeyChain.fromSeed = function fromSeed(seed) {
  return KeyChain.fromOptions({ seed: seed });
};

KeyChain.normalizedSeed = function normalizedSeed(string) {
  return KeyChain.bcoin.crypto.digest.sha512(Buffer.from(string));
};

KeyChain.prototype.deriveAccountKey = function deriveAccountKey(coin_type, account) {
  if (this.masterKey.network.keyPrefix.coinType === 1) {
    coin_type = 1; // The coin type for any currency in test network is the same
  }
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
