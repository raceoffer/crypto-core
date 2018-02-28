const assert = require("assert");
const eth = require('eth-lib');

const BitcoinCashTransaction = require('../bitcore/bitcoincashtransaction');
const BitcoinTransaction = require('../bitcore/bitcointransaction');
const EthereumTransaction = require('../ethereum/ethereumtransaction');

function Currency() {
  if(!(this instanceof Currency)) {
    return new Currency(options);
  }
}

Currency.bcoin = (typeof bcoin !== 'undefined') ? bcoin : null;

Currency.set = function (bcoin) {
  Currency.bcoin = bcoin;
  return Currency;
};

Currency.BTC = 'BTC';
Currency.BCH = 'BCH';
Currency.ETH = 'ETH';

Currency.Bitcoin = null;
Currency.BitcoinCash = null;
Currency.Ethereum = null;

Currency.get = function(coin) {
  switch(coin) {
    case Currency.BTC:
      if (!Currency.Bitcoin) {
        Currency.Bitcoin = new Bitcoin();
      }
      return Currency.Bitcoin;
    case Currency.BCH:
      if (!Currency.BitcoinCash) {
        Currency.BitcoinCash = new BitcoinCash();
      }
      return Currency.BitcoinCash;
    case Currency.ETH:
      if (!Currency.Ethereum) {
        Currency.Ethereum = new Ethereum();
      }
      return Currency.Ethereum;
  }
};

function Bitcoin () {
  if(!(this instanceof Bitcoin)) {
    return new Bitcoin(options);
  }
}

Bitcoin.prototype.formatPublic = function(key) {
  return Currency.bcoin.keyring.fromPublic(Buffer.from(key.encode(true, 'array'))).getPublicKey('base58');
};

Bitcoin.prototype.formatPrivate = function(key) {
  return Currency.bcoin.keyring.fromPrivate(key.toArrayLike(Buffer, 'be', 32)).getPrivateKey('base58');
};

Bitcoin.prototype.address = function(key) {
  return Currency.bcoin.keyring.fromPublic(Buffer.from(key.encode(true, 'array'))).getKeyAddress('base58');
};

Bitcoin.prototype.createTransaction = function(params) {
  return BitcoinTransaction.fromOptions(params);
};

Bitcoin.prototype.fromJSON = function(params) {
  return BitcoinTransaction.fromJSON(params);
};

function BitcoinCash () {
  if(!(this instanceof BitcoinCash)) {
    return new BitcoinCash(options);
  }
}

BitcoinCash.prototype.formatPublic = function(key) {
  return Currency.bcoin.keyring.fromPublic(Buffer.from(key.encode(true, 'array'))).getPublicKey('base58');
};

BitcoinCash.prototype.formatPrivate = function(key) {
  return Currency.bcoin.keyring.fromPrivate(key.toArrayLike(Buffer, 'be', 32)).getPrivateKey('base58');
};

BitcoinCash.prototype.address = function(key) {
  return Currency.bcoin.keyring.fromPublic(Buffer.from(key.encode(true, 'array'))).getKeyAddress('base58');
};

BitcoinCash.prototype.createTransaction = function(params) {
  return BitcoinCashTransaction.fromOptions(params);
};

BitcoinCash.prototype.fromJSON = function(params) {
  return BitcoinCashTransaction.fromJSON(params);
};

function Ethereum () {
  if(!(this instanceof Ethereum)) {
    return new Ethereum(options);
  }
}

Ethereum.prototype.formatPublic = function(key) {
  return '0x' + key.encode('hex', false).slice(2);
};

Ethereum.prototype.formatPrivate = function(key) {
  return '0x' + key.toString(16);
};

Ethereum.prototype.address = function(key) {
  const publicKey = this.formatPublic(key);
  const publicHash = eth.hash.keccak256(publicKey);
  return eth.account.toChecksum('0x' + publicHash.slice(-40));
};

Ethereum.prototype.fromJSON = function(params) {
  return EthereumTransaction.fromJSON(params);
};

module.exports = Currency;
