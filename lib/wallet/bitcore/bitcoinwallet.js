const BitcoreWallet = require('./bitcorewallet');
const InsightProvider = require('../../provider/insightprovider');

const bitcore = require('bitcore-lib');

function BitcoinWallet() {
  this.network = null;
  this.address = null;
  this.provider = null;
}

BitcoinWallet.prototype = Object.create(BitcoreWallet.prototype);
BitcoinWallet.prototype.constructor = BitcoinWallet;

BitcoinWallet.address = function(key, network) {
  return new bitcore.PublicKey(
    new bitcore.crypto.Point(
      bitcore.crypto.BN.fromString(key.x.toString(16), 16),
      bitcore.crypto.BN.fromString(key.y.toString(16), 16),
      true
    ), {
      network: network
    }).toAddress().toString();
};

BitcoinWallet.Mainnet = 'main';
BitcoinWallet.Testnet = 'testnet';

BitcoinWallet.prototype.fromOptions = function(options) {
  this.network = options.network || BitcoinWallet.Mainnet;
  this.address = BitcoinWallet.address(options.key, this.network);

  let endpoint = null;
  switch (this.network) {
    case BitcoinWallet.Mainnet:
      endpoint = 'https://insight.bitpay.com/api';
      break;
    case BitcoinWallet.Testnet:
      endpoint = 'https://test-insight.bitpay.com/api';
      break;
  }

  this.provider = InsightProvider.fromOptions({
    endpoint: endpoint
  });

  return this;
};

BitcoinWallet.fromOptions = function(options) {
  return new BitcoinWallet().fromOptions(options);
};

BitcoinWallet.prototype.fromInternal = function(balance) {
  return bitcore.Unit.fromSatoshis(balance).toBTC();
};

BitcoinWallet.prototype.toInternal = function(balance) {
  return bitcore.Unit.fromBTC(balance).toSatoshis();
};

module.exports = BitcoinWallet;
