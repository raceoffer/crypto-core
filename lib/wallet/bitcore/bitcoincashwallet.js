const BitcoreWallet = require('./bitcorewallet');
const InsightProvider = require('../../provider/insightprovider');

const bitcoincashjs = require('bitcoincashjs');

function BitcoinCashWallet() {
  this.network = null;
  this.address = null;
  this.provider = null;
}

BitcoinCashWallet.prototype = Object.create(BitcoreWallet.prototype);
BitcoinCashWallet.prototype.constructor = BitcoinCashWallet;

BitcoinCashWallet.address = function(key, network) {
  return new bitcoincashjs.PublicKey(
    new bitcoincashjs.crypto.Point(
      bitcoincashjs.crypto.BN.fromString(key.x.toString(16), 16),
      bitcoincashjs.crypto.BN.fromString(key.y.toString(16), 16),
      true
    ), {
      network: network === 'main' ? 'livenet' : 'testnet'
    }).toAddress().toString();
};

BitcoinCashWallet.Mainnet = 'main';
BitcoinCashWallet.Testnet = 'testnet';

BitcoinCashWallet.prototype.fromOptions = function(options) {
  this.network = options.network || BitcoinCashWallet.Mainnet;
  this.address = BitcoinCashWallet.address(options.key, this.network);
  this.endpoint = options.endpoint;

  this.provider = InsightProvider.fromOptions({
    endpoint: this.endpoint
  });

  return this;
};

BitcoinCashWallet.fromOptions = function(options) {
  return new BitcoinCashWallet().fromOptions(options);
};

BitcoinCashWallet.prototype.fromInternal = function(balance) {
  return bitcoincashjs.Unit.fromSatoshis(balance).toBTC();
};

BitcoinCashWallet.prototype.toInternal = function(balance) {
  return Math.floor(bitcoincashjs.Unit.fromBTC(balance).toSatoshis());
};

module.exports = BitcoinCashWallet;
