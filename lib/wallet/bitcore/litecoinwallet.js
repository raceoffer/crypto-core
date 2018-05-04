const BitcoreWallet = require('./bitcorewallet');
const InsightProvider = require('../../provider/insightprovider');

const litecore = require('litecore-lib');

function LitecoinWallet() {
  this.network = null;
  this.address = null;
  this.provider = null;
}

LitecoinWallet.prototype = Object.create(BitcoreWallet.prototype);
LitecoinWallet.prototype.constructor = LitecoinWallet;

LitecoinWallet.address = function(key, network) {
  return new litecore.PublicKey(
    new litecore.crypto.Point(
      litecore.crypto.BN.fromString(key.x.toString(16), 16),
      litecore.crypto.BN.fromString(key.y.toString(16), 16),
      true
    ), {
      network: network === 'main' ? 'livenet' : 'testnet'
    }).toAddress().toString();
};

LitecoinWallet.Mainnet = 'main';
LitecoinWallet.Testnet = 'testnet';

LitecoinWallet.prototype.fromOptions = function(options) {
  this.network = options.network || LitecoinWallet.Mainnet;
  this.address = LitecoinWallet.address(options.key, this.network);
  this.endpoint = options.endpoint;

  this.provider = InsightProvider.fromOptions({
    endpoint: this.endpoint
  });

  return this;
};

LitecoinWallet.fromOptions = function(options) {
  return new LitecoinWallet().fromOptions(options);
};

LitecoinWallet.prototype.fromInternal = function(balance) {
  return litecore.Unit.fromSatoshis(balance).toBTC();
};

LitecoinWallet.prototype.toInternal = function(balance) {
  return Math.floor(litecore.Unit.fromBTC(balance).toSatoshis());
};

module.exports = LitecoinWallet;
