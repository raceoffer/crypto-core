'use strict';

const CoreBN = require('litecore-lib/lib/crypto/bn');
const Point = require('litecore-lib/lib/crypto/point');
const PublicKey = require('litecore-lib/lib/publickey');
const Transaction = require('litecore-lib/lib/transaction');

const { BitcoreWallet } = require('./bitcorewallet');
const { InsightProvider } = require('../../provider/insightprovider');

class LitecoinWallet extends BitcoreWallet {
  constructor() {
    super(Transaction);
  }

  static address(point, network) {
    return new PublicKey(
      new Point(
        CoreBN.fromString(point.x.toString(16), 16),
        CoreBN.fromString(point.y.toString(16), 16),
        true
      ), {
        network: network === 'main' ? 'livenet' : 'testnet'
      }).toAddress().toString();
  }

  fromOptions(options) {
    this.network = options.network || LitecoinWallet.Mainnet;
    this.address = LitecoinWallet.address(options.point, this.network);
    this.endpoint = options.endpoint;

    this.provider = InsightProvider.fromOptions({
      endpoint: this.endpoint
    });

    return this;
  }

  static fromOptions(options) {
    return new LitecoinWallet().fromOptions(options);
  }
}

LitecoinWallet.Mainnet = 'main';
LitecoinWallet.Testnet = 'testnet';

module.exports = {
  LitecoinWallet
};
