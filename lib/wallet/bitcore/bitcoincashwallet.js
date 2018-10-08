'use strict';

const CoreBN = require('bitcoincashjs/src/crypto/bn');
const Point = require('bitcoincashjs/src/crypto/point');
const PublicKey = require('bitcoincashjs/src/publickey');
const Transaction = require('bitcoincashjs/src/transaction');

const { BitcoreWallet }= require('./bitcorewallet');
const { InsightProvider }= require('../../provider/insightprovider');

class BitcoinCashWallet extends BitcoreWallet {
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
    this.network = options.network || BitcoinCashWallet.Mainnet;
    this.address = BitcoinCashWallet.address(options.point, this.network);
    this.endpoint = options.endpoint;

    this.provider = InsightProvider.fromOptions({
      endpoint: this.endpoint
    });

    return this;
  }

  static fromOptions(options) {
    return new BitcoinCashWallet().fromOptions(options);
  }
}

BitcoinCashWallet.Mainnet = 'main';
BitcoinCashWallet.Testnet = 'testnet';

module.exports = {
  BitcoinCashWallet
};
