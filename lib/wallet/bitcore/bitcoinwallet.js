'use strict';

const BN = require('bn.js');

const CoreBN = require('bitcore-lib/lib/crypto/bn');
const Point = require('bitcore-lib/lib/crypto/point');
const PublicKey = require('bitcore-lib/lib/publickey');
const Unit = require('bitcore-lib/lib/unit');
const Transaction = require('bitcore-lib/lib/transaction');

const { BitcoreWallet } = require('./bitcorewallet');
const { InsightProvider } = require('../../provider/insightprovider');

class BitcoinWallet extends BitcoreWallet {
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
        network: network
      }).toAddress().toString();
  }

  fromOptions(options) {
    this.network = options.network || BitcoinWallet.Mainnet;
    this.address = BitcoinWallet.address(options.point, this.network);
    this.endpoint = options.endpoint;

    this.provider = InsightProvider.fromOptions({
      endpoint: this.endpoint
    });

    return this;
  }

  static fromOptions(options) {
    return new BitcoinWallet().fromOptions(options);
  }

  fromInternal(balance) {
    return Unit.fromSatoshis(balance.toNumber()).toBTC();
  }

  toInternal(balance) {
    return new BN(Unit.fromBTC(balance).toSatoshis());
  }
}

BitcoinWallet.Mainnet = 'main';
BitcoinWallet.Testnet = 'testnet';

module.exports = {
  BitcoinWallet
};
