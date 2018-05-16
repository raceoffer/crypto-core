'use strict';

import BN from 'bn.js';

const CoreBN = require('bitcore-lib/lib/crypto/bn');
const Point = require('bitcore-lib/lib/crypto/point');
const PublicKey = require('bitcore-lib/lib/publickey');
const Unit = require('bitcore-lib/lib/unit');

import { BitcoreWallet } from './bitcorewallet';
import { InsightProvider } from '../../provider/insightprovider';

export class BitcoinWallet extends BitcoreWallet {
  constructor() {
    this.network = null;
    this.address = null;
    this.provider = null;
  }

  static address(key, network) {
    return new PublicKey(
      new Point(
        CoreBN.fromString(key.x.toString(16), 16),
        CoreBN.fromString(key.y.toString(16), 16),
        true
      ), {
        network: network
      }).toAddress().toString();
  }

  fromOptions(options) {
    this.network = options.network || BitcoinWallet.Mainnet;
    this.address = BitcoinWallet.address(options.key, this.network);
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
