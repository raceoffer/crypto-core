'use strict';

import BN from 'bn.js';

import CoreBN from 'bitcore-lib/lib/crypto/bn';
import Point from 'bitcore-lib/lib/crypto/point';
import PublicKey from 'bitcore-lib/lib/publickey';
import Unit from 'bitcore-lib/lib/unit';

import { BitcoreWallet } from './bitcorewallet';
import { InsightProvider } from '../../provider/insightprovider';

export class BitcoinWallet extends BitcoreWallet {
  constructor() {
    super();
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
