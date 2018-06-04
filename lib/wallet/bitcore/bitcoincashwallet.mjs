'use strict';

import BN from 'bn.js';

import CoreBN from 'bitcoincashjs/src/crypto/bn';
import Point from 'bitcoincashjs/src/crypto/point';
import PublicKey from 'bitcoincashjs/src/publickey';
import Unit from 'bitcoincashjs/src/unit';

import { BitcoreWallet } from './bitcorewallet';
import { InsightProvider } from '../../provider/insightprovider';

export class BitcoinCashWallet extends BitcoreWallet {
  constructor () {
    super();
  }

  static address(key, network) {
    return new PublicKey(
      new Point(
        CoreBN.fromString(key.x.toString(16), 16),
        CoreBN.fromString(key.y.toString(16), 16),
        true
      ), {
        network: network === 'main' ? 'livenet' : 'testnet'
      }).toAddress().toString();
  }

  fromOptions(options) {
    this.network = options.network || BitcoinCashWallet.Mainnet;
    this.address = BitcoinCashWallet.address(options.key, this.network);
    this.endpoint = options.endpoint;

    this.provider = InsightProvider.fromOptions({
      endpoint: this.endpoint
    });

    return this;
  }

  static fromOptions(options) {
    return new BitcoinCashWallet().fromOptions(options);
  }

  fromInternal(balance) {
    return Unit.fromSatoshis(balance.toNumber()).toBTC();
  }

  toInternal(balance) {
    return new BN(bitcoincashjs.Unit.fromBTC(balance).toSatoshis());
  }
}

BitcoinCashWallet.Mainnet = 'main';
BitcoinCashWallet.Testnet = 'testnet';
