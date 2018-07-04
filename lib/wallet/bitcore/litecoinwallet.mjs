'use strict';

import BN from 'bn.js';

import CoreBN from 'litecore-lib/lib/crypto/bn';
import Point from 'litecore-lib/lib/crypto/point';
import PublicKey from 'litecore-lib/lib/publickey';
import Unit from 'litecore-lib/lib/unit';

import { BitcoreWallet } from './bitcorewallet';
import { InsightProvider } from '../../provider/insightprovider';

export class LitecoinWallet extends BitcoreWallet {
  constructor() {
    super();
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

  fromInternal(balance) {
    return Unit.fromSatoshis(balance.toNumber()).toBTC();
  }

  toInternal(balance) {
    return new BN(Unit.fromBTC(balance).toSatoshis());
  }
}

LitecoinWallet.Mainnet = 'main';
LitecoinWallet.Testnet = 'testnet';
