'use strict';

import assert from 'assert';
import hd from 'bitcore-lib/lib/hdprivatekey';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

export class KeyChain {
  constructor() {
    this.masterKey = null;
  }

  fromOptions(options) {
    assert(Buffer.isBuffer(options.seed), 'A seed is required');

    this.masterKey = hd.fromSeed(options.seed, null);

    return this;
  }

  static fromOptions(options) {
    return new KeyChain().fromOptions(options);
  }

  static fromSeed(seed) {
    return KeyChain.fromOptions({ seed: seed });
  }

  deriveAccountKey(coin_type, account) {
    return this.masterKey
      .derive(44, true) // BIP 44
      .derive(coin_type, true) // Crypto coin id
      .derive(account, true) // Account index
      .derive(0, true) // External chain
      .derive(0, true); // Single key
  }

  getAccountSecret(coin_type, account) {
    return this.deriveAccountKey(coin_type, account).privateKey.toBuffer();
  }
}
