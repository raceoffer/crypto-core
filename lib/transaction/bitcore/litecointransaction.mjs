'use strict';

import PublicKey from 'litecore-lib/lib/publickey';
import PrivateKey from 'litecore-lib/lib/privatekey';
import Hash from 'litecore-lib/lib/crypto/hash';
import BN from 'litecore-lib/lib/crypto/bn';
import Point from 'litecore-lib/lib/crypto/point';
import Transaction from 'litecore-lib/lib/transaction';
import BufferUtil from 'litecore-lib/lib/util/buffer';
import Signature from 'litecore-lib/lib/crypto/signature';
import TXSignature from 'litecore-lib/lib/transaction/signature';
import PublicKeyHashInput from 'litecore-lib/lib/transaction/input/publickeyhash';
import PublicKeyInput from 'litecore-lib/lib/transaction/input/publickey';

import { BitcoreTransaction } from './bitcoretransaction';

export class LitecoinTransaction extends BitcoreTransaction {
  constructor() {
    super(
      PublicKey,
      PrivateKey,
      Hash,
      BN,
      Point,
      Transaction,
      BufferUtil,
      Signature,
      TXSignature,
      PublicKeyHashInput,
      PublicKeyInput
    );
  }

  static create() {
    return new LitecoinTransaction();
  }

  static fromOptions(options) {
    return new LitecoinTransaction().fromOptions(options);
  }

  static fromJSON(json) {
    return new LitecoinTransaction().fromJSON(json);
  }

  static fromBytes(bytes) {
    return new LitecoinTransaction().fromBytes(bytes);
  }

  networkName(network) {
    if(network === BitcoreTransaction.Mainnet) {
      return 'livenet';
    } else {
      return 'testnet';
    }
  }

  defaultSigtype() {
    return this.Signature.SIGHASH_ALL | this.Signature.SIGHASH_FORKID;
  }
}
