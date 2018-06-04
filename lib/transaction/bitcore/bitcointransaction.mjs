'use strict';

import PublicKey from 'bitcore-lib/lib/publickey';
import PrivateKey from 'bitcore-lib/lib/privatekey';
import Hash from 'bitcore-lib/lib/crypto/hash';
import BN from 'bitcore-lib/lib/crypto/bn';
import Point from 'bitcore-lib/lib/crypto/point';
import Transaction from 'bitcore-lib/lib/transaction';
import BufferUtil from 'bitcore-lib/lib/util/buffer';
import Signature from 'bitcore-lib/lib/crypto/signature';
import TXSignature from 'bitcore-lib/lib/transaction/signature';
import PublicKeyHashInput from 'bitcore-lib/lib/transaction/input/publickeyhash';
import PublicKeyInput from 'bitcore-lib/lib/transaction/input/publickey';

import { BitcoreTransaction } from './bitcoretransaction';

export class BitcoinTransaction extends BitcoreTransaction {
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
    return new BitcoinTransaction();
  }

  static fromJSON(json) {
    return new BitcoinTransaction().fromJSON(json);
  }

  static fromOptions(options) {
    return new BitcoinTransaction().fromOptions(options);
  }

  defaultSigtype() {
    return this.Signature.SIGHASH_ALL;
  }
}
