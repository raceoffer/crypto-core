'use strict';

import PublicKey from 'bitcoincashjs/src/publickey';
import PrivateKey from 'bitcoincashjs/src/privatekey';
import Hash from 'bitcoincashjs/src/crypto/hash';
import BN from 'bitcoincashjs/src/crypto/bn';
import Point from 'bitcoincashjs/src/crypto/point';
import Transaction from 'bitcoincashjs/src/transaction';
import BufferUtil from 'bitcoincashjs/src/util/buffer';
import Signature from 'bitcoincashjs/src/crypto/signature';
import TXSignature from 'bitcoincashjs/src/transaction/signature';
import PublicKeyHashInput from 'bitcoincashjs/src/transaction/input/publickeyhash';
import PublicKeyInput from 'bitcoincashjs/src/transaction/input/publickey';

import { BitcoreTransaction } from './bitcoretransaction';

export class BitcoinCashTransaction extends BitcoreTransaction {
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
    return new BitcoinCashTransaction();
  }

  static fromJSON(json) {
    return new BitcoinCashTransaction().fromJSON(json);
  }

  static fromOptions(options) {
    return new BitcoinCashTransaction().fromOptions(options);
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
