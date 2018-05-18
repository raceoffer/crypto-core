'use strict';

const PublicKey = require('bitcoincashjs/src/publickey');
const PrivateKey = require('bitcoincashjs/src/privatekey');
const Hash = require('bitcoincashjs/src/crypto/hash');
const BN = require('bitcoincashjs/src/crypto/bn');
const Point = require('bitcoincashjs/src/crypto/point');
const Transaction = require('bitcoincashjs/src/transaction');
const BufferUtil = require('bitcoincashjs/src/util/buffer');
const Signature = require('bitcoincashjs/src/crypto/signature');
const TXSignature = require('bitcoincashjs/src/transaction/signature');
const PublicKeyHashInput = require('bitcoincashjs/src/transaction/input/publickeyhash');
const PublicKeyInput = require('bitcoincashjs/src/transaction/input/publickey');

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
