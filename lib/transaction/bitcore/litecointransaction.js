'use strict';

const PublicKey = require('litecore-lib/lib/publickey');
const PrivateKey = require('litecore-lib/lib/privatekey');
const Hash = require('litecore-lib/lib/crypto/hash');
const BN = require('litecore-lib/lib/crypto/bn');
const Point = require('litecore-lib/lib/crypto/point');
const Transaction = require('litecore-lib/lib/transaction');
const BufferUtil = require('litecore-lib/lib/util/buffer');
const Signature = require('litecore-lib/lib/crypto/signature');
const TXSignature = require('litecore-lib/lib/transaction/signature');
const PublicKeyHashInput = require('litecore-lib/lib/transaction/input/publickeyhash');
const PublicKeyInput = require('litecore-lib/lib/transaction/input/publickey');

const { BitcoreTransaction } = require('./bitcoretransaction');

class LitecoinTransaction extends BitcoreTransaction {
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

  static fromJSON(json, hex) {
    return new LitecoinTransaction().fromJSON(json, hex);
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

module.exports = {
  LitecoinTransaction
};
