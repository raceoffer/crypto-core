'use strict';

const PublicKey = require('bitcore-lib/lib/publickey');
const PrivateKey = require('bitcore-lib/lib/privatekey');
const Hash = require('bitcore-lib/lib/crypto/hash');
const BN = require('bitcore-lib/lib/crypto/bn');
const Point = require('bitcore-lib/lib/crypto/point');
const Transaction = require('bitcore-lib/lib/transaction');
const BufferUtil = require('bitcore-lib/lib/util/buffer');
const Signature = require('bitcore-lib/lib/crypto/signature');
const TXSignature = require('bitcore-lib/lib/transaction/signature');
const PublicKeyHashInput = require('bitcore-lib/lib/transaction/input/publickeyhash');
const PublicKeyInput = require('bitcore-lib/lib/transaction/input/publickey');

const { BitcoreTransaction } = require('./bitcoretransaction');

class BitcoinTransaction extends BitcoreTransaction {
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

  static fromOptions(options) {
    return new BitcoinTransaction().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new BitcoinTransaction().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new BitcoinTransaction().fromBytes(bytes);
  }

  defaultSigtype() {
    return this.Signature.SIGHASH_ALL;
  }
}

module.exports = {
  BitcoinTransaction
};
