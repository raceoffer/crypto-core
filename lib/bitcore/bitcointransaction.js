const bitcore = require('bitcore-lib');
bitcore.BufferUtil = require('bitcore-lib/lib/util/buffer');
bitcore.Signature = require('bitcore-lib/lib/crypto/signature');
bitcore.TXSignature = require('bitcore-lib/lib/transaction/signature');

const BitcoreTransaction = require('./bitcoretransaction');

function BitcoinTransaction() {
  this.PublicKey = bitcore.PublicKey;
  this.PrivateKey = bitcore.PrivateKey;
  this.Hash = bitcore.crypto.Hash;
  this.BN = bitcore.crypto.BN;
  this.Transaction = bitcore.Transaction;
  this.BufferUtil = bitcore.BufferUtil;
  this.Signature = bitcore.Signature;
  this.TXSignature = bitcore.TXSignature;

  this.network = null;

  this.tx = null;
}

BitcoinTransaction.prototype = Object.create(BitcoreTransaction.prototype);
BitcoinTransaction.prototype.constructor = BitcoinTransaction;

BitcoinTransaction.fromJSON = function fromJSON(json) {
  return new BitcoinTransaction().fromJSON(json);
};

BitcoinTransaction.fromOptions = function fromOptions(options) {
  return new BitcoinTransaction().fromOptions(options);
};

BitcoinTransaction.prototype.defaultSigtype = function () {
  return this.Signature.SIGHASH_ALL;
};

module.exports = BitcoinTransaction;
