const cash = require('bitcoincashjs');
cash.BufferUtil = require('bitcoincashjs/src/util/buffer');
cash.Signature = require('bitcoincashjs/src/crypto/signature');
cash.TXSignature = require('bitcoincashjs/src/transaction/signature');

const BitcoreTransaction = require('./bitcoretransaction');

function BitcoinCashTransaction() {
  this.PublicKey = cash.PublicKey;
  this.PrivateKey = cash.PrivateKey;
  this.Hash = cash.crypto.Hash;
  this.BN = cash.crypto.BN;
  this.Transaction = cash.Transaction;
  this.BufferUtil = cash.BufferUtil;
  this.Signature = cash.Signature;
  this.TXSignature = cash.TXSignature;

  this.network = null;

  this.tx = null;
}

BitcoinCashTransaction.prototype = Object.create(BitcoreTransaction.prototype);
BitcoinCashTransaction.prototype.constructor = BitcoinCashTransaction;

BitcoinCashTransaction.fromJSON = function fromJSON(json) {
  return new BitcoinCashTransaction().fromJSON(json);
};

BitcoinCashTransaction.fromOptions = function fromOptions(options) {
  return new BitcoinCashTransaction().fromOptions(options);
};

BitcoinCashTransaction.prototype.networkName = function (network) {
  if(network === BitcoreTransaction.Mainnet) {
    return 'livenet';
  } else {
    return 'testnet';
  }
};

BitcoinCashTransaction.prototype.defaultSigtype = function () {
  return this.Signature.SIGHASH_ALL | this.Signature.SIGHASH_FORKID;
};

module.exports = BitcoinCashTransaction;
