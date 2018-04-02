const assert = require('assert');
const Utils = require('../utils');

const bitcore = require('bitcore-lib');
bitcore.BufferUtil = require('bitcore-lib/lib/util/buffer');
bitcore.Signature = require('bitcore-lib/lib/crypto/signature');
bitcore.TXSignature = require('bitcore-lib/lib/transaction/signature');

const BitcoreTransaction = require('./bitcoretransaction');

function BitcoinTransaction(options) {
  if(!(this instanceof BitcoinTransaction))
    return new BitcoinTransaction(options);

  // library-dependent types
  this.PublicKey = bitcore.PublicKey;
  this.PrivateKey = bitcore.PrivateKey;
  this.Hash = bitcore.crypto.Hash;
  this.BN = bitcore.crypto.BN;
  this.Point = bitcore.crypto.Point;
  this.Transaction = bitcore.Transaction;
  this.BufferUtil = bitcore.BufferUtil;
  this.Signature = bitcore.Signature;
  this.TXSignature = bitcore.TXSignature;

  this.network = BitcoreTransaction.Testnet;

  this.tx = new this.Transaction();

  if(options) {
    this.fromOptions(options);
  }
}

BitcoinTransaction.prototype = Object.create(BitcoreTransaction.prototype);

BitcoinTransaction.fromJSON = function fromJSON(json) {
  return new BitcoinTransaction().fromJSON(json);
};

BitcoinTransaction.fromOptions = function fromOptions(options) {
  return new BitcoinTransaction().fromOptions(options);
};

BitcoinTransaction.prototype.defaultSigtype = function () {
  return this.Signature.SIGHASH_ALL;
};

BitcoinTransaction.prototype.prepare = async function prepare(options) {
  if(!options) {
    options = {};
  }

  assert(options.wallet);
  assert(options.address);
  assert(options.value);

  const coins = await options.wallet.getCoins();

  const utxos = coins.map(coin => {
    return {
      txId: Utils.reverse(coin.hash),
      outputIndex: coin.index,
      script: coin.script.toJSON(),
      satoshis: coin.value
    }
  });

  this.tx = this.tx
    .from(utxos)
    .to(options.address, options.value);

  if(options.fee) {
    this.tx = this.tx.fee(options.fee);
  }

  this.tx = this.tx.change(options.wallet.getAddress('base58'));

  assert(this.tx.hasAllUtxoInfo());
};

module.exports = BitcoinTransaction;
