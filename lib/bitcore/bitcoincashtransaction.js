const assert = require('assert');
const Utils = require('../utils');

const cash = require('bitcoincashjs');
cash.BufferUtil = require('bitcoincashjs/src/util/buffer');
cash.Signature = require('bitcoincashjs/src/crypto/signature');
cash.TXSignature = require('bitcoincashjs/src/transaction/signature');

const BitcoreTransaction = require('./bitcoretransaction');

function BitcoinCashTransaction(options) {
  if(!(this instanceof BitcoinCashTransaction))
    return new BitcoinCashTransaction(options);

  // library-dependent types
  this.PublicKey = cash.PublicKey;
  this.PrivateKey = cash.PrivateKey;
  this.Hash = cash.crypto.Hash;
  this.BN = cash.crypto.BN;
  this.Transaction = cash.Transaction;
  this.BufferUtil = cash.BufferUtil;
  this.Signature = cash.Signature;
  this.TXSignature = cash.TXSignature;

  this.network = BitcoreTransaction.Testnet;

  this.tx = new this.Transaction();

  if(options) {
    this.fromOptions(options);
  }
}

BitcoinCashTransaction.prototype = Object.create(BitcoreTransaction.prototype);

BitcoinCashTransaction.fromOptions = function fromOptions(options) {
  return new BitcoinCashTransaction().fromOptions(options);
};

BitcoinCashTransaction.fromJSON = function fromJSON(json) {
  return new BitcoinCashTransaction().fromJSON(json);
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

BitcoinCashTransaction.prototype.prepare = async function prepare(options) {
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

  const publicKey = new this.PublicKey(options.wallet.getPublicKey(), { network: this.networkName(this.network) });

  this.tx = this.tx
    .from(utxos)
    .to(options.address, options.value)
    .change(publicKey.toAddress().toString());

  assert(this.tx.hasAllUtxoInfo());
};

module.exports = BitcoinCashTransaction;
