const litecore = require('litecore-lib');
litecore.BufferUtil = require('litecore-lib/lib/util/buffer');
litecore.Signature = require('litecore-lib/lib/crypto/signature');
litecore.TXSignature = require('litecore-lib/lib/transaction/signature');

const BitcoreTransaction = require('./bitcoretransaction');

function LitecoinTransaction() {
  this.PublicKey = litecore.PublicKey;
  this.PrivateKey = litecore.PrivateKey;
  this.Hash = litecore.crypto.Hash;
  this.BN = litecore.crypto.BN;
  this.Point = litecore.crypto.Point;
  this.Transaction = litecore.Transaction;
  this.BufferUtil = litecore.BufferUtil;
  this.Signature = litecore.Signature;
  this.TXSignature = litecore.TXSignature;

  this.network = null;

  this.tx = null;

  this.signers = null;
}

LitecoinTransaction.prototype = Object.create(BitcoreTransaction.prototype);
LitecoinTransaction.prototype.constructor = LitecoinTransaction;

LitecoinTransaction.fromOptions = function fromOptions(options) {
    return new LitecoinTransaction().fromOptions(options);
};

LitecoinTransaction.fromJSON = function fromJSON(json) {
    return new LitecoinTransaction().fromJSON(json);
};

LitecoinTransaction.prototype.networkName = function (network) {
    if(network === BitcoreTransaction.Mainnet) {
        return 'livenet';
    } else {
        return 'testnet';
    }
};

LitecoinTransaction.prototype.defaultSigtype = function () {
    return this.Signature.SIGHASH_ALL | this.Signature.SIGHASH_FORKID;
};

module.exports = LitecoinTransaction;
