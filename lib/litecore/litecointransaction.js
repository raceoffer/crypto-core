const assert = require('assert');
const Utils = require('../utils');

const litecore = require('litecore-lib');
litecore.BufferUtil = require('litecore-lib/lib/util/buffer');
litecore.Signature = require('litecore-lib/lib/crypto/signature');
litecore.TXSignature = require('litecore-lib/lib/transaction/signature');

const LitecoreTransaction = require('./litecoretransaction');

function LitecoinTransaction(options) {
    if(!(this instanceof LitecoinTransaction))
        return new LitecoinTransaction(options);

    // library-dependent types
    this.PublicKey = litecore.PublicKey;
    this.PrivateKey = litecore.PrivateKey;
    this.Hash = litecore.crypto.Hash;
    this.BN = litecore.crypto.BN;
    this.Transaction = litecore.Transaction;
    this.BufferUtil = litecore.BufferUtil;
    this.Signature = litecore.Signature;
    this.TXSignature = litecore.TXSignature;

    this.network = LitecoinTransaction.Testnet;

    this.tx = new this.Transaction();

    if(options) {
        this.fromOptions(options);
    }
}

LitecoinTransaction.prototype = Object.create(LitecoinTransaction.prototype);

LitecoinTransaction.fromJSON = function fromJSON(json) {
    return new LitecoinTransaction().fromJSON(json);
};

LitecoinTransaction.fromOptions = function fromOptions(options) {
    return new LitecoinTransaction().fromOptions(options);
};

LitecoinTransaction.prototype.defaultSigtype = function () {
    return this.Signature.SIGHASH_ALL;
};

LitecoinTransaction.prototype.prepare = async function prepare(options) {
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

module.exports = LitecoinTransaction;