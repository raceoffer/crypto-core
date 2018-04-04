const assert = require('assert');
const Utils = require('../utils');

const litecore = require('litecore-lib');
litecore.BufferUtil = require('litecore-lib/lib/util/buffer');
litecore.Signature = require('litecore-lib/lib/crypto/signature');
litecore.TXSignature = require('litecore-lib/lib/transaction/signature');

const BitcoreTransaction = require('./bitcoretransaction');

function LitecoinTransaction(options) {
    if(!(this instanceof LitecoinTransaction))
        return new LitecoinTransaction(options);

    // library-dependent types
    this.PublicKey = litecore.PublicKey;
    this.PrivateKey = litecore.PrivateKey;
    this.Hash = litecore.crypto.Hash;
    this.BN = litecore.crypto.BN;
    this.Point = litecore.crypto.Point;
    this.Transaction = litecore.Transaction;
    this.BufferUtil = litecore.BufferUtil;
    this.Signature = litecore.Signature;
    this.TXSignature = litecore.TXSignature;

    this.network = BitcoreTransaction.Testnet;

    this.tx = new this.Transaction();

    if(options) {
        this.fromOptions(options);
    }
}

LitecoinTransaction.prototype = Object.create(BitcoreTransaction.prototype);

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

    const publicKey = new this.PublicKey(options.wallet.getPublicKey(), { network: this.networkName(this.network) });

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