const _ = require('lodash');

const ec = require('elliptic').ec('secp256k1');
const BN = require('bn.js');
const jspaillier = require('jspaillier');
const BigInteger = require("jsbn").BigInteger;
const Signature = require('elliptic/lib/elliptic/ec/signature');

const BitcoinTransactionSignature = require('bitcore-lib/lib/transaction/signature');
const BitcoinCashTransactionSignature = require('bitcoincashjs/src/transaction/signature');
const LitecoinTransactionSignature = require('litecore-lib/lib/transaction/signature');

const CompoundKey = require('./compoundkey');
const PaillierProver = require('./paillierprover');
const PaillierVerifier = require('./paillierverifier');
const PedersenScheme = require('./pedersenscheme');
const BitcoinTransaction = require('./bitcore/bitcointransaction');
const BitcoinCashTransaction = require('./bitcore/bitcoincashtransaction');
const LitecoinTransaction = require('./bitcore/litecointransaction');
const EthereumTransaction = require('./ethereum/ethereumtransaction');
const Signer = require('./signer');

function PaillierPrivateKey(lambda, pubkey, x) {
  this.lambda = lambda;
  this.pubkey = pubkey;
  this.x = x;
}

PaillierPrivateKey.prototype = jspaillier.privateKey.prototype;
PaillierPrivateKey.prototype.constructor = PaillierPrivateKey;

function PaillierPublicKey(bits, n, n2, np1, rncache) {
  this.bits = bits;
  this.n = n;
  this.n2 = n2;
  this.np1 = np1;
  this.rncache = rncache;
}

PaillierPublicKey.prototype = jspaillier.publicKey.prototype;
PaillierPublicKey.prototype.constructor = PaillierPublicKey;

function Marshal() {}

Marshal.wrap = function (data, context) {
  // 'Safe' types
  if ( _.isUndefined(data)
    || _.isNull(data)
    || _.isString(data)
    || _.isNumber(data)
    || _.isBoolean(data)
  ) {
    return data;
  }

  if (Buffer.isBuffer(data)) {
    return {
      type: 'Buffer',
      value: data.toString('hex')
    };
  }

  if (data.constructor && data.constructor.name === 'KeyPair') {
    return {
      type: 'KeyPair',
      priv: data.priv ? Marshal.wrap(data.getPrivate(), 'KeyPair') : null,
      pub: data.pub ? Marshal.wrap(data.getPublic(), 'KeyPair') : null
    };
  }

  if (data.constructor && data.constructor.name === 'BN') {
    return {
      type: 'BN',
      value: data.toString(16)
    };
  }

  if (data.constructor && data.constructor.name === 'Point') {
    return {
      type: 'Point',
      value: data.toJSON()
    };
  }

  if (data.constructor && data.constructor.name === 'BigInteger') {
    return {
      type: 'BigInteger',
      value: data.toString(16)
    };
  }

  if (data.constructor && data.constructor.name === 'CompoundKey') {
    return {
      type: 'CompoundKey',
      localPrivateKey: Marshal.wrap(data.localPrivateKey, 'CompoundKey'),
      remotePublicKey: Marshal.wrap(data.remotePublicKey, 'CompoundKey'),
      compoundPublicKey: Marshal.wrap(data.compoundPublicKey, 'CompoundKey'),
      localPaillierPublicKey: Marshal.wrap(data.localPaillierPublicKey, 'CompoundKey'),
      localPaillierPrivateKey: Marshal.wrap(data.localPaillierPrivateKey, 'CompoundKey'),
      remotePrivateCiphertext: Marshal.wrap(data.remotePrivateCiphertext, 'CompoundKey'),
      remotePaillierPublicKey: Marshal.wrap(data.remotePaillierPublicKey, 'CompoundKey')
    };
  }

  if (data.constructor && data.constructor.name === 'PaillierProver') {
    return {
      type: 'PaillierProver',
      pk: Marshal.wrap(data.pk, 'PaillierProver'),
      sk: Marshal.wrap(data.sk, 'PaillierProver'),
      x: Marshal.wrap(data.x, 'PaillierProver'),
      pedersenScheme: Marshal.wrap(data.pedersenScheme, 'PaillierProver'),
      remoteParams: Marshal.wrap(data.remoteParams, 'PaillierProver'),
      iCommitment: Marshal.wrap(data.iCommitment, 'PaillierProver'),
      iDecommitment: Marshal.wrap(data.iDecommitment, 'PaillierProver'),
      sCommitment: Marshal.wrap(data.sCommitment, 'PaillierProver'),
      aDecommitment: Marshal.wrap(data.aDecommitment, 'PaillierProver'),
      alpha: Marshal.wrap(data.alpha, 'PaillierProver')
    };
  }

  if (data.constructor && data.constructor.name === 'PaillierVerifier') {
    return {
      type: 'PaillierVerifier',
      pk: Marshal.wrap(data.pk, 'PaillierVerifier'),
      c: Marshal.wrap(data.c, 'PaillierVerifier'),
      Q: Marshal.wrap(data.Q, 'PaillierVerifier'),
      a: Marshal.wrap(data.a, 'PaillierVerifier'),
      b: Marshal.wrap(data.b, 'PaillierVerifier'),
      pedersenScheme: Marshal.wrap(data.pedersenScheme, 'PaillierVerifier'),
      aCommitment: Marshal.wrap(data.aCommitment, 'PaillierVerifier'),
      sDecommitment: Marshal.wrap(data.sDecommitment, 'PaillierVerifier'),
      remoteParams: Marshal.wrap(data.remoteParams, 'PaillierVerifier'),
    };
  }

  if (data.constructor && data.constructor.name === 'PedersenScheme') {
    return {
      type: 'PedersenScheme',
      a: Marshal.wrap(data.a, 'PedersenScheme'),
      H: Marshal.wrap(data.H, 'PedersenScheme')
    };
  }

  if (data.constructor && data.constructor.name === 'Signer') {
    return {
      type: 'Signer',
      compoundKey: Marshal.wrap(data.compoundKey, 'Signer'),
      message: Marshal.wrap(data.message, 'Signer'),
      k: Marshal.wrap(data.k, 'Signer'),
      R: Marshal.wrap(data.R, 'Signer'),
      r: Marshal.wrap(data.r, 'Signer'),
      remoteParams: Marshal.wrap(data.remoteParams, 'Signer'),
      remoteCommitment: Marshal.wrap(data.remoteCommitment, 'Signer'),
      localDecommitment: Marshal.wrap(data.localDecommitment, 'Signer'),
      pedersenScheme: Marshal.wrap(data.pedersenScheme, 'Signer')
    };
  }

  if (data.constructor && data.constructor.name === 'Signature') {
    return {
      type: 'Signature',
      r: Marshal.wrap(data.r, 'Signature'),
      s: Marshal.wrap(data.s, 'Signature'),
      recoveryParam: Marshal.wrap(data.recoveryParam, 'Signature')
    };
  }

  if (data.constructor && data.constructor.name === 'TransactionSignature' && context === 'BitcoinTransaction') {
    return {
      type: 'BitcoinTransactionSignature',
      value: data.toObject()
    };
  }

  if (data.constructor && data.constructor.name === 'TransactionSignature' && context === 'BitcoinCashTransaction') {
    return {
      type: 'BitcoinCashTransactionSignature',
      value: data.toObject()
    };
  }

  if (data.constructor && data.constructor.name === 'TransactionSignature' && context === 'LitecoinTransaction') {
    return {
      type: 'LitecoinTransactionSignature',
      value: data.toObject()
    };
  }

  if (data.constructor && data.constructor.name === 'BitcoinTransaction') {
    return {
      type: 'BitcoinTransaction',
      network: Marshal.wrap(data.network, 'BitcoinTransaction'),
      tx: data.tx.toObject(),
      signers: Marshal.wrap(data.signers, 'BitcoinTransaction')
    };
  }

  if (data.constructor && data.constructor.name === 'BitcoinCashTransaction') {
    return {
      type: 'BitcoinCashTransaction',
      network: Marshal.wrap(data.network, 'BitcoinCashTransaction'),
      tx: data.tx.toObject(),
      signers: Marshal.wrap(data.signers, 'BitcoinCashTransaction')
    };
  }

  if (data.constructor && data.constructor.name === 'LitecoinTransaction') {
    return {
      type: 'LitecoinTransaction',
      network: Marshal.wrap(data.network, 'LitecoinTransaction'),
      tx: data.tx.toObject(),
      signers: Marshal.wrap(data.signers, 'LitecoinTransaction')
    };
  }

  if (data.constructor && data.constructor.name === 'EthereumTransaction') {
    return {
      type: 'EthereumTransaction',
      tx: Marshal.wrap(data.tx, 'EthereumTransaction'),
      rlpEncoded: Marshal.wrap(data.rlpEncoded, 'EthereumTransaction'),
      hash: Marshal.wrap(data.hash, 'EthereumTransaction'),
      signedTransaction: Marshal.wrap(data.signedTransaction, 'EthereumTransaction'),
      signer: Marshal.wrap(data.signer, 'EthereumTransaction')
    };
  }

  if (_.isObject(data) && _.difference(['bits', 'n', 'n2', 'np1', 'rncache'], _.keys(data)).length === 0) {
    return {
      type: 'PaillierPublicKey',
      bits: Marshal.wrap(data.bits, 'PaillierPublicKey'),
      n: Marshal.wrap(data.n, 'PaillierPublicKey'),
      n2: Marshal.wrap(data.n2, 'PaillierPublicKey'),
      np1: Marshal.wrap(data.np1, 'PaillierPublicKey'),
      rncache: Marshal.wrap(data.rncache, 'PaillierPublicKey')
    };
  }

  if (_.isObject(data) && _.difference(['lambda', 'pubkey', 'x'], _.keys(data)).length === 0) {
    return {
      type: 'PaillierPrivateKey',
      lambda: Marshal.wrap(data.lambda, 'PaillierPrivateKey'),
      pubkey: Marshal.wrap(data.pubkey, 'PaillierPrivateKey'),
      x: Marshal.wrap(data.x, 'PaillierPrivateKey')
    };
  }

  if (_.isArray(data)) {
    return _.map(data, arg => Marshal.wrap(arg, context));
  }

  if (_.isObject(data)) {
    return _.mapValues(data, arg => Marshal.wrap(arg, context));
  }

  return data;
};

Marshal.unwrap = function(data) {
  // 'Safe' types
  if ( _.isUndefined(data)
    || _.isNull(data)
    || _.isString(data)
    || _.isNumber(data)
    || _.isBoolean(data)
  ) {
    return data;
  }

  if (_.isObject(data) && data.type === 'Buffer') {
    return Buffer.from(data.value, 'hex');
  }

  if (_.isObject(data) && data.type === 'KeyPair') {
    if (data.priv) {
      return ec.keyFromPrivate(Marshal.unwrap(data.priv))
    } else if (data.pub) {
      return ec.keyFromPublic(Marshal.unwrap(data.pub, 'hex'));
    } else {
      return null;
    }
  }

  if (_.isObject(data) && data.type === 'BN') {
    return new BN(data.value, 16);
  }

  if (_.isObject(data) && data.type === 'Point') {
    return ec.curve.pointFromJSON(data.value, true);
  }

  if (_.isObject(data) && data.type === 'BigInteger') {
    return new BigInteger(data.value, 16);
  }

  if (_.isObject(data) && data.type === 'CompoundKey') {
    const compoundKey = new CompoundKey();
    compoundKey.localPrivateKey = Marshal.unwrap(data.localPrivateKey);
    compoundKey.remotePublicKey = Marshal.unwrap(data.remotePublicKey);
    compoundKey.compoundPublicKey = Marshal.unwrap(data.compoundPublicKey);
    compoundKey.localPaillierPublicKey = Marshal.unwrap(data.localPaillierPublicKey);
    compoundKey.localPaillierPrivateKey = Marshal.unwrap(data.localPaillierPrivateKey);
    compoundKey.remotePrivateCiphertext = Marshal.unwrap(data.remotePrivateCiphertext);
    compoundKey.remotePaillierPublicKey = Marshal.unwrap(data.remotePaillierPublicKey);
    return compoundKey;
  }

  if (_.isObject(data) && data.type === 'PaillierProver') {
    const prover = new PaillierProver();
    prover.pk = Marshal.unwrap(data.pk);
    prover.sk = Marshal.unwrap(data.sk);
    prover.x = Marshal.unwrap(data.x);
    prover.pedersenScheme = Marshal.unwrap(data.pedersenScheme);
    prover.remoteParams = Marshal.unwrap(data.remoteParams);
    prover.iCommitment = Marshal.unwrap(data.iCommitment);
    prover.iDecommitment = Marshal.unwrap(data.iDecommitment);
    prover.sCommitment = Marshal.unwrap(data.sCommitment);
    prover.aDecommitment = Marshal.unwrap(data.aDecommitment);
    prover.alpha = Marshal.unwrap(data.alpha);
    return prover;
  }

  if (_.isObject(data) && data.type === 'PaillierVerifier') {
    const verifier = new PaillierVerifier();
    verifier.pk = Marshal.unwrap(data.pk);
    verifier.c = Marshal.unwrap(data.c);
    verifier.Q = Marshal.unwrap(data.Q);
    verifier.a = Marshal.unwrap(data.a);
    verifier.b = Marshal.unwrap(data.b);
    verifier.pedersenScheme = Marshal.unwrap(data.pedersenScheme);
    verifier.aCommitment = Marshal.unwrap(data.aCommitment);
    verifier.sDecommitment = Marshal.unwrap(data.sDecommitment);
    verifier.remoteParams = Marshal.unwrap(data.remoteParams);
    return verifier;
  }

  if (_.isObject(data) && data.type === 'PedersenScheme') {
    const pedersenScheme = new PedersenScheme();
    pedersenScheme.a = Marshal.unwrap(data.a);
    pedersenScheme.H = Marshal.unwrap(data.H);
    return pedersenScheme;
  }

  if (_.isObject(data) && data.type === 'Signer') {
    const signer = new Signer();
    signer.compoundKey = Marshal.unwrap(data.compoundKey);
    signer.message = Marshal.unwrap(data.message);
    signer.k = Marshal.unwrap(data.k);
    signer.R = Marshal.unwrap(data.R);
    signer.r = Marshal.unwrap(data.r);
    signer.remoteParams = Marshal.unwrap(data.remoteParams);
    signer.remoteCommitment = Marshal.unwrap(data.remoteCommitment);
    signer.localDecommitment = Marshal.unwrap(data.localDecommitment);
    signer.pedersenScheme = Marshal.unwrap(data.pedersenScheme);
    return signer;
  }

  if (_.isObject(data) && data.type === 'Signature') {
    return new Signature({ r: Marshal.unwrap(data.r), s: Marshal.unwrap(data.s), recoveryParam: Marshal.unwrap(data.recoveryParam) });
  }

  if (_.isObject(data) && data.type === 'BitcoinTransactionSignature') {
    return new BitcoinTransactionSignature(data.value);
  }

  if (_.isObject(data) && data.type === 'BitcoinCashTransactionSignature') {
    return new BitcoinCashTransactionSignature(data.value);
  }

  if (_.isObject(data) && data.type === 'LitecoinTransactionSignature') {
    return new LitecoinTransactionSignature(data.value);
  }

  if (_.isObject(data) && data.type === 'BitcoinTransaction') {
    const bitcoinTransaction = new BitcoinTransaction();
    bitcoinTransaction.network = Marshal.unwrap(data.network);
    bitcoinTransaction.signers = Marshal.unwrap(data.signers);
    bitcoinTransaction.tx = new bitcoinTransaction.Transaction(data.tx);
    return bitcoinTransaction;
  }

  if (_.isObject(data) && data.type === 'BitcoinCashTransaction') {
    const bitcoinCashTransaction = new BitcoinCashTransaction();
    bitcoinCashTransaction.network = Marshal.unwrap(data.network);
    bitcoinCashTransaction.signers = Marshal.unwrap(data.signers);
    bitcoinCashTransaction.tx = new bitcoinCashTransaction.Transaction(data.tx);
    return bitcoinCashTransaction;
  }

  if (_.isObject(data) && data.type === 'LitecoinTransaction') {
    const litecoinTransaction = new LitecoinTransaction();
    litecoinTransaction.network = Marshal.unwrap(data.network);
    litecoinTransaction.signers = Marshal.unwrap(data.signers);
    litecoinTransaction.tx = new litecoinTransaction.Transaction(data.tx);
    return litecoinTransaction;
  }

  if (_.isObject(data) && data.type === 'EthereumTransaction') {
    const ethereumTransaction = new EthereumTransaction();
    ethereumTransaction.tx = Marshal.unwrap(data.tx);
    ethereumTransaction.rlpEncoded = Marshal.unwrap(data.rlpEncoded);
    ethereumTransaction.hash = Marshal.unwrap(data.hash);
    ethereumTransaction.signedTransaction = Marshal.unwrap(data.signedTransaction);
    ethereumTransaction.signer = Marshal.unwrap(data.signer);
    return ethereumTransaction;
  }

  if (_.isObject(data) && data.type === 'PaillierPublicKey') {
    return new PaillierPublicKey(
      Marshal.unwrap(data.bits),
      Marshal.unwrap(data.n),
      Marshal.unwrap(data.n2),
      Marshal.unwrap(data.np1),
      Marshal.unwrap(data.rncache));
  }

  if (_.isObject(data) && data.type === 'PaillierPrivateKey') {
    return new PaillierPrivateKey(
      Marshal.unwrap(data.lambda),
      Marshal.unwrap(data.pubkey),
      Marshal.unwrap(data.x));
  }

  if (_.isArray(data)) {
    return _.map(data, Marshal.unwrap);
  }

  if (_.isObject(data)) {
    return _.mapValues(data, Marshal.unwrap);
  }

  return data;
};

module.exports = Marshal;
