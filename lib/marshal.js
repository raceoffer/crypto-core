const _ = require('lodash');

const ec = require('elliptic').ec('secp256k1');
const BN = require('bn.js');
const jspaillier = require('jspaillier');
const BigInteger = require("jsbn").BigInteger;
const Signature = require('elliptic/lib/elliptic/ec/signature');

const TransactionSignature = require('bitcore-lib/lib/transaction/signature');

const CompoundKey = require('./compoundkey');
const PaillierProver = require('./paillierprover');
const PaillierVerifier = require('./paillierverifier');
const PedersenScheme = require('./pedersenscheme');
const BitcoinTransaction = require('./bitcore/bitcointransaction');
const BitcoinCashTransaction = require('./bitcore/bitcoincashtransaction');
const EthereumTransaction = require('./ethereum/ethereumtransaction');
const Signer = require('./signer');

function Marshal() {}

Marshal.wrap = function (data) {
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
      priv: data.priv ? Marshal.wrap(data.getPrivate()) : null,
      pub: data.pub ? Marshal.wrap(data.getPublic()) : null
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
      localPrivateKey: Marshal.wrap(data.localPrivateKey),
      remotePublicKey: Marshal.wrap(data.remotePublicKey),
      compoundPublicKey: Marshal.wrap(data.compoundPublicKey),
      localPaillierPublicKey: Marshal.wrap(data.localPaillierPublicKey),
      localPaillierPrivateKey: Marshal.wrap(data.localPaillierPrivateKey),
      remotePrivateCiphertext: Marshal.wrap(data.remotePrivateCiphertext),
      remotePaillierPublicKey: Marshal.wrap(data.remotePaillierPublicKey)
    };
  }

  if (data.constructor && data.constructor.name === 'PaillierProver') {
    return {
      type: 'PaillierProver',
      pk: Marshal.wrap(data.pk),
      sk: Marshal.wrap(data.sk),
      x: Marshal.wrap(data.x),
      pedersenScheme: Marshal.wrap(data.pedersenScheme),
      remoteParams: Marshal.wrap(data.remoteParams),
      iCommitment: Marshal.wrap(data.iCommitment),
      iDecommitment: Marshal.wrap(data.iDecommitment),
      sCommitment: Marshal.wrap(data.sCommitment),
      aDecommitment: Marshal.wrap(data.aDecommitment),
      alpha: Marshal.wrap(data.alpha)
    };
  }

  if (data.constructor && data.constructor.name === 'PaillierVerifier') {
    return {
      type: 'PaillierVerifier',
      pk: Marshal.wrap(data.pk),
      c: Marshal.wrap(data.c),
      Q: Marshal.wrap(data.Q),
      a: Marshal.wrap(data.a),
      b: Marshal.wrap(data.b),
      pedersenScheme: Marshal.wrap(data.pedersenScheme),
      aCommitment: Marshal.wrap(data.aCommitment),
      sDecommitment: Marshal.wrap(data.sDecommitment),
      remoteParams: Marshal.wrap(data.remoteParams),
    };
  }

  if (data.constructor && data.constructor.name === 'PedersenScheme') {
    return {
      type: 'PedersenScheme',
      a: Marshal.wrap(data.a),
      H: Marshal.wrap(data.H)
    };
  }

  if (data.constructor && data.constructor.name === 'Signer') {
    return {
      type: 'Signer',
      compoundKey: Marshal.wrap(data.compoundKey),
      message: Marshal.wrap(data.message),
      k: Marshal.wrap(data.k),
      R: Marshal.wrap(data.R),
      r: Marshal.wrap(data.r),
      remoteParams: Marshal.wrap(data.remoteParams),
      remoteCommitment: Marshal.wrap(data.remoteCommitment),
      localDecommitment: Marshal.wrap(data.localDecommitment),
      pedersenScheme: Marshal.wrap(data.pedersenScheme)
    };
  }

  if (data.constructor && data.constructor.name === 'Signature') {
    return {
      type: 'Signature',
      r: Marshal.wrap(data.r),
      s: Marshal.wrap(data.s),
      recoveryParam: Marshal.wrap(data.recoveryParam)
    };
  }

  if (data.constructor && data.constructor.name === 'TransactionSignature') {
    return {
      type: 'TransactionSignature',
      value: data.toObject()
    };
  }

  if (data.constructor && data.constructor.name === 'BitcoinTransaction') {
    return {
      type: 'BitcoinTransaction',
      network: Marshal.wrap(data.network),
      tx: data.tx.toObject(),
      signers: Marshal.wrap(data.signers)
    };
  }

  if (data.constructor && data.constructor.name === 'BitcoinCashTransaction') {
    return {
      type: 'BitcoinCashTransaction',
      network: Marshal.wrap(data.network),
      tx: data.tx.toObject(),
      signers: Marshal.wrap(data.signers)
    };
  }

  if (data.constructor && data.constructor.name === 'EthereumTransaction') {
    return {
      type: 'EthereumTransaction',
      tx: Marshal.wrap(data.tx),
      rlpEncoded: Marshal.wrap(data.rlpEncoded),
      hash: Marshal.wrap(data.hash),
      signedTransaction: Marshal.wrap(data.signedTransaction)
    };
  }

  if (_.isObject(data) && _.difference(['bits', 'n', 'n2', 'np1', 'rncache'], _.keys(data)).length === 0) {
    return {
      type: 'PaillierPublicKey',
      bits: data.bits,
      n: Marshal.wrap(data.n)
    };
  }

  if (_.isObject(data) && _.difference(['lambda', 'pubkey', 'x'], _.keys(data)).length === 0) {
    return {
      type: 'PaillierPrivateKey',
      lambda: Marshal.wrap(data.lambda),
      pubkey: Marshal.wrap(data.pubkey)
    };
  }

  if (_.isArray(data)) {
    return _.map(data, Marshal.wrap);
  }

  if (_.isObject(data)) {
    return _.mapValues(data, Marshal.wrap);
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

  if (_.isObject(data) && data.type === 'TransactionSignature') {
    return new TransactionSignature(data.value);
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

  if (_.isObject(data) && data.type === 'EthereumTransaction') {
    const ethereumTransaction = new EthereumTransaction();
    ethereumTransaction.tx = Marshal.unwrap(data.tx);
    ethereumTransaction.rlpEncoded = Marshal.unwrap(data.rlpEncoded);
    ethereumTransaction.hash = Marshal.unwrap(data.hash);
    ethereumTransaction.signedTransaction = Marshal.unwrap(data.signedTransaction);
    return ethereumTransaction;
  }

  if (_.isObject(data) && data.type === 'PaillierPublicKey') {
    return new jspaillier.publicKey(data.bits, Marshal.unwrap(data.n));
  }

  if (_.isObject(data) && data.type === 'PaillierPrivateKey') {
    return new jspaillier.privateKey(Marshal.unwrap(data.lambda), Marshal.unwrap(data.pubkey));
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
