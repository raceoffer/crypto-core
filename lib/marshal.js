'use strict';

import isUndefined from 'lodash/isUndefined';
import isNull from 'lodash/isNull';
import isString from 'lodash/isString';
import isNumber from 'lodash/isNumber';
import isBoolean from 'lodash/isBoolean';
import isArray from 'lodash/isArray';
import isObject from 'lodash/isObject';
import map from 'lodash/map';
import mapValues from 'lodash/mapValues';

const ec = require('elliptic').ec('secp256k1');
const BN = require('bn.js');
const KeyPair = require('elliptic/lib/elliptic/ec/key');
const jspaillier = require('jspaillier');
const BigInteger = require("jsbn").BigInteger;
const Signature = require('elliptic/lib/elliptic/ec/signature');

const BitcoinTransactionSignature = require('bitcore-lib/lib/transaction/signature');
const BitcoinCashTransactionSignature = require('bitcoincashjs/src/transaction/signature');
const LitecoinTransactionSignature = require('litecore-lib/lib/transaction/signature');

import { CompoundKey } from './primitives/compoundkey';
import { PaillierProver } from './primitives/paillierprover';
import { PaillierVerifier } from './primitives/paillierverifier';
import { PedersenScheme } from './primitives/pedersenscheme';
import { BitcoinTransaction } from './transaction/bitcore/bitcointransaction';
import { BitcoinCashTransaction } from './transaction/bitcore/bitcoincashtransaction';
import { LitecoinTransaction } from './transaction/bitcore/litecointransaction';
import { EthereumTransaction } from './transaction/ethereum/ethereumtransaction';
import { Signer } from './primitives/signer';

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

export function wrap(data) {
  // 'Safe' types
  if ( isUndefined(data)
    || isNull(data)
    || isString(data)
    || isNumber(data)
    || isBoolean(data)
  ) {
    return data;
  }

  if (Buffer.isBuffer(data)) {
    return {
      type: 'Buffer',
      value: data.toString('hex')
    };
  }

  if (data instanceof KeyPair) {
    return {
      type: 'KeyPair',
      priv: data.priv ? wrap(data.getPrivate()) : null,
      pub: data.pub ? wrap(data.getPublic()) : null
    };
  }

  if (BN.isBN(data)) {
    return {
      type: 'BN',
      value: data.toString(16)
    };
  }

  if (data instanceof BigInteger) {
    return {
      type: 'BigInteger',
      value: data.toString(16)
    };
  }

  if (data instanceof CompoundKey) {
    return {
      type: 'CompoundKey',
      localPrivateKey: wrap(data.localPrivateKey),
      remotePublicKey: wrap(data.remotePublicKey),
      compoundPublicKey: wrap(data.compoundPublicKey),
      localPaillierPublicKey: wrap(data.localPaillierPublicKey),
      localPaillierPrivateKey: wrap(data.localPaillierPrivateKey),
      remotePrivateCiphertext: wrap(data.remotePrivateCiphertext),
      remotePaillierPublicKey: wrap(data.remotePaillierPublicKey)
    };
  }

  if (data instanceof PaillierProver) {
    return {
      type: 'PaillierProver',
      pk: wrap(data.pk),
      sk: wrap(data.sk),
      x: wrap(data.x),
      pedersenScheme: wrap(data.pedersenScheme),
      remoteParams: wrap(data.remoteParams),
      iCommitment: wrap(data.iCommitment),
      iDecommitment: wrap(data.iDecommitment),
      sCommitment: wrap(data.sCommitment),
      aDecommitment: wrap(data.aDecommitment),
      alpha: wrap(data.alpha)
    };
  }

  if (data instanceof PaillierVerifier) {
    return {
      type: 'PaillierVerifier',
      pk: wrap(data.pk),
      c: wrap(data.c),
      Q: wrap(data.Q),
      a: wrap(data.a),
      b: wrap(data.b),
      pedersenScheme: wrap(data.pedersenScheme),
      aCommitment: wrap(data.aCommitment),
      sDecommitment: wrap(data.sDecommitment),
      remoteParams: wrap(data.remoteParams),
    };
  }

  if (data instanceof PedersenScheme) {
    return {
      type: 'PedersenScheme',
      a: wrap(data.a),
      H: wrap(data.H)
    };
  }

  if (data instanceof Signer) {
    return {
      type: 'Signer',
      compoundKey: wrap(data.compoundKey),
      message: wrap(data.message),
      k: wrap(data.k),
      R: wrap(data.R),
      r:wrap(data.r),
      remoteParams: wrap(data.remoteParams),
      remoteCommitment: wrap(data.remoteCommitment),
      localDecommitment: wrap(data.localDecommitment),
      pedersenScheme: wrap(data.pedersenScheme)
    };
  }

  if (data instanceof Signature) {
    return {
      type: 'Signature',
      r: wrap(data.r),
      s: wrap(data.s),
      recoveryParam: wrap(data.recoveryParam)
    };
  }

  if (data instanceof BitcoinTransactionSignature) {
    return {
      type: 'BitcoinTransactionSignature',
      value: data.toObject()
    };
  }

  if (data instanceof BitcoinCashTransactionSignature) {
    return {
      type: 'BitcoinCashTransactionSignature',
      value: data.toObject()
    };
  }

  if (data instanceof LitecoinTransactionSignature) {
    return {
      type: 'LitecoinTransactionSignature',
      value: data.toObject()
    };
  }

  if (data instanceof BitcoinTransaction) {
    return {
      type: 'BitcoinTransaction',
      network: wrap(data.network),
      tx: data.tx ? data.tx.toObject() : null,
      signers: wrap(data.signers)
    };
  }

  if (data instanceof BitcoinCashTransaction) {
    return {
      type: 'BitcoinCashTransaction',
      network: wrap(data.network),
      tx: data.tx ? data.tx.toObject() : null,
      signers: wrap(data.signers)
    };
  }

  if (data instanceof LitecoinTransaction) {
    return {
      type: 'LitecoinTransaction',
      network: wrap(data.network),
      tx: data.tx ? data.tx.toObject() : null,
      signers: wrap(data.signers)
    };
  }

  if (data instanceof EthereumTransaction) {
    return {
      type: 'EthereumTransaction',
      tx: wrap(data.tx),
      rlpEncoded: wrap(data.rlpEncoded),
      hash: wrap(data.hash),
      signedTransaction: wrap(data.signedTransaction),
      signer: wrap(data.signer)
    };
  }

  if (data instanceof jspaillier.publicKey) {
    return {
      type: 'PaillierPublicKey',
      bits: wrap(data.bits),
      n: wrap(data.n),
      n2: wrap(data.n2),
      np1: wrap(data.np1),
      rncache: wrap(data.rncache)
    };
  }

  if (data instanceof jspaillier.privateKey) {
    return {
      type: 'PaillierPrivateKey',
      lambda: wrap(data.lambda),
      pubkey: wrap(data.pubkey),
      x: wrap(data.x)
    };
  }

  if (data instanceof ec.curve.point(new BN(), new BN(), false).constructor) {
    return {
      type: 'Point',
      value: data.toJSON()
    };
  }

  if (isArray(data)) {
    return map(data, arg => wrap(arg));
  }

  if (isObject(data)) {
    return mapValues(data, arg => wrap(arg));
  }

  return data;
};

export function unwrap(data) {
  // 'Safe' types
  if ( isUndefined(data)
    || isNull(data)
    || isString(data)
    || isNumber(data)
    || isBoolean(data)
  ) {
    return data;
  }

  if (isObject(data) && data.type === 'Buffer') {
    return Buffer.from(data.value, 'hex');
  }

  if (isObject(data) && data.type === 'KeyPair') {
    if (data.priv) {
      return ec.keyFromPrivate(unwrap(data.priv));
    } else if (data.pub) {
      return ec.keyFromPublic(unwrap(data.pub, 'hex'));
    } else {
      return null;
    }
  }

  if (isObject(data) && data.type === 'BN') {
    return new BN(data.value, 16);
  }

  if (isObject(data) && data.type === 'Point') {
    return ec.curve.pointFromJSON(data.value, true);
  }

  if (isObject(data) && data.type === 'BigInteger') {
    return new BigInteger(data.value, 16);
  }

  if (isObject(data) && data.type === 'CompoundKey') {
    const compoundKey = new CompoundKey();
    compoundKey.localPrivateKey = unwrap(data.localPrivateKey);
    compoundKey.remotePublicKey = unwrap(data.remotePublicKey);
    compoundKey.compoundPublicKey = unwrap(data.compoundPublicKey);
    compoundKey.localPaillierPublicKey = unwrap(data.localPaillierPublicKey);
    compoundKey.localPaillierPrivateKey = unwrap(data.localPaillierPrivateKey);
    compoundKey.remotePrivateCiphertext = unwrap(data.remotePrivateCiphertext);
    compoundKey.remotePaillierPublicKey = unwrap(data.remotePaillierPublicKey);
    return compoundKey;
  }

  if (isObject(data) && data.type === 'PaillierProver') {
    const prover = new PaillierProver();
    prover.pk = unwrap(data.pk);
    prover.sk = unwrap(data.sk);
    prover.x = unwrap(data.x);
    prover.pedersenScheme = unwrap(data.pedersenScheme);
    prover.remoteParams = unwrap(data.remoteParams);
    prover.iCommitment = unwrap(data.iCommitment);
    prover.iDecommitment = unwrap(data.iDecommitment);
    prover.sCommitment = unwrap(data.sCommitment);
    prover.aDecommitment = unwrap(data.aDecommitment);
    prover.alpha = unwrap(data.alpha);
    return prover;
  }

  if (isObject(data) && data.type === 'PaillierVerifier') {
    const verifier = new PaillierVerifier();
    verifier.pk = unwrap(data.pk);
    verifier.c = unwrap(data.c);
    verifier.Q = unwrap(data.Q);
    verifier.a = unwrap(data.a);
    verifier.b = unwrap(data.b);
    verifier.pedersenScheme = unwrap(data.pedersenScheme);
    verifier.aCommitment = unwrap(data.aCommitment);
    verifier.sDecommitment = unwrap(data.sDecommitment);
    verifier.remoteParams = unwrap(data.remoteParams);
    return verifier;
  }

  if (isObject(data) && data.type === 'PedersenScheme') {
    const pedersenScheme = new PedersenScheme();
    pedersenScheme.a = unwrap(data.a);
    pedersenScheme.H = unwrap(data.H);
    return pedersenScheme;
  }

  if (isObject(data) && data.type === 'Signer') {
    const signer = new Signer();
    signer.compoundKey = unwrap(data.compoundKey);
    signer.message = unwrap(data.message);
    signer.k = unwrap(data.k);
    signer.R = unwrap(data.R);
    signer.r = unwrap(data.r);
    signer.remoteParams = unwrap(data.remoteParams);
    signer.remoteCommitment = unwrap(data.remoteCommitment);
    signer.localDecommitment = unwrap(data.localDecommitment);
    signer.pedersenScheme = unwrap(data.pedersenScheme);
    return signer;
  }

  if (isObject(data) && data.type === 'Signature') {
    return new Signature({ r: unwrap(data.r), s: unwrap(data.s), recoveryParam: unwrap(data.recoveryParam) });
  }

  if (isObject(data) && data.type === 'BitcoinTransactionSignature') {
    return new BitcoinTransactionSignature(data.value);
  }

  if (isObject(data) && data.type === 'BitcoinCashTransactionSignature') {
    return new BitcoinCashTransactionSignature(data.value);
  }

  if (isObject(data) && data.type === 'LitecoinTransactionSignature') {
    return new LitecoinTransactionSignature(data.value);
  }

  if (isObject(data) && data.type === 'BitcoinTransaction') {
    const bitcoinTransaction = new BitcoinTransaction();
    bitcoinTransaction.network = unwrap(data.network);
    bitcoinTransaction.signers = unwrap(data.signers);
    bitcoinTransaction.tx = data.tx ? new bitcoinTransaction.Transaction(data.tx) : null;
    return bitcoinTransaction;
  }

  if (isObject(data) && data.type === 'BitcoinCashTransaction') {
    const bitcoinCashTransaction = new BitcoinCashTransaction();
    bitcoinCashTransaction.network = unwrap(data.network);
    bitcoinCashTransaction.signers = unwrap(data.signers);
    bitcoinCashTransaction.tx = data.tx ? new bitcoinCashTransaction.Transaction(data.tx) : null;
    return bitcoinCashTransaction;
  }

  if (isObject(data) && data.type === 'LitecoinTransaction') {
    const litecoinTransaction = new LitecoinTransaction();
    litecoinTransaction.network = unwrap(data.network);
    litecoinTransaction.signers = unwrap(data.signers);
    litecoinTransaction.tx = data.tx ? new litecoinTransaction.Transaction(data.tx) : null;
    return litecoinTransaction;
  }

  if (isObject(data) && data.type === 'EthereumTransaction') {
    const ethereumTransaction = new EthereumTransaction();
    ethereumTransaction.tx = unwrap(data.tx);
    ethereumTransaction.rlpEncoded = unwrap(data.rlpEncoded);
    ethereumTransaction.hash = unwrap(data.hash);
    ethereumTransaction.signedTransaction = unwrap(data.signedTransaction);
    ethereumTransaction.signer = unwrap(data.signer);
    return ethereumTransaction;
  }

  if (isObject(data) && data.type === 'PaillierPublicKey') {
    return new PaillierPublicKey(
      unwrap(data.bits),
      unwrap(data.n),
      unwrap(data.n2),
      unwrap(data.np1),
      unwrap(data.rncache));
  }

  if (isObject(data) && data.type === 'PaillierPrivateKey') {
    return new PaillierPrivateKey(
      unwrap(data.lambda),
      unwrap(data.pubkey),
      unwrap(data.x));
  }

  if (isArray(data)) {
    return map(data, unwrap);
  }

  if (isObject(data)) {
    return mapValues(data, unwrap);
  }

  return data;
};
