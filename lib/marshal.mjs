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

import elliptic from 'elliptic';
import BN from 'bn.js';
import KeyPairEcdsa from 'elliptic/lib/elliptic/ec/key';
import KeyPairEddsa from 'elliptic/lib/elliptic/eddsa/key';
import jspaillier from 'jspaillier';
import JSBN from "jsbn";
import Signature from 'elliptic/lib/elliptic/ec/signature';
import buffer from 'buffer';

const Buffer = buffer.Buffer;
const ecdsa = elliptic.ec('secp256k1');
const eddsa = elliptic.eddsa('ed25519');
const BigInteger = JSBN.BigInteger;

import BitcoinTransactionSignature from 'bitcore-lib/lib/transaction/signature';
import BitcoinCashTransactionSignature from 'bitcoincashjs/src/transaction/signature';
import LitecoinTransactionSignature from 'litecore-lib/lib/transaction/signature';

import { CompoundKey as CompoundKeyEcdsa } from './primitives/ecdsa/compoundkey';
import { CompoundKey as CompoundKeyEddsa } from './primitives/eddsa/compoundkey';

import { PaillierProver } from './primitives/ecdsa/paillierprover';
import { PaillierVerifier } from './primitives/ecdsa/paillierverifier';
import { BitcoinTransaction } from './transaction/bitcore/bitcointransaction';
import { BitcoinCashTransaction } from './transaction/bitcore/bitcoincashtransaction';
import { LitecoinTransaction } from './transaction/bitcore/litecointransaction';
import { EthereumTransaction } from './transaction/ethereum/ethereumtransaction';
import { NemTransaction } from './transaction/nem/nemtransaction';
import { Signer as SignerEcdsa } from './primitives/ecdsa/signer';
import { Signer as SignerEddsa, PartialSignature } from './primitives/eddsa/signer';
import { SyncSession, SyncData } from "./primitives/eddsa/syncsession";
import { KeyPair } from "./primitives/eddsa/keypair";

import { toJSON, fromJSON } from './convert';
import {
  PedersenCommitment,
  PedersenDecommitment,
  PedersenParameters,
  PedersenScheme
} from "./primitives/pedersenscheme";

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
      value: toJSON(data)
    }
  }

  if (data instanceof CompoundKeyEddsa) {
    return {
      type: 'CompoundKeyEddsa',
      value: toJSON(data)
    };
  }

  if (data instanceof PedersenScheme) {
    return {
      type: 'PedersenScheme',
      value: toJSON(data)
    };
  }

  if (data instanceof PedersenParameters) {
    return {
      type: 'PedersenParameters',
      value: toJSON(data)
    };
  }

  if (data instanceof PedersenCommitment) {
    return {
      type: 'PedersenCommitment',
      value: toJSON(data)
    };
  }

  if (data instanceof PedersenDecommitment) {
    return {
      type: 'PedersenDecommitment',
      value: toJSON(data)
    };
  }

  if (data instanceof SyncSession) {
    return {
      type: 'SyncSession',
      value: toJSON(data)
    }
  }

  if (data instanceof SyncData) {
    return {
      type: 'SyncData',
      value: toJSON(data)
    }
  }

  if (data instanceof SignerEddsa) {
    return {
      type: 'SignerEddsa',
      value: toJSON(data)
    };
  }

  if (data instanceof PartialSignature) {
    return {
      type: 'PartialSignature',
      value: toJSON(data)
    };
  }

  if (data instanceof NemTransaction) {
    return {
      type: 'NemTransaction',
      value: toJSON(data)
    };
  }

  if (data instanceof SignerEcdsa) {
    return {
      type: 'SignerEcdsa',
      compoundKey: wrap(data.compoundKey),
      message: wrap(data.message),
      k: wrap(data.k),
      R: wrap(data.R),
      r: wrap(data.r),
      remoteParams: wrap(data.remoteParams),
      remoteCommitment: wrap(data.remoteCommitment),
      localDecommitment: wrap(data.localDecommitment),
      pedersenScheme: wrap(data.pedersenScheme)
    };
  }

  // if (data instanceof Signature) {
  //   return {
  //     type: 'Signature',
  //     r: wrap(data.r),
  //     s: wrap(data.s),
  //     recoveryParam: wrap(data.recoveryParam)
  //   };
  // }

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
      data: data.data,
      signer: wrap(data.signer)
    };
  }

  // if (data instanceof jspaillier.publicKey) {
  //   return {
  //     type: 'PaillierPublicKey',
  //     bits: wrap(data.bits),
  //     n: wrap(data.n),
  //     n2: wrap(data.n2),
  //     np1: wrap(data.np1),
  //     rncache: wrap(data.rncache)
  //   };
  // }
  //
  // if (data instanceof jspaillier.privateKey) {
  //   return {
  //     type: 'PaillierPrivateKey',
  //     lambda: wrap(data.lambda),
  //     pubkey: wrap(data.pubkey),
  //     x: wrap(data.x)
  //   };
  // }
  //
  // if (data instanceof ecdsa.curve.point(new BN(), new BN(), false).constructor) {
  //   return {
  //     type: 'PointEcdsa',
  //     value: data.toJSON()
  //   };
  // }
  //
  //   if (data instanceof eddsa.curve.point(new BN(), new BN(), new BN()).constructor) {
  //     return {
  //       type: 'PointEddsa',
  //       value: map([ data.x, data.y, data.z ], wrap)
  //     };
  //   }
  //
  // if (isArray(data)) {
  //   return map(data, arg => wrap(arg));
  // }
  //
  // if (isObject(data)) {
  //   return mapValues(data, arg => wrap(arg));
  // }

  // return data;
}

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

  if (isObject(data) && data.type === 'KeyPairEcdsa') {
    if (data.priv) {
      return ecdsa.keyFromPrivate(unwrap(data.priv));
    } else if (data.pub) {
      return ecdsa.keyFromPublic(unwrap(data.pub));
    } else {
      return null;
    }
  }

  if (isObject(data) && data.type === 'KeyPairEddsa') {
    if (data.secret) {
      return eddsa.keyFromSecret(unwrap(data.secret));
    } else if (data.pub) {
      return eddsa.keyFromPublic(unwrap(data.pub));
    } else {
      return null;
    }
  }

  if (isObject(data) && data.type === 'BN') {
    return new BN(data.value, 16);
  }

  if (isObject(data) && data.type === 'PointEcdsa') {
    return ecdsa.curve.pointFromJSON(data.value, true);
  }

  if (isObject(data) && data.type === 'PointEddsa') {
    return eddsa.curve.pointFromJSON(map(data, unwrap));
  }

  if (isObject(data) && data.type === 'BigInteger') {
    return new BigInteger(data.value, 16);
  }

  if (isObject(data) && data.type === 'CompoundKeyEcdsa') {
    const compoundKey = new CompoundKeyEcdsa();
    compoundKey.curve = data.curve;
    compoundKey.ecdsa = elliptic.ec(compoundKey.curve);
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

  if (isObject(data) && data.type === 'CompoundKeyEddsa') {
    return fromJSON(CompoundKeyEddsa, data.value);
  }

  if (isObject(data) && data.type === 'KeyPair') {
    return fromJSON(KeyPair, data.value);
  }

  if (isObject(data) && data.type === 'PedersenScheme') {
    return fromJSON(PedersenScheme, data.value);
  }

  if (isObject(data) && data.type === 'PedersenParameters') {
    return fromJSON(PedersenParameters, data.value);
  }

  if (isObject(data) && data.type === 'PedersenCommitment') {
    return fromJSON(PedersenCommitment, data.value);
  }

  if (isObject(data) && data.type === 'PedersenDecommitment') {
    return fromJSON(PedersenDecommitment, data.value);
  }

  if (isObject(data) && data.type === 'SyncSession') {
    return fromJSON(SyncSession, data.value);
  }

  if (isObject(data) && data.type === 'SyncData') {
    return fromJSON(SyncData, data.value);
  }

  if (isObject(data) && data.type === 'SignerEddsa') {
    return fromJSON(SignerEddsa, data.value);
  }

  if (isObject(data) && data.type === 'PartialSignature') {
    return fromJSON(PartialSignature, data.value);
  }

  if (isObject(data) && data.type === 'NemTransaction') {
    return fromJSON(NemTransaction, data.value);
  }

  if (isObject(data) && data.type === 'SignerEcdsa') {
    const signer = new SignerEcdsa();
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
    ethereumTransaction.data = data.data;
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
}
