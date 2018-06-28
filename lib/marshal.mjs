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

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { KeyPair } from "./primitives/eddsa/keypair";
import { CompoundKey as CompoundKeyEcdsa } from './primitives/ecdsa/compoundkey';
import { CompoundKey as CompoundKeyEddsa } from './primitives/eddsa/compoundkey';

import { PaillierProver } from './primitives/ecdsa/paillierprover';
import { PaillierVerifier, SCommitment, SyncData as SyncDataEcdsa } from './primitives/ecdsa/paillierverifier';
import { SyncSession, SyncData as SyncDataEddsa } from "./primitives/eddsa/syncsession";

import { Signer as SignerEcdsa, PartialSignature as PartialSignatureEcdsa } from './primitives/ecdsa/signer';
import { Signer as SignerEddsa, PartialSignature as PartialSignatureEddsa } from './primitives/eddsa/signer';

//-----------------------
import BitcoinTransactionSignature from 'bitcore-lib/lib/transaction/signature';
import BitcoinCashTransactionSignature from 'bitcoincashjs/src/transaction/signature';
import LitecoinTransactionSignature from 'litecore-lib/lib/transaction/signature';

import { BitcoinTransaction } from './transaction/bitcore/bitcointransaction';
import { BitcoinCashTransaction } from './transaction/bitcore/bitcoincashtransaction';
import { LitecoinTransaction } from './transaction/bitcore/litecointransaction';
import { EthereumTransaction } from './transaction/ethereum/ethereumtransaction';
import { NemTransaction } from './transaction/nem/nemtransaction';
//-----------------------

import {
  PedersenScheme,
  PedersenCommitment,
  PedersenDecommitment,
  PedersenParameters
} from './primitives/pedersenscheme';

import { toJSON, fromJSON } from './convert';

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

  if (data instanceof CompoundKeyEcdsa) {
    return {
      type: 'CompoundKeyEcdsa',
      value: toJSON(data)
    };
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

  if(data instanceof PaillierProver) {
    return {
      type: 'PaillierProver',
      value: toJSON(data)
    }
  }

  if(data instanceof PaillierVerifier) {
    return {
      type: 'PaillierVerifier',
      value: toJSON(data)
    }
  }

  if (data instanceof SyncSession) {
    return {
      type: 'SyncSession',
      value: toJSON(data)
    }
  }

  if (data instanceof SyncDataEddsa) {
    return {
      type: 'SyncDataEddsa',
      value: toJSON(data)
    }
  }

  if (data instanceof SyncDataEcdsa) {
    return {
      type: 'SyncDataEcdsa',
      value: toJSON(data)
    }
  }

  if (data instanceof SCommitment) {
    return {
      type: 'SCommitment',
      value: toJSON(data)
    }
  }

  if (data instanceof SignerEddsa) {
    return {
      type: 'SignerEddsa',
      value: toJSON(data)
    };
  }

  if (data instanceof SignerEcdsa) {
    return {
      type: 'SignerEcdsa',
      value: toJSON(data)
    };
  }

  if (data instanceof PartialSignatureEcdsa) {
    return {
      type: 'PartialSignatureEcdsa',
      value: toJSON(data)
    };
  }

  if (data instanceof PartialSignatureEddsa) {
    return {
      type: 'PartialSignatureEddsa',
      value: toJSON(data)
    };
  }

  if (data instanceof NemTransaction) {
    return {
      type: 'NemTransaction',
      value: toJSON(data)
    };
  }

  if (data instanceof EthereumTransaction) {
    return {
      type: 'EthereumTransaction',
      value: toJSON(data)
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

  if (isArray(data)) {
    return map(data, arg => wrap(arg));
  }

  if (isObject(data)) {
    return mapValues(data, arg => wrap(arg));
  }

  return data;
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

  if (isObject(data) && data.type === 'PaillierProver') {
    return fromJSON(PaillierProver, data.value);
  }

  if (isObject(data) && data.type === 'PaillierVerifier') {
    return fromJSON(PaillierVerifier, data.value);
  }

  if (isObject(data) && data.type === 'CompoundKeyEddsa') {
    return fromJSON(CompoundKeyEddsa, data.value);
  }

  if (isObject(data) && data.type === 'CompoundKeyEcdsa') {
    return fromJSON(CompoundKeyEcdsa, data.value);
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

  if (isObject(data) && data.type === 'SyncDataEddsa') {
    return fromJSON(SyncDataEddsa, data.value);
  }

  if (isObject(data) && data.type === 'SyncDataEcdsa') {
    return fromJSON(SyncDataEcdsa, data.value);
  }

  if (isObject(data) && data.type === 'SCommitment') {
    return fromJSON(SCommitment, data.value);
  }

  if (isObject(data) && data.type === 'SignerEddsa') {
    return fromJSON(SignerEddsa, data.value);
  }

  if (isObject(data) && data.type === 'SignerEcdsa') {
    return fromJSON(SignerEcdsa, data.value);
  }

  if (isObject(data) && data.type === 'PartialSignatureEcdsa') {
    return fromJSON(PartialSignatureEcdsa, data.value);
  }

  if (isObject(data) && data.type === 'PartialSignatureEddsa') {
    return fromJSON(PartialSignatureEddsa, data.value);
  }

  if (isObject(data) && data.type === 'NemTransaction') {
    return fromJSON(NemTransaction, data.value);
  }

  if (isObject(data) && data.type === 'EthereumTransaction') {
    return fromJSON(EthereumTransaction, data.value);
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

  if (isArray(data)) {
    return map(data, unwrap);
  }

  if (isObject(data)) {
    return mapValues(data, unwrap);
  }

  return data;
}
