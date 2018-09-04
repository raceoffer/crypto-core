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

import BN from 'bn.js';

import { KeyPair } from "./primitives/eddsa/keypair";

import { SyncSession, SyncData as SyncDataEddsa } from "./primitives/eddsa/syncsession";
import { PaillierPublicKey, PaillierSecretKey } from './primitives/ecdsa/paillierkeys';

import { EthereumTransaction } from './transaction/ethereum/ethereumtransaction';
import { NemTransaction } from './transaction/nem/nemtransaction';
import { NeoTransaction } from './transaction/neo/neotransaction';
import { BitcoinTransaction } from './transaction/bitcore/bitcointransaction';
import { BitcoinCashTransaction } from './transaction/bitcore/bitcoincashtransaction';
import { LitecoinTransaction } from './transaction/bitcore/litecointransaction';

import {
  PedersenScheme,
  PedersenCommitment,
  PedersenDecommitment,
  PedersenParameters
} from './primitives/pedersenscheme';

import { toJSON, fromJSON, encodeBuffer, decodeBuffer, encodeBN, decodeBN } from './convert';

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
      value: encodeBuffer(data)
    };
  }

  if (BN.isBN(data)) {
    return {
      type: 'BN',
      value: encodeBN(data, true)
    };
  }

  if (data instanceof KeyPair) {
    return {
      type: 'KeyPair',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PaillierPublicKey) {
    return {
      type: 'PaillierPublicKey',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PaillierSecretKey) {
    return {
      type: 'PaillierSecretKey',
      value: toJSON(data, true)
    };
  }

  if (data instanceof CompoundKeyEcdsa) {
    return {
      type: 'CompoundKeyEcdsa',
      value: toJSON(data, true)
    };
  }

  if (data instanceof CompoundKeyEddsa) {
    return {
      type: 'CompoundKeyEddsa',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PedersenScheme) {
    return {
      type: 'PedersenScheme',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PedersenParameters) {
    return {
      type: 'PedersenParameters',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PedersenCommitment) {
    return {
      type: 'PedersenCommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PedersenDecommitment) {
    return {
      type: 'PedersenDecommitment',
      value: toJSON(data, true)
    };
  }

  if(data instanceof PaillierProver) {
    return {
      type: 'PaillierProver',
      value: toJSON(data, true)
    };
  }

  if(data instanceof PaillierVerifier) {
    return {
      type: 'PaillierVerifier',
      value: toJSON(data, true)
    };
  }

  if (data instanceof SyncSession) {
    return {
      type: 'SyncSession',
      value: toJSON(data, true)
    };
  }

  if (data instanceof SyncDataEddsa) {
    return {
      type: 'SyncDataEddsa',
      value: toJSON(data, true)
    };
  }

  if (data instanceof SyncDataEcdsa) {
    return {
      type: 'SyncDataEcdsa',
      value: toJSON(data, true)
    };
  }

  if (data instanceof SCommitment) {
    return {
      type: 'SCommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof SignerEddsa) {
    return {
      type: 'SignerEddsa',
      value: toJSON(data, true)
    };
  }

  if (data instanceof SignerEcdsa) {
    return {
      type: 'SignerEcdsa',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PartialSignatureEcdsa) {
    return {
      type: 'PartialSignatureEcdsa',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PartialSignatureEddsa) {
    return {
      type: 'PartialSignatureEddsa',
      value: toJSON(data, true)
    };
  }

  if (data instanceof Signature) {
    return {
      type: 'Signature',
      value: toJSON(data, true)
    };
  }

  if (data instanceof NemTransaction) {
    return {
      type: 'NemTransaction',
      value: toJSON(data, true)
    };
  }

  if (data instanceof NeoTransaction) {
    return {
      type: 'NeoTransaction',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EthereumTransaction) {
    return {
      type: 'EthereumTransaction',
      value: toJSON(data, true)
    };
  }

  if (data instanceof BitcoinTransaction) {
    return {
      type: 'BitcoinTransaction',
      value: toJSON(data, true)
    };
  }

  if (data instanceof BitcoinCashTransaction) {
    return {
      type: 'BitcoinCashTransaction',
      value: toJSON(data, true)
    };
  }

  if (data instanceof LitecoinTransaction) {
    return {
      type: 'LitecoinTransaction',
      value: toJSON(data, true)
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
    return decodeBuffer(data.value);
  }

  if (isObject(data) && data.type === 'BN') {
    return decodeBN(data.value, true);
  }

  if (isObject(data) && data.type === 'PaillierProver') {
    return fromJSON(PaillierProver, data.value, true);
  }

  if (isObject(data) && data.type === 'PaillierVerifier') {
    return fromJSON(PaillierVerifier, data.value, true);
  }

  if (isObject(data) && data.type === 'CompoundKeyEddsa') {
    return fromJSON(CompoundKeyEddsa, data.value, true);
  }

  if (isObject(data) && data.type === 'CompoundKeyEcdsa') {
    return fromJSON(CompoundKeyEcdsa, data.value, true);
  }

  if (isObject(data) && data.type === 'KeyPair') {
    return fromJSON(KeyPair, data.value, true);
  }

  if (isObject(data) && data.type === 'PaillierPublicKey') {
    return fromJSON(PaillierPublicKey, data.value, true);
  }

  if (isObject(data) && data.type === 'PaillierSecretKey') {
    return fromJSON(PaillierSecretKey, data.value, true);
  }

  if (isObject(data) && data.type === 'PedersenScheme') {
    return fromJSON(PedersenScheme, data.value, true);
  }

  if (isObject(data) && data.type === 'PedersenParameters') {
    return fromJSON(PedersenParameters, data.value, true);
  }

  if (isObject(data) && data.type === 'PedersenCommitment') {
    return fromJSON(PedersenCommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'PedersenDecommitment') {
    return fromJSON(PedersenDecommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'SyncSession') {
    return fromJSON(SyncSession, data.value, true);
  }

  if (isObject(data) && data.type === 'SyncDataEddsa') {
    return fromJSON(SyncDataEddsa, data.value, true);
  }

  if (isObject(data) && data.type === 'SyncDataEcdsa') {
    return fromJSON(SyncDataEcdsa, data.value, true);
  }

  if (isObject(data) && data.type === 'SCommitment') {
    return fromJSON(SCommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'SignerEddsa') {
    return fromJSON(SignerEddsa, data.value, true);
  }

  if (isObject(data) && data.type === 'SignerEcdsa') {
    return fromJSON(SignerEcdsa, data.value, true);
  }

  if (isObject(data) && data.type === 'PartialSignatureEcdsa') {
    return fromJSON(PartialSignatureEcdsa, data.value, true);
  }

  if (isObject(data) && data.type === 'PartialSignatureEddsa') {
    return fromJSON(PartialSignatureEddsa, data.value, true);
  }

  if (isObject(data) && data.type === 'Signature') {
    return fromJSON(Signature, data.value, true);
  }

  if (isObject(data) && data.type === 'NemTransaction') {
    return fromJSON(NemTransaction, data.value, true);
  }

  if (isObject(data) && data.type === 'NeoTransaction') {
      return fromJSON(NeoTransaction, data.value, true);
  }

  if (isObject(data) && data.type === 'EthereumTransaction') {
    return fromJSON(EthereumTransaction, data.value, true);
  }

  if (isObject(data) && data.type === 'BitcoinTransaction') {
    return fromJSON(BitcoinTransaction, data.value, true);
  }

  if (isObject(data) && data.type === 'BitcoinCashTransaction') {
    return fromJSON(BitcoinCashTransaction, data.value, true);
  }

  if (isObject(data) && data.type === 'LitecoinTransaction') {
    return fromJSON(LitecoinTransaction, data.value, true);
  }

  if (isArray(data)) {
    return map(data, unwrap);
  }

  if (isObject(data)) {
    return mapValues(data, unwrap);
  }

  return data;
}
