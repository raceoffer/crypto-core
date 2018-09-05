'use strict';

const isUndefined = require('lodash/isUndefined');
const isNull = require('lodash/isNull');
const isString = require('lodash/isString');
const isNumber = require('lodash/isNumber');
const isBoolean = require('lodash/isBoolean');
const isArray = require('lodash/isArray');
const isObject = require('lodash/isObject');
const map = require('lodash/map');
const mapValues = require('lodash/mapValues');

const { Buffer } = require('buffer');

const BN = require('bn.js');

// const { KeyPair } = require('./primitives/eddsa/keypair');

const { PaillierPublicKey, PaillierSecretKey } = require('./primitives/ecdsa/paillierkeys');
const { DistributedEcdsaKey } = require("./primitives/ecdsa/distributedkey");

const { EthereumTransaction } = require('./transaction/ethereum/ethereumtransaction');
const { NeoTransaction } = require('./transaction/neo/neotransaction');
// const { NemTransaction } = require('./transaction/nem/nemtransaction');
const { BitcoinTransaction } = require('./transaction/bitcore/bitcointransaction');
const { BitcoinCashTransaction } = require('./transaction/bitcore/bitcoincashtransaction');
const { LitecoinTransaction } = require('./transaction/bitcore/litecointransaction');

const { PedersenScheme } = require('./primitives/pedersenscheme');

const { toJSON, fromJSON, encodeBuffer, decodeBuffer, encodeBN, decodeBN } = require('./convert');

function wrap(data) {
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

  // if (data instanceof KeyPair) {
  //   return {
  //     type: 'KeyPair',
  //     value: toJSON(data, true)
  //   };
  // }

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

  if (data instanceof DistributedEcdsaKey) {
    return {
      type: 'DistributedEcdsaKey',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PedersenScheme) {
    return {
      type: 'PedersenScheme',
      value: toJSON(data, true)
    };
  }

  // if (data instanceof NemTransaction) {
  //   return {
  //     type: 'NemTransaction',
  //     value: toJSON(data, true)
  //   };
  // }

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

function unwrap(data) {
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

  if (isObject(data) && data.type === 'DistributedEcdsaKey') {
    return fromJSON(DistributedEcdsaKey, data.value, true);
  }

  // if (isObject(data) && data.type === 'KeyPair') {
  //   return fromJSON(KeyPair, data.value, true);
  // }

  if (isObject(data) && data.type === 'PaillierPublicKey') {
    return fromJSON(PaillierPublicKey, data.value, true);
  }

  if (isObject(data) && data.type === 'PaillierSecretKey') {
    return fromJSON(PaillierSecretKey, data.value, true);
  }

  if (isObject(data) && data.type === 'PedersenScheme') {
    return fromJSON(PedersenScheme, data.value, true);
  }

  // if (isObject(data) && data.type === 'NemTransaction') {
  //   return fromJSON(NemTransaction, data.value, true);
  // }

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

module.exports = {
  wrap,
  unwrap
};
