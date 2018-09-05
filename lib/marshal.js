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

const {
  DistributedEcdsaKey,
  DistributedEcdsaKeyShard
} = require("./primitives/ecdsa/distributedkey");

const {
  DistributedEcdsaSyncSession,
  DistributedEcdsaSyncSessionShard,
  EcdsaInitialCommitment,
  EcdsaInitialDecommitment,
  EcdsaInitialData,
  EcdsaChallengeCommitment,
  EcdsaChallengeDecommitment,
  EcdsaResponseCommitment,
  EcdsaResponseDecommitment,
  EcdsaSyncData,
  EcdsaShardSyncData
} = require('./primitives/ecdsa/distributedsyncsession');

const {
  DistributedEcdsaSignSession,
  DistributedEcdsaSignSessionShard,
  EcdsaEntropyCommitment,
  EcdsaEntropyDecommitment,
  EcdsaEntropyData,
  EcdsaPartialSignature,
  EcdsaSignature
} = require('./primitives/ecdsa/distributedsignsession');

const { EthereumTransaction } = require('./transaction/ethereum/ethereumtransaction');
const { NeoTransaction } = require('./transaction/neo/neotransaction');
// const { NemTransaction } = require('./transaction/nem/nemtransaction');
const { BitcoinTransaction } = require('./transaction/bitcore/bitcointransaction');
const { BitcoinCashTransaction } = require('./transaction/bitcore/bitcoincashtransaction');
const { LitecoinTransaction } = require('./transaction/bitcore/litecointransaction');

const { PedersenScheme } = require('./primitives/pedersenscheme');
const { SchnorrProof } = require('./primitives/schnorrproof');

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

  if (data instanceof SchnorrProof) {
    return {
      type: 'SchnorrProof',
      value: toJSON(data, true)
    };
  }

  if (data instanceof PedersenScheme) {
    return {
      type: 'PedersenScheme',
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

  if (data instanceof DistributedEcdsaKey) {
    return {
      type: 'DistributedEcdsaKey',
      value: toJSON(data, true)
    };
  }

  if (data instanceof DistributedEcdsaKeyShard) {
    return {
      type: 'DistributedEcdsaKeyShard',
      value: toJSON(data, true)
    };
  }

  if (data instanceof DistributedEcdsaSyncSession) {
    return {
      type: 'DistributedEcdsaSyncSession',
      value: toJSON(data, true)
    };
  }

  if (data instanceof DistributedEcdsaSyncSessionShard) {
    return {
      type: 'DistributedEcdsaSyncSessionShard',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaInitialCommitment) {
    return {
      type: 'EcdsaInitialCommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaInitialDecommitment) {
    return {
      type: 'EcdsaInitialDecommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaInitialData) {
    return {
      type: 'EcdsaInitialData',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaChallengeCommitment) {
    return {
      type: 'EcdsaChallengeCommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaChallengeDecommitment) {
    return {
      type: 'EcdsaChallengeDecommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaResponseCommitment) {
    return {
      type: 'EcdsaResponseCommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaResponseDecommitment) {
    return {
      type: 'EcdsaResponseDecommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaSyncData) {
    return {
      type: 'EcdsaSyncData',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaShardSyncData) {
    return {
      type: 'EcdsaShardSyncData',
      value: toJSON(data, true)
    };
  }

  if (data instanceof DistributedEcdsaSignSession) {
    return {
      type: 'DistributedEcdsaSignSession',
      value: toJSON(data, true)
    };
  }

  if (data instanceof DistributedEcdsaSignSessionShard) {
    return {
      type: 'DistributedEcdsaSignSessionShard',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaEntropyCommitment) {
    return {
      type: 'EcdsaEntropyCommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaEntropyDecommitment) {
    return {
      type: 'EcdsaEntropyDecommitment',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaEntropyData) {
    return {
      type: 'EcdsaEntropyData',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaPartialSignature) {
    return {
      type: 'EcdsaPartialSignature',
      value: toJSON(data, true)
    };
  }

  if (data instanceof EcdsaSignature) {
    return {
      type: 'EcdsaSignature',
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

  if (isObject(data) && data.type === 'PedersenScheme') {
    return fromJSON(PedersenScheme, data.value, true);
  }

  if (isObject(data) && data.type === 'SchnorrProof') {
    return fromJSON(SchnorrProof, data.value, true);
  }

  if (isObject(data) && data.type === 'PaillierPublicKey') {
    return fromJSON(PaillierPublicKey, data.value, true);
  }

  if (isObject(data) && data.type === 'PaillierSecretKey') {
    return fromJSON(PaillierSecretKey, data.value, true);
  }

  // if (isObject(data) && data.type === 'KeyPair') {
  //   return fromJSON(KeyPair, data.value, true);
  // }

  if (isObject(data) && data.type === 'DistributedEcdsaKey') {
    return fromJSON(DistributedEcdsaKey, data.value, true);
  }

  if (isObject(data) && data.type === 'DistributedEcdsaKeyShard') {
    return fromJSON(DistributedEcdsaKeyShard, data.value, true);
  }

  if (isObject(data) && data.type === 'DistributedEcdsaSyncSession') {
    return fromJSON(DistributedEcdsaSyncSession, data.value, true);
  }

  if (isObject(data) && data.type === 'DistributedEcdsaSyncSessionShard') {
    return fromJSON(DistributedEcdsaSyncSessionShard, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaInitialCommitment') {
    return fromJSON(EcdsaInitialCommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaInitialDecommitment') {
    return fromJSON(EcdsaInitialDecommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaInitialData') {
    return fromJSON(EcdsaInitialData, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaChallengeCommitment') {
    return fromJSON(EcdsaChallengeCommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaChallengeDecommitment') {
    return fromJSON(EcdsaChallengeDecommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaResponseCommitment') {
    return fromJSON(EcdsaResponseCommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaResponseDecommitment') {
    return fromJSON(EcdsaResponseDecommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaSyncData') {
    return fromJSON(EcdsaSyncData, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaShardSyncData') {
    return fromJSON(EcdsaShardSyncData, data.value, true);
  }

  if (isObject(data) && data.type === 'DistributedEcdsaSignSession') {
    return fromJSON(DistributedEcdsaSignSession, data.value, true);
  }

  if (isObject(data) && data.type === 'DistributedEcdsaSignSessionShard') {
    return fromJSON(DistributedEcdsaSignSessionShard, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaEntropyCommitment') {
    return fromJSON(EcdsaEntropyCommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaEntropyDecommitment') {
    return fromJSON(EcdsaEntropyDecommitment, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaEntropyData') {
    return fromJSON(EcdsaEntropyData, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaPartialSignature') {
    return fromJSON(EcdsaPartialSignature, data.value, true);
  }

  if (isObject(data) && data.type === 'EcdsaSignature') {
    return fromJSON(EcdsaSignature, data.value, true);
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
