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

const { Root } = require('protobufjs');
const proto = require('./marshal.json');

const root = Root.fromJSON(proto);

const { PaillierPublicKey, PaillierSecretKey } = require('./primitives/ecdsa/paillierkeys');

const { EddsaKeyPair } = require('./primitives/eddsa/keypair');

const {
  DistributedEcdsaKey,
  DistributedEcdsaKeyShard
} = require("./primitives/ecdsa/distributedkey");

const {
  DistributedEddsaKey
} = require("./primitives/eddsa/distributedkey");

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

const {
  DistributedEddsaSyncSession,
  DistributedEddsaSyncSessionShard,
  EddsaCommitment,
  EddsaDecommitment,
  EddsaData,
  EddsaSyncData
} = require('./primitives/eddsa/distributedsyncsession');

const {
  BitcoreSignSession,
  BitcoreSignSessionShard,
  BitcoreEntropyCommitment,
  BitcoreEntropyDecommitment,
  BitcoreEntropyData,
  BitcorePartialSignature,
  BitcoreSignature
} = require('./transaction/bitcore/bitcoretransaction');

const { EthereumTransaction } = require('./transaction/ethereum/ethereumtransaction');
const { NeoTransaction } = require('./transaction/neo/neotransaction');
const { NemTransaction } = require('./transaction/nem/nemtransaction');
const { BitcoinTransaction } = require('./transaction/bitcore/bitcointransaction');
const { BitcoinCashTransaction } = require('./transaction/bitcore/bitcoincashtransaction');
const { LitecoinTransaction } = require('./transaction/bitcore/litecointransaction');

const { PedersenScheme } = require('./primitives/pedersenscheme');
const { SchnorrProof } = require('./primitives/schnorrproof');

const { toJSON, fromJSON, encodeBuffer, decodeBuffer, encodeBN, decodeBN, toBytes, fromBytes } = require('./convert');

const typeMap = {
  PedersenScheme,
  SchnorrProof,
  PaillierPublicKey,
  PaillierSecretKey,
  DistributedEcdsaKey,
  DistributedEcdsaKeyShard,
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
  EcdsaShardSyncData,
  DistributedEcdsaSignSession,
  DistributedEcdsaSignSessionShard,
  EcdsaEntropyCommitment,
  EcdsaEntropyDecommitment,
  EcdsaEntropyData,
  EcdsaPartialSignature,
  EcdsaSignature,
  EddsaKeyPair,
  DistributedEddsaKey,
  DistributedEddsaSyncSession,
  DistributedEddsaSyncSessionShard,
  EddsaCommitment,
  EddsaDecommitment,
  EddsaData,
  EddsaSyncData,
  BitcoreSignSession,
  BitcoreSignSessionShard,
  BitcoreEntropyCommitment,
  BitcoreEntropyDecommitment,
  BitcoreEntropyData,
  BitcorePartialSignature,
  BitcoreSignature,
  EthereumTransaction,
  NeoTransaction,
  NemTransaction,
  BitcoinTransaction,
  BitcoinCashTransaction,
  LitecoinTransaction
};

function encode(data) {
  const TypedMessage = root.lookupType('TypedMessage');
  for (const property in typeMap) {
    if (typeMap.hasOwnProperty(property)) {
      if (data instanceof typeMap[property]) {
        return new Buffer(TypedMessage.encode({
          type: property,
          value: toBytes(data)
        }).finish());
      }
    }
  }

  throw new Error('Unsupported type');
}

function decode(bytes) {
  const TypedMessage = root.lookupType('TypedMessage');
  
  const { type, value } = TypedMessage.decode(bytes);

  if (typeMap.hasOwnProperty(type)) {
    return fromBytes(typeMap[type], value);
  }

  throw new Error('Unsupported type');
}

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

  for (const property in typeMap) {
    if (typeMap.hasOwnProperty(property)) {
      if (data instanceof typeMap[property]) {
        return {
          type: property,
          value: toJSON(data, true)
        };
      }
    }
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

  if (isObject(data) && typeMap.hasOwnProperty(data.type)) {
    return fromJSON(typeMap[data.type], data.value, true);
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
  unwrap,
  encode,
  decode
};
