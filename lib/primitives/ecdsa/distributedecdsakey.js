'use strict';

const BN = require('bn.js');

const { DistributedEcdsaSignSession, DistributedEcdsaSignSessionShard } = require('./distributedecdsasignsession');
const { DistributedEcdsaSyncSession, DistributedEcdsaSyncSessionShard } = require('./distributedecdsasyncsession');
const { generateKeys, PaillierPublicKey, PaillierSecretKey } = require('./paillierkeys');

const { Field, generateMessage } = require('../../convert');

const { Root } = require('protobufjs');
const proto = require('./distributedecdsakey.json');

const root = Root.fromJSON(proto);

class DistributedEcdsaKey extends generateMessage(
  'DistributedEcdsaKey', {
    localPrivateKey: [Field.BN],
    remotePublicPoint: [Field.Point],
    compoundPublicPoint: [Field.Point],
    localPaillierPublicKey: [Field.Custom, PaillierPublicKey],
    localPaillierSecretKey: [Field.Custom, PaillierSecretKey]
  },
  root
) {
  static generatePaillierKeys() {
    return generateKeys();
  }

  fromOptions(options) {
    super.fromOptions(options);

    this.localPrivateKey = new BN(options.secret);

    return this;
  }

  static fromOptions(options) {
    return new DistributedEcdsaKey().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedEcdsaKey().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEcdsaKey().fromBytes(bytes);
  }

  localPrivate() {
    return this.localPrivateKey;
  }

  localPublic() {
    return this.crypto.g.mul(this.localPrivateKey);
  }

  remotePublic() {
    return this.remotePublicPoint;
  }

  compoundPublic() {
    return this.compoundPublicPoint;
  }

  startSyncSession() {
    return DistributedEcdsaSyncSession.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      localPaillierPublicKey: this.localPaillierPublicKey,
      localPaillierSecretKey: this.localPaillierSecretKey
    });
  }

  importSyncData(syncData) {
    const point = syncData.publicPoint;
    const compound = point.mul(this.localPrivateKey);

    this.remotePublicPoint = point;
    this.compoundPublicPoint = compound;
  }

  startSignSession(message) {
    return DistributedEcdsaSignSession.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      localPaillierSecretKey: this.localPaillierSecretKey,
      message: message
    });
  }
}

class DistributedEcdsaKeyShard extends generateMessage(
  'DistributedEcdsaKeyShard', {
    localPrivateKey: [Field.BN],
    remotePublicPoint: [Field.Point],
    compoundPublicPoint: [Field.Point],
    remotePaillierPublicKey: [Field.Custom, PaillierPublicKey],
    remoteCiphertext: [Field.BigInteger]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPrivateKey = new BN(options.secret);

    return this;
  }

  static fromOptions(options) {
    return new DistributedEcdsaKeyShard().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedEcdsaKeyShard().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEcdsaKeyShard().fromBytes(bytes);
  }

  localPrivate() {
    return this.localPrivateKey;
  }

  localPublic() {
    return this.crypto.g.mul(this.localPrivateKey);
  }

  remotePublic() {
    return this.remotePublicPoint;
  }

  compoundPublic() {
    return this.compoundPublicPoint;
  }

  startSyncSession() {
    return DistributedEcdsaSyncSessionShard.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey
    });
  }

  importSyncData(syncData) {
    const point = syncData.publicPoint;
    const compound = point.mul(this.localPrivateKey);

    this.remotePublicPoint = point;
    this.compoundPublicPoint = compound;
    this.remoteCiphertext = syncData.ciphertext;
    this.remotePaillierPublicKey = syncData.paillierPublicKey;
  }

  startSignSession(message) {
    return DistributedEcdsaSignSessionShard.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      remotePaillierPublicKey: this.remotePaillierPublicKey,
      remotePrivateCiphertext: this.remoteCiphertext,
      message: message
    });
  }
}

module.exports = {
  DistributedEcdsaKey,
  DistributedEcdsaKeyShard
};
