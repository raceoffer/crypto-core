'use strict';

import BN from 'bn.js';

import { PaillierProver } from './paillierprover';
import { PaillierVerifier } from './paillierverifier';
import { DistributedSigner, DistributedSignerShard } from './distributedsigner';

import { Field, generateMessage } from '../../convert';

import { Root } from 'protobufjs';
import * as proto from './distributedkey.json';

const root = Root.fromJSON(proto);

import { generateKeys, PaillierPublicKey, PaillierSecretKey } from './paillierkeys';

export class DistributedKey extends generateMessage(
  'DistributedKey', {
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
    return new DistributedKey().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedKey().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedKey().fromBytes(bytes);
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
    return PaillierProver.fromOptions({
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
    return DistributedSigner.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      localPaillierSecretKey: this.localPaillierSecretKey,
      message: message
    });
  }
}

export class DistributedKeyShard extends generateMessage(
  'DistributedKeyShard', {
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
    return new DistributedKeyShard().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedKeyShard().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedKeyShard().fromBytes(bytes);
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
    return PaillierVerifier.fromOptions({
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
    return DistributedSignerShard.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      remotePaillierPublicKey: this.remotePaillierPublicKey,
      remotePrivateCiphertext: this.remoteCiphertext,
      message: message
    });
  }
}