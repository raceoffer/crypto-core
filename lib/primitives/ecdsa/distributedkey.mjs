'use strict';

import assert from 'assert';

import { PaillierProver } from './paillierprover';
import { PaillierVerifier } from './paillierverifier';
import { Signer } from './signer';

import { matchCurve } from '../../curves';

import {
  toJSON,
  fromJSON,
  encodePoint,
  decodePoint,
  encodeBigInteger,
  decodeBigInteger,
  decodeBN,
  encodeBN
} from "../../convert";

import { Root } from 'protobufjs';
import * as proto from './distributedkey.json';

const root = Root.fromJSON(proto);

import { generateKeys, PaillierPublicKey, PaillierSecretKey } from "./paillierkeys";

export class DistributedKey {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.localPrivateKey = null;
    this.remotePublicPoint = null;
    this.compoundPublicPoint = null;

    this.localPaillierPublicKey  = null;
    this.localPaillierSecretKey = null;
  }

  static generatePaillierKeys() {
    return generateKeys();
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = this.crypto.keyFromPrivate(options.secret);
    this.localPaillierPublicKey = options.paillierKeys.publicKey;
    this.localPaillierSecretKey = options.paillierKeys.secretKey;

    return this;
  }

  static fromOptions(options) {
    return new DistributedKey().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      localPrivateKey: encodeBN(this.localPrivateKey.priv, hex),
      remotePublicPoint: encodePoint(this.remotePublicPoint, hex),
      compoundPublicPoint: encodePoint(this.compoundPublicPoint, hex),
      localPaillierPublicKey: toJSON(this.localPaillierPublicKey, hex),
      localPaillierSecretKey: toJSON(this.localPaillierSecretKey, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = this.crypto.keyFromPrivate(decodeBN(json.localPrivateKey, hex));
    this.remotePublicPoint = decodePoint(this.crypto, json.remotePublicPoint, hex);
    this.compoundPublicPoint = decodePoint(this.crypto, json.compoundPublicPoint, hex);

    this.localPaillierPublicKey  = fromJSON(PaillierPublicKey, json.localPaillierPublicKey, hex);
    this.localPaillierSecretKey = fromJSON(PaillierSecretKey, json.localPaillierSecretKey, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new DistributedKey().fromJSON(json, hex);
  }

  toBytes() {
    const type = root.lookupType('DistributedKey');
    return new Buffer(type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const type = root.lookupType('DistributedKey');
    return this.fromJSON(type.decode(bytes));
  }

  static fromBytes(bytes) {
    return new DistributedKey().fromBytes(bytes);
  }

  /**
   * Returns a local private key
   * @returns {*}
   */
  localPrivate() {
    return this.localPrivateKey.getPrivate();
  }

  /**
   * Returns a local public key
   */
  localPublic() {
    return this.localPrivateKey.getPublic();
  }

  remotePublic() {
    return this.remotePublicPoint;
  }

  compoundPublic() {
    return this.compoundPublicPoint;
  }

  /**
   * Initializes and returns a prover object, responsible for key exchange protocol @see PaillierProof
   * @returns {PaillierProver}
   */
  startSyncSession() {
    assert(this.localPrivateKey, "The key must be initialized to start a commitment");

    return PaillierProver.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivate(),
      localPaillierPublicKey: this.localPaillierPublicKey,
      localPaillierSecretKey: this.localPaillierSecretKey
    });
  }

  /**
   * Finalizes the initialization process, applying a verified data from key exchange protocol
   * Sets a compound public key and enables signing
   * @param syncData
   */
  importSyncData(syncData) {
    const point = syncData.publicPoint;
    const compound = point.mul(this.localPrivate());

    this.remotePublicPoint = point;
    this.compoundPublicPoint = compound;
  }

  /**
   * Initiates a Signer object, responsible for message signing protocol
   * @param message (Buffer) - a message to sign
   * @returns {Signer}
   */
  startSignSession(message) {
    return Signer.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      localPaillierPrivateKey: this.localPaillierPrivateKey,
      message: message
    });
  }
}

export class DistributedKeyShard {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.localPrivateKey = null;
    this.remotePublicPoint = null;
    this.compoundPublicPoint = null;

    this.remoteCiphertext = null;
    this.remotePaillierPublicKey = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = this.crypto.keyFromPrivate(options.secret);

    return this;
  }

  static fromOptions(options) {
    return new DistributedKeyShard().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      localPrivateKey: encodeBN(this.localPrivateKey.priv, hex),
      remotePublicPoint: encodePoint(this.remotePublicPoint, hex),
      compoundPublicPoint: encodePoint(this.compoundPublicPoint, hex),
      remotePaillierPublicKey: toJSON(this.remotePaillierPublicKey, hex),
      remoteCiphertext: encodeBigInteger(this.remoteCiphertext, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = this.crypto.keyFromPrivate(decodeBN(json.localPrivateKey, hex));
    this.remotePublicPoint = decodePoint(this.crypto, json.remotePublicPoint, hex);
    this.compoundPublicPoint = decodePoint(this.crypto, json.compoundPublicPoint, hex);

    this.remotePaillierPublicKey = fromJSON(PaillierPublicKey, json.remotePaillierPublicKey, hex);

    this.remoteCiphertext = decodeBigInteger(json.remoteCiphertext, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new DistributedKeyShard().fromJSON(json, hex);
  }

  toBytes() {
    const type = root.lookupType('DistributedKeyShard');
    return new Buffer(type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const type = root.lookupType('DistributedKeyShard');
    return this.fromJSON(type.decode(bytes));
  }

  static fromBytes(bytes) {
    return new DistributedKeyShard().fromBytes(bytes);
  }

  /**
   * Returns a local private key
   * @returns {*}
   */
  localPrivate() {
    return this.localPrivateKey.getPrivate();
  }

  /**
   * Returns a local public key
   */
  localPublic() {
    return this.localPrivateKey.getPublic();
  }

  remotePublic() {
    return this.remotePublicPoint;
  }

  compoundPublic() {
    return this.compoundPublicPoint;
  }

  /**
   * Initializes and returns a prover object, responsible for key exchange protocol @see PaillierProof
   * @returns {PaillierProver}
   */
  startSyncSession() {
    assert(this.localPrivateKey, "The key must be initialized to start a commitment");

    return PaillierVerifier.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivate()
    });
  }

  /**
   * Finalizes the initialization process, applying a verified data from key exchange protocol
   * Sets a compound public key and enables signing
   * @param syncData
   */
  importSyncData(syncData) {
    const point = syncData.publicPoint;
    const compound = point.mul(this.localPrivate());

    this.remotePublicPoint = point;
    this.compoundPublicPoint = compound;
    this.remoteCiphertext = syncData.ciphertext;
    this.remotePaillierPublicKey = syncData.paillierPublicKey;
  }

  /**
   * Initiates a Signer object, responsible for message signing protocol
   * @param message (Buffer) - a message to sign
   * @returns {Signer}
   */
  startSignSession(message) {
    return Signer.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      remotePaillierPublicKey: this.remotePaillierPublicKey,
      remotePrivateCiphertext: this.remoteCiphertext,
      message: message
    });
  }
}