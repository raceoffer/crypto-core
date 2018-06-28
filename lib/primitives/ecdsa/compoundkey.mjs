'use strict';

import assert from 'assert';

import { PaillierProver } from './paillierprover';
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

import { generateKeys, PaillierPublicKey, PaillierSecretKey } from "./paillierkeys";

export class CompoundKey {
  constructor() {
    this.curve = null;
    this.crypto = null;

    // Own key (private)
    this.localPrivateKey = null;

    // External key (public only)
    this.remotePublic = null;

    // Compound key (public only)
    this.compoundPublic = null;

    // Paillier keypair
    this.localPaillierPublicKey  = null;
    this.localPaillierPrivateKey = null;

    // Encrypted remote private key
    this.remotePrivateCiphertext = null;

    // Remote paillier public key
    this.remotePaillierPublicKey = null;
  }

  static generatePaillierKeys() {
    return generateKeys();
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = this.crypto.keyFromPrivate(options.secret);
    this.localPaillierPublicKey = options.paillierKeys.publicKey;
    this.localPaillierPrivateKey = options.paillierKeys.secretKey;

    return this;
  }

  static fromOptions(options) {
    return new CompoundKey().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      localPrivateKey: encodeBN(this.localPrivateKey.priv),
      remotePublic: encodePoint(this.remotePublic),
      compoundPublic: encodePoint(this.compoundPublic),
      localPaillierPublicKey: toJSON(this.localPaillierPublicKey),
      localPaillierPrivateKey: toJSON(this.localPaillierPrivateKey),
      remotePaillierPublicKey: toJSON(this.remotePaillierPublicKey),
      remotePrivateCiphertext: encodeBigInteger(this.remotePrivateCiphertext)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = this.crypto.keyFromPrivate(decodeBN(json.localPrivateKey));
    this.remotePublic = decodePoint(this.crypto, json.remotePublic);
    this.compoundPublic = decodePoint(this.crypto, json.compoundPublic);

    this.localPaillierPublicKey  = fromJSON(PaillierPublicKey, json.localPaillierPublicKey);
    this.localPaillierPrivateKey = fromJSON(PaillierSecretKey, json.localPaillierPrivateKey);
    this.remotePaillierPublicKey = fromJSON(PaillierPublicKey, json.remotePaillierPublicKey);

    this.remotePrivateCiphertext = decodeBigInteger(json.remotePrivateCiphertext);

    return this;
  }

  static fromJSON(json) {
    return new CompoundKey().fromJSON(json);
  }

  /**
   * Returns a local private key
   * @returns {*}
   */
  get localPrivate() {
    return this.localPrivateKey.getPrivate();
  }

  /**
   * Returns a local public key
   */
  get localPublic() {
    return this.localPrivateKey.getPublic();
  }

  /**
   * Initializes and returns a prover object, responsible for key exchange protocol @see PaillierProof
   * @returns {PaillierProver}
   */
  startSyncSession() {
    assert(this.localPrivateKey, "The key must be initialized to start a commitment");

    return PaillierProver.fromOptions({
      curve: this.curve,
      x:  this.localPrivate,
      pk: this.localPaillierPublicKey,
      sk: this.localPaillierPrivateKey
    });
  }

  /**
   * Finalizes the initialization process, applying a verified data from key exchange protocol
   * Sets a compound public key and enables signing
   * @param syncData
   */
  importSyncData(syncData) {
    const point = syncData.Q;
    const compound = point.mul(this.localPrivate);

    this.remotePublic = point;
    this.compoundPublic = compound;
    this.remotePrivateCiphertext = syncData.c;
    this.remotePaillierPublicKey = syncData.pk;
  }

  /**
   * Returns the exact set of data used to finalize this CompoundKey
   * May be used for key duplication and re-initialization
   * @returns {{Q, pk: (null|*), c: (null|*)}}
   */
  extractSyncData() {
    assert(this.compoundPublicKey);

    return {
      Q: this.remotePublic,
      pk: this.remotePaillierPublicKey,
      c: this.remotePrivateCiphertext
    };
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
      remotePaillierPublicKey: this.remotePaillierPublicKey,
      remotePrivateCiphertext: this.remotePrivateCiphertext,
      message: message
    });
  }
}
