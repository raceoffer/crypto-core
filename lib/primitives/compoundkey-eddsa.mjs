'use strict';

import assert from 'assert';

import EC from 'elliptic';
import jspaillier from 'jspaillier';

const ec = EC.eddsa('ed25519');

import { PaillierProver } from './paillierprover';
import { SignerEddsa } from "./signer-eddsa";

export class CompoundKeyEddsa {
  constructor() {
    // Own key (private)
    this.localPrivateKey = null;

    // External key (public only)
    this.remotePublicKey = null;

    // Compound key (public only)
    this.compoundPublicKey = null;

    // Paillier keypair
    this.localPaillierPublicKey  = null;
    this.localPaillierPrivateKey = null;

    // Encrypted remote private key
    this.remotePrivateCiphertext = null;

    // Remote paillier public key
    this.remotePaillierPublicKey = null;
  }

  /**
   * Generates a paillier keypair
   * @returns {{localPaillierPublicKey, localPaillierPrivateKey}}
   */
  static generatePaillierKeys() {
    const paillierKeys = jspaillier.generateKeys(1024);
    return {
      localPaillierPublicKey:  paillierKeys.pub,
      localPaillierPrivateKey: paillierKeys.sec
    };
  }

  /**
   * Initializes a KeyPair from byte string
   * @param secret
   * @returns {KeyPair}
   */
  static keyFromSecret(secret) {
    return ec.keyFromSecret(secret);
  }

  /**
   * Initializes a CompoundKey from byte string
   * @param secret
   */
  static fromSecret(secret) {
    return CompoundKeyEddsa.fromOptions({
      localPrivateKey: CompoundKeyEddsa.keyFromSecret(secret),
      localPaillierKeys: CompoundKeyEddsa.generatePaillierKeys()
    });
  }

  /**
   * Initializes a Compound key with options
   * @param options.localPrivateKey
   * @param options.localPaillierKeys
   * @returns {CompoundKey}
   */
  fromOptions(options) {
    assert(options.localPrivateKey, 'A private keyring is required');
    assert(options.localPaillierKeys, 'Paillier keys are required');

    this.localPrivateKey = options.localPrivateKey;
    this.localPaillierPublicKey = options.localPaillierKeys.localPaillierPublicKey;
    this.localPaillierPrivateKey = options.localPaillierKeys.localPaillierPrivateKey;

    return this;
  }

  /**
   * Static version of the above
   * @returns {CompoundKey}
   */
  static fromOptions(options) {
    return new CompoundKeyEddsa().fromOptions(options);
  }

  /**
   * Returns a local private key
   * @returns {*}
   */
  getPrivateKey() {
    return this.localPrivateKey.priv();
  }

  /**
   * Returns a local public key encoded with options encoding [raw if not specified]
   * @param compress - point compression
   * @param enc [optional] - 'hex'/'base58'
   */
  getPublicKey() {
    return this.localPrivateKey.pub();
  }

  /**
   * Returns a compound public key encoded with options encoding [raw if not specified]
   * @param compress - point compression
   * @param enc [optional] - 'hex'/'base58'
   */
  getCompoundPublicKey() {
    if(!this.remotePublicKey){
      return null;
    }
    return this.compoundPublicKey.pub();
  }

  /**
   * Initializes and returns a prover object, responsible for key exchange protocol @see PaillierProof
   * @returns {PaillierProver}
   */
  startInitialCommitment() {
    assert(this.localPrivateKey, "The key must be initialized to start a commitment");

    return PaillierProver.fromOptions({
      ec: ec,
      x:  this.getPrivateKey(),
      pk: this.localPaillierPublicKey,
      sk: this.localPaillierPrivateKey
    });
  }

  /**
   * Finalizes the initialization process, applying a verified data from key exchange protocol
   * Sets a compound public key and enables signing
   * @param syncData
   */
  finishInitialSync(syncData) {
    // remote Q
    const point = syncData.Q;
    // local x
    const key = this.getPrivateKey();
    // compound Q according to ECDH
    const compound = point.mul(key);

    this.remotePublicKey = ec.keyFromPublic(point);
    this.remotePrivateCiphertext = syncData.c;
    this.remotePaillierPublicKey = syncData.pk;

    this.compoundPublicKey = ec.keyFromPublic(compound);
  }

  /**
   * Returns the exact set of data used to finalize this CompoundKey
   * May be used for key duplication and re-initialization
   * @returns {{Q, pk: (null|*), c: (null|*)}}
   */
  extractSyncData() {
    assert(this.compoundPublicKey);

    return {
      Q: this.remotePublicKey.pub(),
      pk: this.remotePaillierPublicKey,
      c: this.remotePrivateCiphertext
    };
  }

  /**
   * Initiates a Signer object, responsible for message signing protocol
   * @param message (Buffer) - a message to sign
   * @returns {Signer}
   */
  startSign(message) {
    return SignerEddsa.fromOptions({
      message: message,
      compoundKey: this
    });
  }
}
