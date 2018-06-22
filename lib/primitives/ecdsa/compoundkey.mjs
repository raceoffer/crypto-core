'use strict';

import assert from 'assert';

import elliptic from 'elliptic';
import BN from 'bn.js';
import jspaillier from 'jspaillier';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

import { PaillierProver } from './paillierprover';
import { Signer } from './signer';

export class CompoundKey {
  constructor() {
    this.curve = null;
    this.ec = null;

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
   * Generates a random private key from Z_n/3
   * @returns {KeyPair}
   */
  static generateKey(curve = 'secp256k1') {
    const ec = elliptic.ec(curve);

    const n3 = ec.n.div(new BN(3));
    let key = null;
    do {
      key = ec.genKeyPair();
    } while(key.getPrivate().cmp(n3) > 0);
    return key;
  }

  /**
   * Generates a random CompoundKey with local key from Z_n/3
   */
  static generate(curve = 'secp256k1') {
    return CompoundKey.fromOptions({
      curve: curve,
      localPrivateKey: CompoundKey.generateKey(curve),
      localPaillierKeys: CompoundKey.generatePaillierKeys()
    });
  }

  /**
   * Initializes a KeyPair from byte string
   * @param secret
   * @param curve
   * @returns {KeyPair}
   */
  static keyFromSecret(secret, curve = 'secp256k1') {
    return elliptic.ec(curve).keyFromPrivate(secret);
  }

  /**
   * Initializes a CompoundKey from byte string
   * @param secret
   * @param curve
   */
  static fromSecret(secret, curve = 'secp256k1') {
    return CompoundKey.fromOptions({
      curve: curve,
      localPrivateKey: CompoundKey.keyFromSecret(secret, curve),
      localPaillierKeys: CompoundKey.generatePaillierKeys()
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

    this.curve = options.curve || 'secp256k1';
    this.ec = elliptic.ec(this.curve);

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
    return new CompoundKey().fromOptions(options);
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
   * Returns a compound public key
   */
  get compoundPublic() {
    if(!this.remotePublicKey){
      return null;
    }
    return this.compoundPublicKey.getPublic();
  }

  /**
   * Initializes and returns a prover object, responsible for key exchange protocol @see PaillierProof
   * @returns {PaillierProver}
   */
  startSyncSession() {
    assert(this.localPrivateKey, "The key must be initialized to start a commitment");

    return PaillierProver.fromOptions({
      curve: this.ec,
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
    // remote Q
    const point = syncData.Q;
    // local x
    const key = this.localPrivate;
    // compound Q according to ECDH
    const compound = point.mul(key);

    this.remotePublicKey = this.ec.keyFromPublic(Buffer.from(point.encode(true, 'array')));
    this.remotePrivateCiphertext = syncData.c;
    this.remotePaillierPublicKey = syncData.pk;

    this.compoundPublicKey = this.ec.keyFromPublic(Buffer.from(compound.encode(true, 'array')));
  }

  /**
   * Returns the exact set of data used to finalize this CompoundKey
   * May be used for key duplication and re-initialization
   * @returns {{Q, pk: (null|*), c: (null|*)}}
   */
  extractSyncData() {
    assert(this.compoundPublicKey);

    return {
      Q: this.remotePublicKey.getPublic(),
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
    return Signer.fromOptions({
      message: message,
      compoundKey: this
    });
  }
}
