'use strict';

import assert from 'assert';

import BN from 'bn.js';
import HmacDRBG from 'hmac-drbg';
import Signature from 'elliptic/lib/elliptic/ec/signature';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { SchnorrProof } from '../schnorrproof';
import {
  PedersenScheme,
  PedersenParameters,
  PedersenCommitment,
  PedersenDecommitment
} from '../pedersenscheme';

import { matchCurve } from '../../curves';
import { randomBytes } from "../../utils";

import {
  toJSON,
  fromJSON,
  encodePoint,
  decodePoint,
  encodeBigInteger,
  decodeBigInteger,
  decodeBN,
  encodeBN,
  toBigInteger,
  toBN,
  decodeBuffer,
  encodeBuffer
} from "../../convert";

import { PaillierPublicKey, PaillierSecretKey } from "./paillierkeys";

export class PartialSignature {
  constructor() {
    this.e = null;
  }

  fromOptions(options) {
    this.e = options.e;

    return this;
  }

  static fromOptions(options) {
    return new PartialSignature().fromOptions(options);
  }

  toJSON() {
    return {
      e: encodeBigInteger(this.e)
    };
  }

  fromJSON(json) {
    this.e = decodeBigInteger(json.e);

    return this;
  }

  static fromJSON(json) {
    return new PartialSignature().fromJSON(json);
  }
}

export class Signer {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.localPrivateKey = null;
    this.localPaillierPrivateKey = null;
    this.remotePaillierPublicKey = null;
    this.remotePrivateCiphertext = null;
    this.message = null;

    // local entropy multiplicative share (temporary ecdsa private key)
    this.k = null;
    // compound ECDH-exchanged public entropy
    this.R = null;
    // R.x
    this.r = null;

    // Pedersen commitment\decommitment scheme, initialized with random parameters
    this.pedersenScheme = null;
    // Pedersen scheme parameters, received from the remote participant
    this.remoteParams = null;
    // R commitment from the remote participant awaiting for decommitment to be received
    this.remoteCommitment = null;
    // local R decommitment awaiting for the remote commitment to be received
    this.localDecommitment = null;
  }

  generateK(privateKey, message) {
    const key = privateKey;
    const msg = this.crypto._truncateToN(new BN(message, 16));

    const bytes = this.crypto.n.byteLength();
    const bkey = key.toArray('be', bytes);

    const nonce = msg.toArray('be', bytes);

    const drbg = new HmacDRBG({
      hash: this.crypto.hash,
      entropy: bkey,
      nonce: nonce,
      pers: null,
      persEnc: 'utf8'
    });

    const ns1 = this.crypto.n.sub(new BN(1));

    let k = null;
    do {
      k = new BN(drbg.generate(bytes));
      k = this.crypto._truncateToN(k, true);
    } while (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0);

    return k;
  }

  /**
   * Signer initialization. Generates a random entropy fragment k
   * @param options @see CompoundKey.prototype.startSign
   * @returns {Signer}
   */
  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = options.localPrivateKey;
    this.localPaillierPrivateKey = options.localPaillierPrivateKey;
    this.remotePaillierPublicKey = options.remotePaillierPublicKey;
    this.remotePrivateCiphertext = options.remotePrivateCiphertext;
    this.message = options.message;

    this.pedersenScheme = PedersenScheme.generate(this.curve);

    this.k = this.generateK(this.localPrivateKey.priv, this.message);

    return this;
  }

  /**
   * Static version of the above
   * @param options
   * @returns {Signer}
   */
  static fromOptions(options) {
    return new Signer().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      localPrivateKey: encodeBN(this.localPrivateKey.priv),
      localPaillierPrivateKey: toJSON(this.localPaillierPrivateKey),
      remotePaillierPublicKey: toJSON(this.remotePaillierPublicKey),
      remotePrivateCiphertext: encodeBigInteger(this.remotePrivateCiphertext),
      message: encodeBuffer(this.message),
      k: encodeBN(this.k),
      R: encodePoint(this.R),
      r: encodeBN(this.r),
      pedersenScheme: toJSON(this.pedersenScheme),
      remoteParams: toJSON(this.remoteParams),
      remoteCommitment: toJSON(this.remoteCommitment),
      localDecommitment: toJSON(this.localDecommitment)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = this.crypto.keyFromPrivate(decodeBN(json.localPrivateKey));
    this.localPaillierPrivateKey = fromJSON(PaillierSecretKey, json.localPaillierPrivateKey);
    this.remotePaillierPublicKey = fromJSON(PaillierPublicKey, json.remotePaillierPublicKey);
    this.remotePrivateCiphertext = decodeBigInteger(json.remotePrivateCiphertext);
    this.message = decodeBuffer(json.message);

    this.k = decodeBN(json.k);
    this.R = decodePoint(this.crypto, json.R);
    this.r = decodeBN(json.r);

    this.pedersenScheme = fromJSON(PedersenScheme, json.pedersenScheme);
    this.remoteParams = fromJSON(PedersenParameters, json.remoteParams);
    this.remoteCommitment = fromJSON(PedersenCommitment, json.remoteCommitment);
    this.localDecommitment = fromJSON(PedersenDecommitment, json.localDecommitment);

    return this;
  }

  static fromJSON(json) {
    return new Signer().fromJSON(json);
  }

  /**
   * Computes an entropy commitment, consisting of local R value and proof of a discrete logarithm for R
   * Also contains public parameters of local Pedersen scheme
   * @returns {{params: {H}, entropy: (commitment|{C})}}
   */
  createCommitment() {
    assert(this.k, "The key must be initialized to create a commitment");

    const R = this.crypto.g.mul(this.k);
    const proof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.k
    });

    const data = {
      R: encodePoint(R),
      proof: toJSON(proof)
    };

    const cmt = this.pedersenScheme.commit(Buffer.from(JSON.stringify(data), 'ascii'));

    // A decommitment needs to be saved until we receive a remote commitment
    this.localDecommitment = cmt.decommitment;

    return {
      params: this.pedersenScheme.getParams(),
      commitment: cmt.commitment
    };
  }

  /**
   * Saves a remote commitment and public parameters and publishes decommitment
   * @param commitment - remote commitment to be saved and lately verified
   * @returns {null|*}
   */
  processCommitment(commitment) {
    this.remoteParams = commitment.params;
    this.remoteCommitment = commitment.commitment;

    return this.localDecommitment;
  }

  /**
   * Verifies decommitment according to a previously saved commitmnet.
   * Computes a ECDH shared public entropy and r parameter
   * @param decommitment - a remote decommitment
   */
  processDecommitment(decommitment) {
    // Verifies that the decommitment matches a previously published commitment
    assert(PedersenScheme.verify(this.remoteParams, this.remoteCommitment, decommitment));

    const data = JSON.parse(decommitment.message.toString('ascii'));

    const R = decodePoint(this.crypto, data.R);
    const proof = fromJSON(SchnorrProof, data.proof);

    // Verifies a Schnorr proof of knowledge of the discrete log
    assert(proof.verify(R));

    this.R = R.mul(this.k);
    this.r = this.R.getX().umod(this.crypto.n);
  }

  /**
   * Computes a paillier-encrypted (with other party's paillier public key) signature fragment
   * A degree of ec.n is added to the ciphertext in order to prevent factorization
   * @returns {{e}}
   */
  computePartialSignature() {
    assert(this.r && this.R);

    const p = this.remotePaillierPublicKey;
    const c = this.remotePrivateCiphertext;
    const x = this.localPrivateKey.priv;
    const m = this.crypto._truncateToN(new BN(this.message, 16));

    const t = new BN(randomBytes(32).toString('hex'), 16);

    const a = this.k.invm(this.crypto.n).mul(x).mul(this.r).umod(this.crypto.n);
    const b = this.k.invm(this.crypto.n).mul(m).umod(this.crypto.n).add(t.mul(this.crypto.n));
    const e = p.add(p.mult(c, toBigInteger(a)), p.encrypt(toBigInteger(b)));

    return PartialSignature.fromOptions({ e: e });
  }

  finalizeSignature(s) {
    const d = toBN(this.localPaillierPrivateKey.decrypt(s.e));

    let S = this.k.invm(this.crypto.n).mul(d).umod(this.crypto.n);

    let recoveryParam = (this.R.getY().isOdd() ? 1 : 0) | (this.R.getX().cmp(this.r) !== 0 ? 2 : 0);

    if (S.cmp(this.crypto.nh) > 0) {
      S = this.crypto.n.sub(S);
      recoveryParam ^= 1;
    }

    return new Signature({ r: this.r, s: S, recoveryParam: recoveryParam });
  }
}
