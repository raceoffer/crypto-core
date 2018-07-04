'use strict';

import assert from 'assert';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import {
  PedersenScheme,
  PedersenParameters,
  PedersenCommitment,
  PedersenDecommitment
} from '../pedersenscheme';
import { PaillierVerifier } from './paillierverifier';
import { matchCurve } from "../../curves";

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
  toBN
} from "../../convert";
import { PaillierPublicKey, PaillierSecretKey } from "./paillierkeys";

export class PaillierProver {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.pk = null;
    this.sk = null;
    this.x = null;

    // Pedersen commitment\decommitment scheme, initialized with random parameters
    this.pedersenScheme = null;

    // Pedersen scheme parameters, received from the remote participant
    this.remoteParams = null;

    // (Q,pk,c) commitment from the remote participant awaiting for decommitment to be received
    this.iCommitment = null;
    // local (Q,pk,c) decommitment awaiting for the remote commitment to be received
    this.iDecommitment = null;

    // (a,b) commitment from the remote participant awaiting for decommitment to be received
    this.sCommitment = null;
    // ;pcal alpha decommitment awaiting for the remote commitment to be received
    this.aDecommitment = null;

    this.alpha = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.pk = options.pk;
    this.sk = options.sk;
    this.x = options.x;
    this.pedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new PaillierProver().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      pk: toJSON(this.pk),
      sk: toJSON(this.sk),
      x: encodeBN(this.x),
      alpha: decodeBN(this.alpha),
      pedersenScheme: toJSON(this.pedersenScheme),
      remoteParams: toJSON(this.remoteParams),
      iCommitment: toJSON(this.iCommitment),
      iDecommitment: toJSON(this.iDecommitment),
      sCommitment: toJSON(this.sCommitment),
      aDecommitment: toJSON(this.aDecommitment)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.pk = fromJSON(PaillierPublicKey, json.pk);
    this.sk = fromJSON(PaillierSecretKey, json.sk);
    this.x = decodeBN(json.x);
    this.alpha = decodeBN(json.alpha);
    this.pedersenScheme = fromJSON(PedersenScheme, json.pedersenScheme);
    this.remoteParams = fromJSON(PedersenParameters, json.remoteParams);
    this.iCommitment = fromJSON(PedersenCommitment, json.iCommitment);
    this.iDecommitment = fromJSON(PedersenDecommitment, json.iDecommitment);
    this.sCommitment = fromJSON(PedersenCommitment, json.sCommitment);
    this.aDecommitment = fromJSON(PedersenDecommitment, json.aDecommitment);

    return this;
  }

  static fromJSON(json) {
    return new PaillierProver().fromJSON(json);
  }

  /**
   * Computes a Pedersen commitment of paillier public key, local public key and paillier encryption of local private key
   * Decommitment is stored until remote commitment is received
   * @returns {{params: {H}, i: (commitment|{C})}}
   */
  createInitialCommitment() {
    const Q = this.crypto.g.mul(this.x);
    const c = this.pk.encrypt(toBigInteger(this.x));

    const data = {
      pk: toJSON(this.pk),
      Q: encodePoint(Q),
      c: encodeBigInteger(c)
    };

    const cmt = this.pedersenScheme.commit(Buffer.from(JSON.stringify(data), 'ascii'));

    this.iDecommitment = cmt.decommitment;

    return {
      params: this.pedersenScheme.getParams(),
      i: cmt.commitment
    };
  }

  /**
   * Saves a remote commitment and public parameters and publishes decommitment
   * @param commitment
   * @returns {null|*}
   */
  processInitialCommitment(commitment) {
    this.iCommitment = commitment.i;
    this.remoteParams = commitment.params;

    return this.iDecommitment;
  }

  /**
   * Initializes a Verifier object, responsible for interactive verification of the proof-of-paillier-encryption
   * @see https://eprint.iacr.org/2017/552.pdf for details on Zk proof-of-encryption
   * @param decommitment
   * @returns {PaillierVerifier}
   */
  processInitialDecommitment(decommitment) {
    assert(PedersenScheme.verify(this.remoteParams, this.iCommitment, decommitment));

    const data = JSON.parse(decommitment.message.toString('ascii'));

    const pk = fromJSON(PaillierPublicKey, data.pk);
    const c = decodeBigInteger(data.c);
    const Q = decodePoint(this.crypto, data.Q);

    return PaillierVerifier.fromOptions({
      curve: this.curve,
      pedersenScheme: this.pedersenScheme,
      remoteParams: this.remoteParams,
      pk: pk,
      c: c,
      Q: Q
    });
  }

  /**
   * Computes alpha commitment nad saves (a,b) commitment for further verification
   * @param commitment
   * @returns {{a: (commitment|{C})}}
   */
  processCommitment(commitment) {
    this.alpha = toBN(this.sk.decrypt(commitment.c));

    this.sCommitment = commitment.s;

    const Q = this.crypto.g.mul(this.alpha);

    const cmt = this.pedersenScheme.commit(Buffer.from(Q.encode(true)));

    // decommitment needs to be saved locally
    this.aDecommitment = cmt.decommitment;

    return {
      a: cmt.commitment
    };
  }

  /**
   * Reveals (alpha) decommitment based on correctness of (a,b) decommitment
   * @param decommitment
   * @returns {null|*}
   */
  processDecommitment(decommitment) {
    assert(PedersenScheme.verify(this.remoteParams, this.sCommitment, decommitment));

    const message = JSON.parse(decommitment.message.toString('ascii'));

    const a = decodeBN(message.a);
    const b = decodeBN(message.b);

    const alpha = this.x.mul(a).iadd(b);

    assert(this.alpha.cmp(alpha) === 0);

    return this.aDecommitment;
  }
}
