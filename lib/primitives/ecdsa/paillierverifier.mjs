'use strict';

import assert from 'assert';

import BN from 'bn.js';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

import {
  PedersenScheme,
  PedersenParameters,
  PedersenCommitment,
  PedersenDecommitment
} from '../pedersenscheme';

import { randomBytes } from '../../utils';
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
  toBigInteger
} from "../../convert";

import { PaillierPublicKey } from "./paillierkeys";

export class SCommitment {
  constructor() {
    this.c = null;
    this.s = null;
  }

  fromOptions(options) {
    this.c = options.c;
    this.s = options.s;

    return this;
  }

  static fromOptions(options) {
    return new SCommitment().fromOptions(options);
  }

  toJSON() {
    return {
      c: encodeBigInteger(this.c),
      s: toJSON(this.s)
    };
  }

  fromJSON(json) {
    this.c = decodeBigInteger(json.c);
    this.s = fromJSON(PedersenCommitment, json.s);

    return this;
  }

  static fromJSON(json) {
    return new SCommitment().fromJSON(json);
  }
}

export class SyncData {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.Q = null;
    this.pk = null;
    this.c = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.Q = options.Q;
    this.pk = options.pk;
    this.c = options.c;

    return this;
  }

  static fromOptions(options) {
    return new SyncData().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      Q: encodePoint(this.Q),
      pk: toJSON(this.pk),
      c: encodeBigInteger(this.c),
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.Q = decodePoint(this.crypto, json.Q);
    this.pk = fromJSON(PaillierPublicKey, json.pk);
    this.c = decodeBigInteger(json.c);

    return this;
  }

  static fromJSON(json) {
    return new SyncData().fromJSON(json);
  }
}

export class PaillierVerifier {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.pk = null;
    this.c = null;
    this.Q = null;

    this.a = null;
    this.b = null;

    this.pedersenScheme = null;
    this.aCommitment = null;
    this.sDecommitment = null;

    this.remoteParams = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.pk = options.pk;
    this.c = options.c;
    this.Q = options.Q;
    this.pedersenScheme = options.pedersenScheme;
    this.remoteParams = options.remoteParams;

    return this;
  }

  static fromOptions(options) {
    return new PaillierVerifier().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      pk: toJSON(this.pk),
      c: encodeBigInteger(this.c),
      Q: encodePoint(this.Q),
      a: encodeBN(this.a),
      b: encodeBN(this.b),
      pedersenScheme: toJSON(this.pedersenScheme),
      remoteParams: toJSON(this.remoteParams),
      aCommitment: toJSON(this.aCommitment),
      sDecommitment: toJSON(this.sDecommitment)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.pk = fromJSON(PaillierPublicKey, json.pk);
    this.c = decodeBigInteger(json.c);
    this.Q = decodePoint(this.crypto, json.Q);
    this.a = decodeBN(json.a);
    this.b = decodeBN(json.b);
    this.pedersenScheme = fromJSON(PedersenScheme, json.pedersenScheme);
    this.remoteParams = fromJSON(PedersenParameters, json.remoteParams);
    this.aCommitment = fromJSON(PedersenCommitment, json.aCommitment);
    this.sDecommitment = fromJSON(PedersenDecommitment, json.sDecommitment);

    return this;
  }

  static fromJSON(json) {
    return new PaillierVerifier().fromJSON(json);
  }

  /**
   * Computes (a,b) commitment and stores decommitment until a remote alpha commitment is received
   * @returns {{c: string, s: (*|commitment|{C})}}
   */
  createCommitment() {
    this.a = new BN(randomBytes(32).toString('hex'), 16);
    this.b = new BN(randomBytes(32).toString('hex'), 16);

    const c = this.pk.add(
      this.pk.mult(
        this.c,
        toBigInteger(this.a)),
      this.pk.encrypt(
        toBigInteger(this.b)));

    const cmt = this.pedersenScheme.commit(Buffer.from(JSON.stringify({
      a: encodeBN(this.a),
      b: encodeBN(this.b)
    }), 'ascii'));

    this.sDecommitment = cmt.decommitment;

    return SCommitment.fromOptions({
      c: c,
      s: cmt.commitment
    });
  }

  /**
   * Saves alpha commitment and reveals (a,b) decommitment
   * @param commitment
   * @returns {null|*}
   */
  processCommitment(commitment) {
    this.aCommitment = commitment.a;

    return this.sDecommitment;
  }

  /**
   * Verifies alpha decommitment and proof-of-encryption, then returns verified synchronization parameters
   * @param decommitment
   * @returns {{Q: *, pk: *, c: *}}
   */
  processDecommitment(decommitment) {
    assert(PedersenScheme.verify(this.remoteParams, this.aCommitment, decommitment));

    const Q = this.crypto.curve.decodePoint(decommitment.message);

    assert(this.Q.mul(this.a).add(this.crypto.g.mul(this.b)).eq(Q));

    return SyncData.fromOptions({
      curve: this.curve,
      Q: this.Q,
      pk: this.pk,
      c: this.c
    });
  }
}
