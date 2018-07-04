'use strict';

import BN from 'bn.js';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

import {
    decodePoint,
    encodePoint,
    decodeBN,
    encodeBN
} from "../convert"

import { randomBytes } from "../utils";
import { matchCurve } from "../curves";

export class PedersenParameters {
  constructor() {
    this.curve = null;
    this.H = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.H = options.H;

    return this;
  }

  static fromOptions(options) {
    return new PedersenParameters().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      H: encodePoint(this.H)
    };
  }

  fromJSON(json) {
    const crypto = matchCurve(json.curve);

    this.curve = json.curve;
    this.H = decodePoint(crypto, json.H);

    return this;
  }

  static fromJSON(json) {
    return new PedersenParameters().fromJSON(json);
  }
}

export class PedersenCommitment {
  constructor() {
    this.curve = null;
    this.C = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.C = options.C;

    return this;
  }

  static fromOptions(options) {
    return new PedersenCommitment().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      C: encodePoint(this.C)
    };
  }

  fromJSON(json) {
    const crypto = matchCurve(json.curve);

    this.curve = json.curve;
    this.C = decodePoint(crypto, json.C);

    return this;
  }

  static fromJSON(json) {
    return new PedersenCommitment().fromJSON(json);
  }
}

export class PedersenDecommitment {
  constructor() {
    this.message = null;
    this.r = null;
  }

  fromOptions(options) {
    this.message = options.message;
    this.r = options.r;

    return this;
  }

  static fromOptions(options) {
    return new PedersenDecommitment().fromOptions(options);
  }

  toJSON() {
    return {
      message: this.message.toString('hex'),
      r: encodeBN(this.r)
    };
  }

  fromJSON(json) {
    this.message = Buffer.from(json.message, 'hex');
    this.r = decodeBN(json.r);

    return this;
  }

  static fromJSON(json) {
    return new PedersenDecommitment().fromJSON(json);
  }
}

export class PedersenScheme {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.a = null;
    this.H = null;
  }

  generate(curve) {
    this.curve = curve;
    this.crypto = matchCurve(this.curve);

    this.a = new BN(randomBytes(32).toString('hex'), 16);
    this.H = this.crypto.g.mul(this.a);
    return this;
  }

  static generate(curve) {
    return new PedersenScheme().generate(curve);
  }

  toJSON() {
    return {
      curve: this.curve,
      a: encodeBN(this.a),
      H: encodePoint(this.H)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.a = decodeBN(json.a);
    this.H = decodePoint(this.crypto, json.H);

    return this;
  }

  static fromJSON(json) {
    return new PedersenScheme().fromJSON(json);
  }

  getParams() {
    return PedersenParameters.fromOptions({
      curve: this.curve,
      H: this.H
    });
  }

  commit(message) {
    const x = new BN(message, 16);
    const r = new BN(randomBytes(32).toString('hex'), 16);
    const X = this.crypto.g.mul(x);
    const R = this.H.mul(r);

    const C = R.add(X);

    return {
      commitment: PedersenCommitment.fromOptions({
        curve: this.curve,
        C: C
      }),
      decommitment: PedersenDecommitment.fromOptions({
        message: message,
        r: r
      })
    };
  }

  static verify(params, commitment, decommitment) {
    const crypto = matchCurve(params.curve);

    const H = params.H;
    const C = commitment.C;
    const x = new BN(decommitment.message, 16);
    const r = decommitment.r;

    return C.eq(crypto.g.mul(x).add(H.mul(r)));
  }
}
