'use strict';

import BN from 'bn.js';

import {
    decodePoint,
    encodePoint,
    decodeBN,
    encodeBN
} from "../convert";

import { randomBytes } from "../utils";
import { matchCurve } from "../curves";

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

    this.a = new BN(randomBytes(32));
    this.H = this.crypto.g.mul(this.a);
    return this;
  }

  static generate(curve) {
    return new PedersenScheme().generate(curve);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      a: encodeBN(this.a, hex),
      H: encodePoint(this.H, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.a = decodeBN(json.a, hex);
    this.H = decodePoint(this.crypto, json.H, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new PedersenScheme().fromJSON(json, hex);
  }

  getParameters() {
    return this.H;
  }

  commit(message) {
    const x = new BN(message, 16);
    const r = new BN(randomBytes(32));
    const X = this.crypto.g.mul(x);
    const R = this.H.mul(r);

    const C = R.add(X);

    return [ C, r ];
  }

  static verify(curve, params, message, commitment, decommitment) {
    const crypto = matchCurve(curve);

    const H = params;
    const C = commitment;
    const x = new BN(message, 16);
    const r = decommitment;

    return C.eq(crypto.g.mul(x).add(H.mul(r)));
  }
}
