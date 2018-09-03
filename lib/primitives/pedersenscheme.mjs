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

import { Root } from 'protobufjs';
import * as proto from './pedersenscheme.json';

const root = Root.fromJSON(proto);

export class PedersenScheme {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.a = null;
    this.h = null;
  }

  generate(curve) {
    this.curve = curve;
    this.crypto = matchCurve(this.curve);

    this.a = new BN(randomBytes(32));
    this.h = this.crypto.g.mul(this.a);
    return this;
  }

  static generate(curve) {
    return new PedersenScheme().generate(curve);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      a: encodeBN(this.a, hex),
      h: encodePoint(this.h, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.a = decodeBN(json.a, hex);
    this.h = decodePoint(this.crypto, json.h, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new PedersenScheme().fromJSON(json, hex);
  }

  toBytes() {
    const type = root.lookupType('PedersenScheme');
    return new Buffer(type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const type = root.lookupType('PedersenScheme');
    return this.fromJSON(type.decode(bytes));
  }

  static fromBytes(bytes) {
    return new PedersenScheme().fromBytes(bytes);
  }

  getParameters() {
    return this.h;
  }

  commit(message) {
    const x = new BN(message, 16);
    const r = new BN(randomBytes(32));
    const X = this.crypto.g.mul(x);
    const R = this.h.mul(r);

    const c = R.add(X);

    return {
      commitment: c,
      decommitment: r
    };
  }

  static verify(curve, parameters, message, commitment, decommitment) {
    const crypto = matchCurve(curve);

    const H = parameters;
    const C = commitment;
    const x = new BN(message, 16);
    const r = decommitment;

    return C.eq(crypto.g.mul(x).add(H.mul(r)));
  }
}
