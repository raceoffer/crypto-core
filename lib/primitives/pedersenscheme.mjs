'use strict';

import BN from 'bn.js';

import {
    Field,
    generateMessage
} from "../convert";

import { randomBytes } from "../utils";
import { matchCurve } from "../curves";

import protobuf from 'protobufjs';
import * as proto from './pedersenscheme.json';

const root = protobuf.Root.fromJSON(proto);

export class PedersenScheme extends generateMessage(
  'PedersenScheme', {
    a: [Field.BN],
    h: [Field.Point]
  },
  root
) {
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

  static fromJSON(json, hex) {
    return new PedersenScheme().fromJSON(json, hex);
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
