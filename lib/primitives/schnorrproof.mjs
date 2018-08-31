'use strict';

import BN from 'bn.js';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

import { randomBytes, sha256 } from '../utils';
import { matchCurve } from "../curves";

import {
  decodePoint,
  encodePoint,
  decodeBN,
  encodeBN
} from "../convert";

/**
 * Schnorr non-interactoive zero knowledge proof of knowledge of discrete log
 * @param options.t
 * @param options.c
 * @param options.s
 * @returns {SchnorrProof}
 * @constructor
 */
export class SchnorrProof {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.t = null;
    this.c = null;
    this.s = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    const x = options.x;

    const r = new BN(randomBytes(32));

    this.t = this.crypto.g.mul(r);
    this.c = new BN(sha256(Buffer.from(this.t.encode(true))), 16);
    this.s = this.c.mul(x).iadd(r).umod(this.crypto.curve.n);

    return this;
  }

  static fromOptions(options) {
    return new SchnorrProof().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      t: encodePoint(this.t, hex),
      c: encodeBN(this.c, hex),
      s: encodeBN(this.s, hex),
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.t = decodePoint(this.crypto, json.t, hex);
    this.c = decodeBN(json.c, hex);
    this.s = decodeBN(json.s, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new SchnorrProof().fromJSON(json, hex);
  }

  /**
   * Verifies the proof according to value Q
   * @param Q - ec point assumed to equal G^x
   * @returns {boolean}
   */
  verify(Q) {
    const c = new BN(sha256(Buffer.from(this.t.encode(true))), 16);
    if(c.cmp(this.c) !== 0) {
      return false;
    }

    return this.crypto.g.mul(this.s).eq(this.t.add(Q.mul(c)));
  }
}
