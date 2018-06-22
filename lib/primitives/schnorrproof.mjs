'use strict';

import BN from 'bn.js';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

import { randomBytes, sha256 } from '../utils';

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

    this.t = null;
    this.c = null;
    this.s = null;
  }

  fromOptions(options) {
    this.curve = options.curve;

    this.t = options.t;
    this.c = options.c;
    this.s = options.s;

    return this;
  }

  static fromOptions(options) {
    return new SchnorrProof().fromOptions(options);
  }

  toJSON() {
    return {
      t: Buffer.from(this.t.encode(true)).toString('hex'),
      c: this.c.toString(16),
      s: this.s.toString(16),
    };
  }

  fromJSON(curve, json) {
    this.curve = curve;

    this.t = this.curve.curve.decodePoint(Buffer.from(json.t,'hex'));
    this.c = new BN(json.c, 16);
    this.s = new BN(json.s, 16);

    return this;
  }

  static fromJSON(curve, json) {
    return new SchnorrProof().fromJSON(curve, json);
  }

  /**
   * Initializes the proof from the value of discrete log x
   * The proof states that while publishing a value Q the prover knows a value x such as Q = G^x
   * @param curve - one of pre-set elliptic curves
   * @param x - the value to be proven
   * @returns {SchnorrProof}
   */
  fromSecret(curve, x) {
    this.curve = curve;

    const r = new BN(randomBytes(32).toString('hex'), 16);

    this.t = this.curve.g.mul(r);
    this.c = new BN(sha256(Buffer.from(this.t.encode(true))), 16);
    this.s = this.c.mul(x).iadd(r).umod(this.curve.curve.n);

    return this;
  }

  static fromSecret(curve, x) {
    return new SchnorrProof().fromSecret(curve, x);
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

    return this.curve.g.mul(this.s).eq(this.t.add(Q.mul(c)));
  }
}
