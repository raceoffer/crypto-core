'use strict';

const BN = require('bn.js');

const { Buffer } = require('buffer');

const { randomBytes, sha256 } = require('../utils');
const { matchCurve } = require('../curves');

const { Field, generateMessage } = require('../convert');

const { Root } = require('protobufjs');
const proto = require('./schnorrproof.json');

const root = Root.fromJSON(proto);

/**
 * Schnorr non-interactoive zero knowledge proof of knowledge of discrete log
 * @param options.t
 * @param options.c
 * @param options.s
 * @returns {SchnorrProof}
 * @constructor
 */
class SchnorrProof extends generateMessage(
  'SchnorrProof', {
    t: [Field.Point],
    c: [Field.BN],
    s: [Field.BN]
  },
  root
) {
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

  static fromJSON(json, hex) {
    return new SchnorrProof().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new SchnorrProof().fromBytes(bytes);
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

module.exports = {
  SchnorrProof
};
