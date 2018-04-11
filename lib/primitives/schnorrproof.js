const ec = require('elliptic').ec('secp256k1');
const BN = require('bn.js');

const Utils = require('../utils');

/**
 * Schnorr non-interactoive zero knowledge proof of knowledge of discrete log
 * @param options.t
 * @param options.c
 * @param options.s
 * @returns {SchnorrProof}
 * @constructor
 */
function SchnorrProof() {
  this.t = null;
  this.c = null;
  this.s = null;
}

SchnorrProof.prototype.fromOptions = function fromOptions(options) {
  this.t = options.t;
  this.c = options.c;
  this.s = options.s;

  return this;
};

SchnorrProof.fromOptions = function fromOptions(options) {
  return new SchnorrProof().fromOptions(options);
};

SchnorrProof.prototype.toJSON = function toJSON() {
  return {
    t: Buffer.from(this.t.encode(true)).toString('hex'),
    c: this.c.toString(16),
    s: this.s.toString(16),
  }
};

SchnorrProof.prototype.fromJSON = function fromJSON(json) {
  this.t = ec.curve.decodePoint(Buffer.from(json.t,'hex'));
  this.c = new BN(json.c, 16);
  this.s = new BN(json.s, 16);

  return this;
};

SchnorrProof.fromJSON = function fromJSON(json) {
  return new SchnorrProof().fromJSON(json);
};

/**
 * Initializes the proof from the value of discrete log x
 * The proof states that while publishing a value Q the prover knows a value x such as Q = G^x
 * @param x - the value to be proven
 * @returns {SchnorrProof}
 */
SchnorrProof.prototype.fromSecret = function fromSecret(x) {
  const r = ec.genKeyPair().getPrivate();

  this.t = ec.g.mul(r);
  this.c = new BN(Utils.sha256(Buffer.from(this.t.encode(true))), 16);
  this.s = this.c.mul(x).iadd(r).umod(ec.n);

  return this;
};

SchnorrProof.fromSecret = function fromSecret(x) {
  return new SchnorrProof().fromSecret(x);
};

/**
 * Verifies the proof according to value Q
 * @param Q - ec point assumed to equal G^x
 * @returns {boolean}
 */
SchnorrProof.prototype.verify = function verify(Q) {
  const c = new BN(Utils.sha256(Buffer.from(this.t.encode(true))), 16);
  if(c.cmp(this.c) !== 0) {
    return false;
  }

  return ec.g.mul(this.s).eq(this.t.add(Q.mul(c)));
};

module.exports = SchnorrProof;
