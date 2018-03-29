const ec = require('elliptic').ec('secp256k1');
const assert = require("assert");
const BigInteger = require("jsbn").BigInteger;

const PedersenScheme = require('./pedersenscheme');

function PaillierVerifier() {
  if(!(this instanceof PaillierVerifier))
    return new PaillierVerifier();

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

PaillierVerifier.prototype.fromOptions = function fromOptions(options) {
  this.pk = options.pk;
  this.c = options.c;
  this.Q = options.Q;
  this.pedersenScheme = options.pedersenScheme;
  this.remoteParams = options.remoteParams;

  return this;
};

PaillierVerifier.fromOptions = function fromOptions(options) {
  return new PaillierVerifier().fromOptions(options);
};

/**
 * Computes (a,b) commitment and stores decommitment until a remote alpha commitment is received
 * @returns {{c: string, s: (*|commitment|{C})}}
 */
PaillierVerifier.prototype.getCommitment = function getCommitment() {
  this.a = ec.genKeyPair().getPrivate();
  this.b = ec.genKeyPair().getPrivate();

  const c = this.pk.add(
    this.pk.mult(
      this.c,
      new BigInteger(this.a.toString(16), 16)),
    this.pk.encrypt(
      new BigInteger(this.b.toString(16), 16)));

  const cmt = this.pedersenScheme.commit(JSON.stringify({
    a: this.a.toString(16),
    b: this.b.toString(16)
  }));

  this.sDecommitment = cmt.decommitment;

  return {
    c: c.toString(16),
    s: cmt.commitment
  }
};

/**
 * Saves alpha commitment and reveals (a,b) decommitment
 * @param commitment
 * @returns {null|*}
 */
PaillierVerifier.prototype.processCommitment = function processCommitment(commitment) {
  this.aCommitment = commitment.a;

  return this.sDecommitment;
};

/**
 * Verifies alpha decommitment and proof-of-encryption, then returns verified synchronization parameters
 * @param decommitment
 * @returns {{Q: *, pk: *, c: *}}
 */
PaillierVerifier.prototype.processDecommitment = function processDecommitment(decommitment) {
  assert(PedersenScheme.verify(this.remoteParams, this.aCommitment, decommitment));

  const Q = ec.curve.decodePoint(Buffer.from(decommitment.message,'hex'));

  assert(this.Q.mul(this.a).add(ec.g.mul(this.b)).eq(Q));

  return {
    Q: this.Q,
    pk: this.pk,
    c: this.c
  }
};

module.exports = PaillierVerifier;
