const ec = require('elliptic').ec('secp256k1');
const BN = require('bn.js');
const jspaillier = require('jspaillier');
const assert = require("assert");
const BigInteger = require("jsbn").BigInteger;

const PedersenScheme = require('./pedersenscheme');

function Prover() {
  if(!(this instanceof Prover))
    return new Prover();

  this.pk = null;
  this.sk = null;
  this.x = null;

  // Pedersen commitment\decommitment scheme, initialized with random parameters
  this.pedersenScheme = PedersenScheme.generate();

  // Pedersen scheme parameters, received from the remote participant
  this.remoteParams = null;

  // (Q,pk,c) commitment from the remote participant awaiting for decommitment to be received
  this.iCommitment = null;
  // local (Q,pk,c) decommitment awaiting for the remote commitment to be received
  this.iDecommitment = null;

  // (a,b) commitment from the remote participant awaiting for decommitment to be received
  this.sCommitment = null;
  // ;pcal alpha decommitment awaiting for the remote commitment to be received
  this.aDecommitment = null;
}

Prover.prototype.fromOptions = function fromOptions(options) {
  this.pk = options.pk;
  this.sk = options.sk;
  this.x = options.x;

  return this;
};

Prover.fromOptions = function fromOptions(options) {
  return new Prover().fromOptions(options);
};

/**
 * Computes a Pedersen commitment of paillier public key, local public key and paillier encryption of local private key
 * Decommitment is stored until remote commitment is received
 * @returns {{params: {H}, i: (commitment|{C})}}
 */
Prover.prototype.getInitialCommitment = function getInitialCommitment() {
  const data = {
    pk: {
      bits: this.pk.bits,
      n: this.pk.n.toString(16)
    },
    Q: Buffer.from(ec.g.mul(this.x).encode(true)).toString('hex'),
    c: this.pk.encrypt(new BigInteger(this.x.toString(16), 16)).toString(16),
  };

  const cmt = this.pedersenScheme.commit(JSON.stringify(data));

  this.iDecommitment = cmt.decommitment;

  return {
    params: this.pedersenScheme.getParams(),
    i: cmt.commitment
  };
};

/**
 * Saves a remote commitment and public parameters and publishes decommitment
 * @param commitment
 * @returns {null|*}
 */
Prover.prototype.processInitialCommitment = function processInitialCommitment(commitment) {
  this.iCommitment = commitment.i;
  this.remoteParams = commitment.params;

  return this.iDecommitment;
};

/**
 * Initializes a Verifier object, responsible for interactive verification of the proof-of-paillier-encryption
 * @see https://eprint.iacr.org/2017/552.pdf for details on Zk proof-of-encryption
 * @param decommitment
 * @returns {Verifier}
 */
Prover.prototype.processInitialDecommitment = function processInitialDecommitment(decommitment) {
  assert(PedersenScheme.verify(this.remoteParams,this.iCommitment,decommitment));

  const data = JSON.parse(decommitment.message);

  const options = {
    pedersenScheme: this.pedersenScheme,
    remoteParams: this.remoteParams,
    pk: new jspaillier.publicKey(data.pk.bits, new BigInteger(data.pk.n, 16)),
    c: new BigInteger(data.c, 16),
    Q: ec.curve.decodePoint(Buffer.from(data.Q, 'hex'))
  };

  return Verifier.fromOptions(options);
};

/**
 * Computes alpha commitment nad saves (a,b) commitment for further verification
 * @param commitment
 * @returns {{a: (commitment|{C})}}
 */
Prover.prototype.processCommitment = function processCommitment(commitment) {
  this.alpha = new BN(this.sk.decrypt(new BigInteger(commitment.c, 16)).toString(16), 16);

  this.sCommitment = commitment.s;

  const Q = ec.g.mul(this.alpha);

  const cmt = this.pedersenScheme.commit(Buffer.from(Q.encode(true)).toString('hex'));

  // decommitment needs to be saved locally
  this.aDecommitment = cmt.decommitment;

  return {
    a: cmt.commitment
  }
};

/**
 * Reveals (alpha) decommitment based on correctness of (a,b) decommitment
 * @param decommitment
 * @returns {null|*}
 */
Prover.prototype.processDecommitment = function processDecommitment(decommitment) {
  assert(PedersenScheme.verify(this.remoteParams,this.sCommitment,decommitment));

  const message = JSON.parse(decommitment.message);

  const a = new BN(message.a, 16);
  const b = new BN(message.b, 16);

  const alpha = this.x.mul(a).iadd(b);

  assert(this.alpha.cmp(alpha) === 0);

  return this.aDecommitment;
};

function Verifier() {
  if(!(this instanceof Verifier))
    return new Verifier();

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

Verifier.prototype.fromOptions = function fromOptions(options) {
  this.pk = options.pk;
  this.c = options.c;
  this.Q = options.Q;
  this.pedersenScheme = options.pedersenScheme;
  this.remoteParams = options.remoteParams;

  return this;
};

Verifier.fromOptions = function fromOptions(options) {
  return new Verifier().fromOptions(options);
};

/**
 * Computes (a,b) commitment and stores decommitment until a remote alpha commitment is received
 * @returns {{c: string, s: (*|commitment|{C})}}
 */
Verifier.prototype.getCommitment = function getCommitment() {
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
Verifier.prototype.processCommitment = function processCommitment(commitment) {
  this.aCommitment = commitment.a;

  return this.sDecommitment;
};

/**
 * Verifies alpha decommitment and proof-of-encryption, then returns verified synchronization parameters
 * @param decommitment
 * @returns {{Q: *, pk: *, c: *}}
 */
Verifier.prototype.processDecommitment = function processDecommitment(decommitment) {
  assert(PedersenScheme.verify(this.remoteParams,this.aCommitment,decommitment));

  const Q = ec.curve.decodePoint(Buffer.from(decommitment.message,'hex'));

  assert(this.Q.mul(this.a).add(ec.g.mul(this.b)).eq(Q));

  return {
    Q: this.Q,
    pk: this.pk,
    c: this.c
  }
};

module.exports = {
  Prover,
  Verifier
};
