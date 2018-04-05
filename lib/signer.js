const assert = require("assert");
const ec = require('elliptic').ec('secp256k1');
const BN = require('bn.js');

const HmacDRBG = require('hmac-drbg');
const Signature = require('elliptic/lib/elliptic/ec/signature');
const BigInteger = require("jsbn").BigInteger;

const SchnorrProof = require('./schnorrproof');
const PedersenScheme = require('./pedersenscheme');

function Signer() {
  // Pedersen commitment\decommitment scheme, initialized with random parameters
  this.pedersenScheme = null;
  this.compoundKey = null;
  this.message = null;

  // local entropy multiplicative share (temporary ecdsa private key)
  this.k = null;
  // compound ECDH-exchanged public entropy
  this.R = null;
  // R.x
  this.r = null;

  // Pedersen scheme parameters, received from the remote participant
  this.remoteParams = null;
  // R commitment from the remote participant awaiting for decommitment to be received
  this.remoteCommitment = null;
  // local R decommitment awaiting for the remote commitment to be received
  this.localDecommitment = null;
}

/**
 * Signer initialization. Generates a random entropy fragment k
 * @param options @see CompoundKey.prototype.startSign
 * @returns {Signer}
 */
Signer.prototype.fromOptions = function fromOptions(options) {
  assert(options.compoundKey,"A private keyring is required");

  this.compoundKey = options.compoundKey;
  this.pedersenScheme = PedersenScheme.generate();
  this.message = options.message;

  const key = this.compoundKey.getPrivateKey();
  const msg = ec._truncateToN(new BN(this.message, 16));

  const bytes = ec.n.byteLength();
  const bkey = key.toArray('be', bytes);

  const nonce = msg.toArray('be', bytes);

  const drbg = new HmacDRBG({
    hash: ec.hash,
    entropy: bkey,
    nonce: nonce,
    pers: null,
    persEnc: 'utf8'
  });

  const ns1 = ec.n.sub(new BN(1));

  do {
    this.k = new BN(drbg.generate(bytes));
    this.k = ec._truncateToN(this.k, true);
  } while (this.k.cmpn(1) <= 0 || this.k.cmp(ns1) >= 0);

  return this;
};

/**
 * Static version of the above
 * @param options
 * @returns {Signer}
 */
Signer.fromOptions = function fromOptions(options) {
  return new Signer().fromOptions(options);
};

/**
 * Computes an entropy commitment, consisting of local R value and proof of a discrete logarithm for R
 * Also contains public parameters of local Pedersen scheme
 * @returns {{params: {H}, entropy: (commitment|{C})}}
 */
Signer.prototype.createEntropyCommitment = function createEntropyCommitment() {
  assert(this.k, "The key must be initialized to create a commitment");

  const data = {
    R: Buffer.from(ec.g.mul(this.k).encode(true)).toString('hex'),
    proof: SchnorrProof.fromSecret(this.k).toJSON()
  };

  const cmt = this.pedersenScheme.commit(JSON.stringify(data));

  // A decommitment needs to be saved until we receive a remote commitment
  this.localDecommitment = cmt.decommitment;

  return {
    params: this.pedersenScheme.getParams(),
    entropy: cmt.commitment
  }
};

/**
 * Saves a remote commitment and public parameters and publishes decommitment
 * @param commitment - remote commitment to be saved and lately verified
 * @returns {null|*}
 */
Signer.prototype.processEntropyCommitment = function processEntropyCommitment(commitment) {
  this.remoteParams = commitment.params;
  this.remoteCommitment = commitment.entropy;

  return this.localDecommitment;
};

/**
 * Verifies decommitment according to a previously saved commitmnet.
 * Computes a ECDH shared public entropy and r parameter
 * @param decommitment - a remote decommitment
 */
Signer.prototype.processEntropyDecommitment = function processEntropyDecommitment(decommitment) {
  // Verifies that the decommitment matches a previously published commitment
  assert(PedersenScheme.verify(this.remoteParams,this.remoteCommitment,decommitment));

  const data = JSON.parse(decommitment.message);

  assert(data.R);

  const point = ec.curve.decodePoint(Buffer.from(data.R,'hex'));

  // Verifies a Schnorr proof of knowledge of the discrete log
  assert(SchnorrProof.fromJSON(data.proof).verify(point));

  this.R = point.mul(this.k);
  this.r = this.R.getX().umod(ec.n);
};

/**
 * Computes a paillier-encrypted (with other party's paillier public key) signature fragment
 * A degree of ec.n is added to the ciphertext in order to prevent factorization
 * @returns {{e}}
 */
Signer.prototype.computeCiphertext = function computeCiphertext() {
  assert(this.r && this.R);

  const p = this.compoundKey.remotePaillierPublicKey;
  const c = this.compoundKey.remotePrivateCiphertext;
  const x = this.compoundKey.getPrivateKey();
  const m = ec._truncateToN(new BN(this.message, 16));

  const a = this.k.invm(ec.n).mul(x).mul(this.r).umod(ec.n);
  const b = this.k.invm(ec.n).mul(m).umod(ec.n).add(ec.genKeyPair().getPrivate().mul(ec.n));
  const e = p.add(p.mult(c,new BigInteger(a.toString(16), 16)), p.encrypt(new BigInteger(b.toString(16), 16))).toString(16);

  return { e };
};

/**
 * Decrypts a remote ciphertext and finalizes the signature with own k share
 * @param ciphertext
 * @returns {Signature}
 */
Signer.prototype.extractSignature = function extractSignature(ciphertext) {
  assert(ciphertext.e);

  const d = new BN(this.compoundKey.localPaillierPrivateKey.decrypt(new BigInteger(ciphertext.e, 16)).toString(16), 16);

  let s = this.k.invm(ec.n).mul(d).umod(ec.n);

  let recoveryParam = (this.R.getY().isOdd() ? 1 : 0) | (this.R.getX().cmp(this.r) !== 0 ? 2 : 0);

  if (s.cmp(ec.nh) > 0) {
    s = ec.n.sub(s);
    recoveryParam ^= 1;
  }

  return new Signature({ r: this.r, s: s, recoveryParam: recoveryParam });
};

module.exports = Signer;
