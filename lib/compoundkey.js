const assert = require("assert");
const ec = require('elliptic').ec('secp256k1');
const HmacDRBG = require('hmac-drbg');
const BN = require('bn.js');
const Signature = require('elliptic/lib/elliptic/ec/signature');
const jspaillier = require('jspaillier');
const BigInteger = require("jsbn").BigInteger;

const SchnorrProof = require('./schnorrproof');
const PaillierProof = require('./paillierproof');
const PedersenScheme = require('./pedersenscheme');

function CompoundKey() {
  if(!(this instanceof CompoundKey))
    return new CompoundKey();

  // Own key (private)
  this.localPrivateKey = null;

  // External key (public only)
  this.remotePublicKey = null;

  // Compound key (public only)
  this.compoundPublicKey = null;

  // Paillier keypair
  this.localPaillierPublicKey  = null;
  this.localPaillierPrivateKey = null;

  // Encrypted remote private key
  this.remotePrivateCiphertext = null;

  // Remote paillier public key
  this.remotePaillierPublicKey = null;
}

/**
 * Generates a paillier keypair
 * @returns {{localPaillierPublicKey, localPaillierPrivateKey}}
 */
CompoundKey.generatePaillierKeys = function() {
  const paillierKeys = jspaillier.generateKeys(1024);
  return {
    localPaillierPublicKey:  paillierKeys.pub,
    localPaillierPrivateKey: paillierKeys.sec
  };
};

/**
 * Generates a random private key from Z_n/3
 * @returns {KeyPair}
 */
CompoundKey.generateKey = function generateKeyring() {
  const n3 = ec.n.div(new BN(3));
  let key = null;
  do {
    key = ec.genKeyPair();
  } while(key.getPrivate().cmp(n3) > 0);
  return key;
};

/**
 * Generates a random CompoundKey with local key from Z_n/3
 */
CompoundKey.generate = function generate() {
  return CompoundKey.fromOptions({
    localPrivateKey: CompoundKey.generateKey(),
    localPaillierKeys: CompoundKey.generatePaillierKeys()
  });
};

/**
 * Initializes a KeyPair from byte string
 * @param secret
 * @returns {KeyPair}
 */
CompoundKey.keyFromSecret = function keyringFromSeed(secret) {
  return ec.keyFromPrivate(secret);
};

/**
 * Initializes a CompoundKey from byte string
 * @param secret
 */
CompoundKey.fromSecret = function fromSecret(secret) {
  return CompoundKey.fromOptions({
    localPrivateKey: CompoundKey.keyFromSecret(secret),
    localPaillierKeys: CompoundKey.generatePaillierKeys()
  });
};

/**
 * Initializes a Compound key with options
 * @param options.localPrivateKey
 * @param options.localPaillierKeys
 * @returns {CompoundKey}
 */
CompoundKey.prototype.fromOptions = function fromOptions(options) {
  assert(options.localPrivateKey, 'A private keyring is required');
  assert(options.localPaillierKeys, 'Paillier keys are required');

  this.localPrivateKey = options.localPrivateKey;
  this.localPaillierPublicKey = options.localPaillierKeys.localPaillierPublicKey;
  this.localPaillierPrivateKey = options.localPaillierKeys.localPaillierPrivateKey;

  return this;
};

/**
 * Static version of the above
 * @returns {CompoundKey}
 */
CompoundKey.fromOptions = function fromOptions(options) {
  return new CompoundKey().fromOptions(options);
};

/**
 * Returns a local private key encoded with options encoding [raw if not specified]
 * @param enc [optional] - 'hex'/'base58'
 * @returns {*}
 */
CompoundKey.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.localPrivateKey.getPrivate(enc);
};

/**
 * Returns a local public key encoded with options encoding [raw if not specified]
 * @param compress - point compression
 * @param enc [optional] - 'hex'/'base58'
 */
CompoundKey.prototype.getPublicKey = function getPublicKey(compress, enc) {
  return this.localPrivateKey.getPublic(compress, enc);
};
/**
 * Returns a compound public key encoded with options encoding [raw if not specified]
 * @param compress - point compression
 * @param enc [optional] - 'hex'/'base58'
 */
CompoundKey.prototype.getCompoundPublicKey = function getCompoundPublicKey(compress, enc) {
  if(!this.remotePublicKey){
    return null;
  }
  return this.compoundPublicKey.getPublic(compress, enc);
};

/**
 * Initializes and returns a prover object, responsible for key exchange protocol @see PaillierProof
 * @returns {Prover}
 */
CompoundKey.prototype.startInitialCommitment = function startInitialCommitment() {
  assert(this.localPrivateKey, "The key must be initialized to start a commitment");

  return new PaillierProof.Prover({
    x:  this.localPrivateKey.getPrivate(),
    pk: this.localPaillierPublicKey,
    sk: this.localPaillierPrivateKey
  });
};

/**
 * Finalizes the initialization process, applying a verified data from key exchange protocol
 * Sets a compound public key and enables signing
 * @param syncData
 */
CompoundKey.prototype.finishInitialSync = function finishInitialSync(syncData) {
  // remote Q
  const point = syncData.Q;
  // local x
  const key = this.localPrivateKey.getPrivate();
  // compound Q according to ECDH
  const compound = point.mul(key);

  this.remotePublicKey = ec.keyFromPublic(Buffer.from(point.encode(true, 'array')));
  this.remotePrivateCiphertext = syncData.c;
  this.remotePaillierPublicKey = syncData.pk;

  this.compoundPublicKey = ec.keyFromPublic(Buffer.from(compound.encode(true, 'array')));
};

/**
 * Returns the exact set of data used to finalize this CompoundKey
 * May be used for key duplication and re-initialization
 * @returns {{Q, pk: (null|*), c: (null|*)}}
 */
CompoundKey.prototype.extractSyncData = function extractSyncData() {
  assert(this.compoundPublicKey);

  return {
    Q: this.remotePublicKey.getPublic(),
    pk: this.remotePaillierPublicKey,
    c: this.remotePrivateCiphertext
  }
};

/**
 * Initiates a Signer object, responsible for message signing protocol
 * @param message (Buffer) - a message to sign
 * @returns {Signer}
 */
CompoundKey.prototype.startSign = function startSign(message) {
  return new Signer({
    message: message,
    compoundKey: this
  });
};

// Signer section

function Signer(options) {
  if(!(this instanceof Signer))
    return new Signer(options);

  // Pedersen commitment\decommitment scheme, initialized with random parameters
  this.pedersenScheme = new PedersenScheme();
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

  if(options) {
    this.fromOptions(options);
  }
}

/**
 * Signer initialization. Generates a random entropy fragment k
 * @param options @see CompoundKey.prototype.startSign
 * @returns {Signer}
 */
Signer.prototype.fromOptions = function fromOptions(options) {
  assert(options.compoundKey,"A private keyring is required");

  this.compoundKey = options.compoundKey;
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

module.exports = CompoundKey;
