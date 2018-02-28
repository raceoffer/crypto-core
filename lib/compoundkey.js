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

function CompoundKey(options) {
  if(!(this instanceof CompoundKey))
    return new CompoundKey(options);

  // Own keyring (full)
  this.localPrivateKey = null;

  // External keyring (public only)
  this.remotePublicKey = null;

  // Compound keyring (public only)
  this.compoundPublicKey = null;

  // Paillier keypair
  const paillierKeys = jspaillier.generateKeys(1024);
  this.localPaillierPublicKey  = paillierKeys.pub;
  this.localPaillierPrivateKey = paillierKeys.sec;

  // Encrypted remote private key
  this.remotePrivateCiphertext = null;

  // Remote paillier public key
  this.remotePaillierPublicKey = null;

  if(options) {
    this.fromOptions(options);
  }
}

CompoundKey.generateKey = function generateKeyring() {
  const n3 = ec.n.div(new BN(3));
  let key = null;
  do {
    key = ec.genKeyPair();
  } while(key.getPrivate().cmp(n3) > 0);
  return key;
};

CompoundKey.generate = function generate() {
  return CompoundKey.fromOptions({ localPrivateKey: CompoundKey.generateKey() });
};

CompoundKey.keyFromSecret = function keyringFromSeed(secret) {
  return ec.keyFromPrivate(secret);
};

CompoundKey.fromSecret = function fromSecret(secret) {
  return CompoundKey.fromOptions({ localPrivateKey: CompoundKey.keyFromSecret(secret) });
};

CompoundKey.prototype.fromOptions = function fromOptions(options) {
  assert(options.localPrivateKey,"A private keyring is required");

  this.localPrivateKey = options.localPrivateKey;

  if(options.remotePublicKey) {
    this.remotePublicKey = options.remotePublicKey;
  }

  return this;
};

CompoundKey.fromOptions = function fromOptions(options) {
  return new CompoundKey().fromOptions(options);
};

CompoundKey.prototype.getPrivateKey = function getPrivateKey(enc) {
  return this.localPrivateKey.getPrivate(enc);
};

CompoundKey.prototype.getPublicKey = function getPublicKey(compress, enc) {
  return this.localPrivateKey.getPublic(compress, enc);
};

CompoundKey.prototype.getCompoundPublicKey = function getCompoundPublicKey(compress, enc) {
  if(!this.remotePublicKey){
    return null;
  }
  return this.compoundPublicKey.getPublic(compress, enc);
};

CompoundKey.prototype.startInitialCommitment = function startInitialCommitment() {
  assert(this.localPrivateKey, "The key must be initialized to start a commitment");

  return new PaillierProof.Prover({
    x:  this.localPrivateKey.getPrivate(),
    pk: this.localPaillierPublicKey,
    sk: this.localPaillierPrivateKey
  });
};

CompoundKey.prototype.finishInitialSync = function finishInitialSync(syncData) {
  const remoteKey = ec.keyFromPublic(Buffer.from(syncData.Q.encode(true, 'array')));
  const point = syncData.Q;

  const key = this.localPrivateKey.getPrivate();
  const compound = point.mul(key);

  this.remotePublicKey = remoteKey;
  this.remotePrivateCiphertext = syncData.c;
  this.remotePaillierPublicKey = syncData.pk;

  this.compoundPublicKey = ec.keyFromPublic(Buffer.from(compound.encode(true, 'array')));
};

CompoundKey.prototype.extractSyncData = function extractSyncData() {
  assert(this.compoundPublicKey);

  return {
    Q: this.remotePublicKey.getPublic(),
    pk: this.remotePaillierPublicKey,
    c: this.remotePrivateCiphertext
  }
};

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

  this.pedersenScheme = new PedersenScheme();
  this.compoundKey = null;
  this.message = null;
  this.k = null;
  this.R = null;
  this.r = null;

  this.remoteParams = null;
  this.remoteCommitment = null;
  this.localDecommitment = null;

  if(options) {
    this.fromOptions(options);
  }
}

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

Signer.fromOptions = function fromOptions(options) {
  return new Signer().fromOptions(options);
};

Signer.prototype.createEntropyCommitment = function createEntropyCommitment() {
  assert(this.k, "The key must be initialized to create a commitment");

  const data = {
    R: Buffer.from(ec.g.mul(this.k).encode(true)).toString('hex'),
    proof: SchnorrProof.fromSecret(this.k).toJSON()
  };

  const cmt = this.pedersenScheme.commit(JSON.stringify(data));

  this.localDecommitment = cmt.decommitment;

  return {
    params: this.pedersenScheme.getParams(),
    entropy: cmt.commitment
  }
};

Signer.prototype.processEntropyCommitment = function processEntropyCommitment(commitment) {
  this.remoteParams = commitment.params;
  this.remoteCommitment = commitment.entropy;

  return this.localDecommitment;
};

Signer.prototype.processEntropyDecommitment = function processEntropyDecommitment(decommitment) {
  assert(PedersenScheme.verify(this.remoteParams,this.remoteCommitment,decommitment));

  const data = JSON.parse(decommitment.message);

  assert(data.R);

  const point = ec.curve.decodePoint(Buffer.from(data.R,'hex'));

  assert(SchnorrProof.fromJSON(data.proof).verify(point));

  this.R = point.mul(this.k);
  this.r = this.R.getX().umod(ec.n);
};

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
