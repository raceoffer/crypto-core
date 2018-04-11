const assert = require("assert");
const ec = require('elliptic').ec('secp256k1');
const BN = require('bn.js');
const jspaillier = require('jspaillier');

const PaillierProver = require('./paillierprover');
const Signer = require('./signer');

function CompoundKey() {
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
 * @returns {PaillierProver}
 */
CompoundKey.prototype.startInitialCommitment = function startInitialCommitment() {
  assert(this.localPrivateKey, "The key must be initialized to start a commitment");

  return PaillierProver.fromOptions({
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
  return Signer.fromOptions({
    message: message,
    compoundKey: this
  });
};

module.exports = CompoundKey;
