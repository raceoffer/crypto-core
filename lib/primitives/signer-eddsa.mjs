'use strict';

import assert from 'assert';

import EC from 'elliptic';
import BN from 'bn.js';
import Signature from 'elliptic/lib/elliptic/ec/signature';
import JSBN from 'jsbn';
import buffer from 'buffer';

const Buffer = buffer.Buffer;
const ec = EC.eddsa('ed25519');
const utils = EC.utils;
const BigInteger = JSBN.BigInteger;

import { SchnorrProof } from './schnorrproof';
import { PedersenScheme } from './pedersenscheme';

export class SignerEddsa {
  constructor() {
    // Pedersen commitment\decommitment scheme, initialized with random parameters
    this.pedersenScheme = null;
    this.compoundKey = null;
    this.message = null;

    // local entropy multiplicative share (temporary ecdsa private key)
    this.r = null;
    // compound ECDH-exchanged public entropy
    this.R = null;

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
  fromOptions(options) {
    assert(options.compoundKey,"A private keyring is required");

    this.compoundKey = options.compoundKey;
    this.pedersenScheme = PedersenScheme.generate(ec);
    this.message = utils.parseBytes(options.message);

    this.r = ec.hashInt(this.compoundKey.localPrivateKey.messagePrefix(), this.message);

    return this;
  }

  /**
   * Static version of the above
   * @param options
   * @returns {Signer}
   */
  static fromOptions(options) {
    return new SignerEddsa().fromOptions(options);
  }

  /**
   * Computes an entropy commitment, consisting of local R value and proof of a discrete logarithm for R
   * Also contains public parameters of local Pedersen scheme
   * @returns {{params: {H}, entropy: (commitment|{C})}}
   */
  createEntropyCommitment() {
    assert(this.r, "The key must be initialized to create a commitment");

    const data = {
      R: Buffer.from(ec.g.mul(this.r).encode(true)).toString('hex'),
      rx: this.compoundKey.localPaillierPublicKey.encrypt(new BigInteger(this.r.toString(16), 16)).toString(16),
      proof: SchnorrProof.fromSecret(ec, this.r).toJSON()
    };

    const cmt = this.pedersenScheme.commit(JSON.stringify(data));

    // A decommitment needs to be saved until we receive a remote commitment
    this.localDecommitment = cmt.decommitment;

    return {
      params: this.pedersenScheme.getParams(),
      entropy: cmt.commitment
    };
  }

  /**
   * Saves a remote commitment and public parameters and publishes decommitment
   * @param commitment - remote commitment to be saved and lately verified
   * @returns {null|*}
   */
  processEntropyCommitment(commitment) {
    this.remoteParams = commitment.params;
    this.remoteCommitment = commitment.entropy;

    return this.localDecommitment;
  }

  /**
   * Verifies decommitment according to a previously saved commitmnet.
   * Computes a ECDH shared public entropy and r parameter
   * @param decommitment - a remote decommitment
   */
  processEntropyDecommitment(decommitment) {
    // Verifies that the decommitment matches a previously published commitment
    assert(PedersenScheme.verify(ec, this.remoteParams,this.remoteCommitment,decommitment));

    const data = JSON.parse(decommitment.message);

    assert(data.R);
    assert(data.rx);

    const point = ec.curve.decodePoint(Buffer.from(data.R,'hex'));

    // Verifies a Schnorr proof of knowledge of the discrete log
    assert(SchnorrProof.fromJSON(ec, data.proof).verify(point));

    this.R = point.mul(this.r);
    this.rx = new BigInteger(data.rx, 16); // 'This needs a proof of encryption'
  }

  /**
   * Computes a paillier-encrypted (with other party's paillier public key) signature fragment
   * A degree of ec.n is added to the ciphertext in order to prevent factorization
   * @returns {{e}}
   */
  computeCiphertext() {
    assert(this.r && this.rx && this.R);

    const Rencoded = ec.encodePoint(this.R);
    const h = ec.hashInt(Rencoded, this.compoundKey.compoundPublicKey.pubBytes(), this.message);

    const p = this.compoundKey.remotePaillierPublicKey;

    const c  = new BigInteger(this.compoundKey.getPrivateKey().toString(16), 16);
    const cx = this.compoundKey.remotePrivateCiphertext;

    const r  = new BigInteger(this.r.toString(16), 16);
    const rx = this.rx;

    const e = p.add(p.mult(rx, r), p.mult(p.mult(cx, c), new BigInteger(h.toString(16), 16))).toString(16);

    return { e };
  }

  /**
   * Decrypts a remote ciphertext and finalizes the signature with own k share
   * @param ciphertext
   * @returns {Signature}
   */
  extractSignature(ciphertext) {
    assert(ciphertext.e);

    const d = new BN(this.compoundKey.localPaillierPrivateKey.decrypt(new BigInteger(ciphertext.e, 16)).toString(16), 16);

    const S = d.umod(ec.curve.n);

    const Rencoded = ec.encodePoint(this.R);

    return ec.makeSignature({ R: this.R, S: S, Rencoded: Rencoded });
  }
}
