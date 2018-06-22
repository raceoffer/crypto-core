'use strict';

import assert from 'assert';

import elliptic from 'elliptic';
import BN from 'bn.js';
import HmacDRBG from 'hmac-drbg';
import Signature from 'elliptic/lib/elliptic/ec/signature';
import JSBN from 'jsbn';
import buffer from 'buffer';

const Buffer = buffer.Buffer;
const BigInteger = JSBN.BigInteger;

import { SchnorrProof } from '../schnorrproof';
import { PedersenScheme } from '../pedersenscheme';

export class Signer {
  constructor() {
    this.curve = null;
    this.ec = null;

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
  fromOptions(options) {
    assert(options.compoundKey,"A private keyring is required");
    assert(options.message);

    this.curve = options.compoundKey.curve || 'secp256k1';
    this.ec = elliptic.ec(this.curve);

    this.compoundKey = options.compoundKey;
    this.pedersenScheme = PedersenScheme.generate(this.ec);
    this.message = options.message;

    const key = this.compoundKey.localPrivate;
    const msg = this.ec._truncateToN(new BN(this.message, 16));

    const bytes = this.ec.n.byteLength();
    const bkey = key.toArray('be', bytes);

    const nonce = msg.toArray('be', bytes);

    const drbg = new HmacDRBG({
      hash: this.ec.hash,
      entropy: bkey,
      nonce: nonce,
      pers: null,
      persEnc: 'utf8'
    });

    const ns1 = this.ec.n.sub(new BN(1));

    do {
      this.k = new BN(drbg.generate(bytes));
      this.k = this.ec._truncateToN(this.k, true);
    } while (this.k.cmpn(1) <= 0 || this.k.cmp(ns1) >= 0);

    return this;
  }

  /**
   * Static version of the above
   * @param options
   * @returns {Signer}
   */
  static fromOptions(options) {
    return new Signer().fromOptions(options);
  }

  /**
   * Computes an entropy commitment, consisting of local R value and proof of a discrete logarithm for R
   * Also contains public parameters of local Pedersen scheme
   * @returns {{params: {H}, entropy: (commitment|{C})}}
   */
  createEntropyCommitment() {
    assert(this.k, "The key must be initialized to create a commitment");

    const data = {
      R: Buffer.from(this.ec.g.mul(this.k).encode(true)).toString('hex'),
      proof: SchnorrProof.fromSecret(this.ec, this.k).toJSON()
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
    assert(PedersenScheme.verify(this.ec, this.remoteParams,this.remoteCommitment,decommitment));

    const data = JSON.parse(decommitment.message);

    assert(data.R);

    const point = this.ec.curve.decodePoint(Buffer.from(data.R,'hex'));

    // Verifies a Schnorr proof of knowledge of the discrete log
    assert(SchnorrProof.fromJSON(this.ec, data.proof).verify(point));

    this.R = point.mul(this.k);
    this.r = this.R.getX().umod(this.ec.n);
  }

  /**
   * Computes a paillier-encrypted (with other party's paillier public key) signature fragment
   * A degree of ec.n is added to the ciphertext in order to prevent factorization
   * @returns {{e}}
   */
  computeCiphertext() {
    assert(this.r && this.R);

    const p = this.compoundKey.remotePaillierPublicKey;
    const c = this.compoundKey.remotePrivateCiphertext;
    const x = this.compoundKey.localPrivate;
    const m = this.ec._truncateToN(new BN(this.message, 16));

    const a = this.k.invm(this.ec.n).mul(x).mul(this.r).umod(this.ec.n);
    const b = this.k.invm(this.ec.n).mul(m).umod(this.ec.n).add(this.ec.genKeyPair().getPrivate().mul(this.ec.n));
    const e = p.add(p.mult(c,new BigInteger(a.toString(16), 16)), p.encrypt(new BigInteger(b.toString(16), 16))).toString(16);

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

    let s = this.k.invm(this.ec.n).mul(d).umod(this.ec.n);

    let recoveryParam = (this.R.getY().isOdd() ? 1 : 0) | (this.R.getX().cmp(this.r) !== 0 ? 2 : 0);

    if (s.cmp(this.ec.nh) > 0) {
      s = this.ec.n.sub(s);
      recoveryParam ^= 1;
    }

    return new Signature({ r: this.r, s: s, recoveryParam: recoveryParam });
  }
}
