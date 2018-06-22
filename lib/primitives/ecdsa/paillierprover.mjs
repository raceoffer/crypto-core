'use strict';

import assert from 'assert';

import BN from 'bn.js';
import JSBN from 'jsbn';
import jspaillier from 'jspaillier';
import buffer from 'buffer';

const Buffer = buffer.Buffer;
const BigInteger = JSBN.BigInteger;

import { PedersenScheme } from '../pedersenscheme';
import { PaillierVerifier } from './paillierverifier';

export class PaillierProver {
  constructor() {
    this.curve = null;

    this.pk = null;
    this.sk = null;
    this.x = null;

    // Pedersen commitment\decommitment scheme, initialized with random parameters
    this.pedersenScheme = null;

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

    this.alpha = null;
  }

  fromOptions(options) {
    this.curve = options.curve;

    this.pk = options.pk;
    this.sk = options.sk;
    this.x = options.x;
    this.pedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new PaillierProver().fromOptions(options);
  }

  /**
   * Computes a Pedersen commitment of paillier public key, local public key and paillier encryption of local private key
   * Decommitment is stored until remote commitment is received
   * @returns {{params: {H}, i: (commitment|{C})}}
   */
  getInitialCommitment() {
    const data = {
      pk: {
        bits: this.pk.bits,
        n: this.pk.n.toString(16)
      },
      Q: Buffer.from(this.curve.g.mul(this.x).encode(true)).toString('hex'),
      c: this.pk.encrypt(new BigInteger(this.x.toString(16), 16)).toString(16),
    };

    const cmt = this.pedersenScheme.commit(JSON.stringify(data));

    this.iDecommitment = cmt.decommitment;

    return {
      params: this.pedersenScheme.getParams(),
      i: cmt.commitment
    };
  }

  /**
   * Saves a remote commitment and public parameters and publishes decommitment
   * @param commitment
   * @returns {null|*}
   */
  processInitialCommitment(commitment) {
    this.iCommitment = commitment.i;
    this.remoteParams = commitment.params;

    return this.iDecommitment;
  }

  /**
   * Initializes a Verifier object, responsible for interactive verification of the proof-of-paillier-encryption
   * @see https://eprint.iacr.org/2017/552.pdf for details on Zk proof-of-encryption
   * @param decommitment
   * @returns {PaillierVerifier}
   */
  processInitialDecommitment(decommitment) {
    assert(PedersenScheme.verify(this.curve, this.remoteParams,this.iCommitment,decommitment));

    const data = JSON.parse(decommitment.message);

    const options = {
      curve: this.curve,
      pedersenScheme: this.pedersenScheme,
      remoteParams: this.remoteParams,
      pk: new jspaillier.publicKey(data.pk.bits, new BigInteger(data.pk.n, 16)),
      c: new BigInteger(data.c, 16),
      Q: this.curve.curve.decodePoint(Buffer.from(data.Q, 'hex'))
    };

    return PaillierVerifier.fromOptions(options);
  }

  /**
   * Computes alpha commitment nad saves (a,b) commitment for further verification
   * @param commitment
   * @returns {{a: (commitment|{C})}}
   */
  processCommitment(commitment) {
    this.alpha = new BN(this.sk.decrypt(new BigInteger(commitment.c, 16)).toString(16), 16);

    this.sCommitment = commitment.s;

    const Q = this.curve.g.mul(this.alpha);

    const cmt = this.pedersenScheme.commit(Buffer.from(Q.encode(true)).toString('hex'));

    // decommitment needs to be saved locally
    this.aDecommitment = cmt.decommitment;

    return {
      a: cmt.commitment
    };
  }

  /**
   * Reveals (alpha) decommitment based on correctness of (a,b) decommitment
   * @param decommitment
   * @returns {null|*}
   */
  processDecommitment(decommitment) {
    assert(PedersenScheme.verify(this.curve, this.remoteParams,this.sCommitment,decommitment));

    const message = JSON.parse(decommitment.message);

    const a = new BN(message.a, 16);
    const b = new BN(message.b, 16);

    const alpha = this.x.mul(a).iadd(b);

    assert(this.alpha.cmp(alpha) === 0);

    return this.aDecommitment;
  }
}
