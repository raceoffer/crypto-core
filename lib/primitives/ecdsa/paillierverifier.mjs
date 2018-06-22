'use strict';

import assert from 'assert';

import BN from 'bn.js';
import JSBN from 'jsbn';
import buffer from 'buffer';

const Buffer = buffer.Buffer;
const BigInteger = JSBN.BigInteger;

import { PedersenScheme } from '../pedersenscheme';
import { randomBytes } from '../../utils';

export class PaillierVerifier {
  constructor() {
    this.curve = null;

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

  fromOptions(options) {
    this.curve = options.curve;

    this.pk = options.pk;
    this.c = options.c;
    this.Q = options.Q;
    this.pedersenScheme = options.pedersenScheme;
    this.remoteParams = options.remoteParams;

    return this;
  }

  static fromOptions(options) {
    return new PaillierVerifier().fromOptions(options);
  }

  /**
   * Computes (a,b) commitment and stores decommitment until a remote alpha commitment is received
   * @returns {{c: string, s: (*|commitment|{C})}}
   */
  getCommitment() {
    this.a = new BN(randomBytes(32).toString('hex'), 16);
    this.b = new BN(randomBytes(32).toString('hex'), 16);

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
    };
  }

  /**
   * Saves alpha commitment and reveals (a,b) decommitment
   * @param commitment
   * @returns {null|*}
   */
  processCommitment(commitment) {
    this.aCommitment = commitment.a;

    return this.sDecommitment;
  }

  /**
   * Verifies alpha decommitment and proof-of-encryption, then returns verified synchronization parameters
   * @param decommitment
   * @returns {{Q: *, pk: *, c: *}}
   */
  processDecommitment(decommitment) {
    assert(PedersenScheme.verify(this.curve, this.remoteParams, this.aCommitment, decommitment));

    const Q = this.curve.curve.decodePoint(Buffer.from(decommitment.message,'hex'));

    assert(this.Q.mul(this.a).add(this.curve.g.mul(this.b)).eq(Q));

    return {
      Q: this.Q,
      pk: this.pk,
      c: this.c
    };
  }
}
