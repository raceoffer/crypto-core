'use strict';

import assert from 'assert';

const ec = require('elliptic').ec('secp256k1');
const BigInteger = require("jsbn").BigInteger;

import { PedersenScheme } from './pedersenscheme';

export class PaillierVerifier {
  constructor() {
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
    assert(PedersenScheme.verify(this.remoteParams, this.aCommitment, decommitment));

    const Q = ec.curve.decodePoint(Buffer.from(decommitment.message,'hex'));

    assert(this.Q.mul(this.a).add(ec.g.mul(this.b)).eq(Q));

    return {
      Q: this.Q,
      pk: this.pk,
      c: this.c
    };
  }
}
