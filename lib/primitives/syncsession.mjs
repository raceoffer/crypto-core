'use strict';

import assert from 'assert';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { PedersenScheme } from './pedersenscheme';
import { SchnorrProof } from "./schnorrproof";

export class SyncSession {
  constructor() {
    this.curve = null;
    this.x = null;

    // Pedersen commitment\decommitment scheme, initialized with random parameters
    this.pedersenScheme = null;

    // Pedersen scheme parameters, received from the remote participant
    this.remoteParams = null;

    // (Q,pk,c) commitment from the remote participant awaiting for decommitment to be received
    this.commitment = null;

    // local (Q,pk,c) decommitment awaiting for the remote commitment to be received
    this.decommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.x = options.x;
    this.pedersenScheme = PedersenScheme.generate(this.curve);
    return this;
  }

  static fromOptions(options) {
    return new SyncSession().fromOptions(options);
  }

  createCommitment() {
    assert(this.x, "The key must be initialized to start a commitment");

    const data = {
      Q: Buffer.from(this.curve.g.mul(this.x).encode(true)).toString('hex'),
      proof: SchnorrProof.fromSecret(this.curve, this.x).toJSON()
    };

    const cmt = this.pedersenScheme.commit(JSON.stringify(data));

    // A decommitment needs to be saved until we receive a remote commitment
    this.decommitment = cmt.decommitment;

    return {
        params: this.pedersenScheme.getParams(),
        commitment: cmt.commitment
    };
  }

  processCommitment(commitment) {
    this.commitment = commitment.commitment;
    this.remoteParams = commitment.params;
    return this.decommitment;
  }

  processDecommitment(decommitment) {
    assert(PedersenScheme.verify(this.curve, this.remoteParams, this.commitment, decommitment));

    const data = JSON.parse(decommitment.message);

    const Q = this.curve.curve.decodePoint(Buffer.from(data.Q,'hex'));

    assert(SchnorrProof.fromJSON(this.curve, data.proof).verify(Q));

    return { Q };
  }
}
