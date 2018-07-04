'use strict';

import assert from 'assert';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { SchnorrProof } from "../schnorrproof";

import {
  PedersenScheme,
  PedersenCommitment,
  PedersenDecommitment,
  PedersenParameters
} from '../pedersenscheme';

import {
  toJSON,
  fromJSON,
  decodePoint,
  encodePoint,
  decodeBN,
  encodeBN
} from "../../convert";

import { matchCurve } from "../../curves";

export class SyncData {
  constructor() {
    this.curve = null;
    this.Q = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.Q = options.Q;

    return this;
  }

  static fromOptions(options) {
    return new SyncData().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      Q: encodePoint(this.Q)
    };
  }

  fromJSON(json) {
    const crypto = matchCurve(json.curve);

    this.curve = json.curve;
    this.Q = decodePoint(crypto, json.Q);

    return this;
  }

  static fromJSON(json) {
    return new SyncData().fromJSON(json);
  }
}

export class SyncSession {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.x = null;

    // Pedersen commitment\decommitment scheme, initialized with random parameters
    this.pedersenScheme = null;

    // Pedersen scheme parameters, received from the remote participant
    this.remoteParams = null;

    // (Q,pk,c) commitment from the remote participant awaiting for decommitment to be received
    this.remoteCommitment = null;

    // local (Q,pk,c) decommitment awaiting for the remote commitment to be received
    this.localDecommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);
    this.x = options.x;
    this.pedersenScheme = PedersenScheme.generate(this.curve);
    return this;
  }

  static fromOptions(options) {
    return new SyncSession().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      x: encodeBN(this.x),
      pedersenScheme: toJSON(this.pedersenScheme),
      remoteParams: toJSON(this.remoteParams),
      remoteCommitment: toJSON(this.remoteCommitment),
      localDecommitment: toJSON(this.localDecommitment)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);
    this.x = decodeBN(json.x);
    this.pedersenScheme = fromJSON(PedersenScheme, json.pedersenScheme);
    this.remoteParams = fromJSON(PedersenParameters, json.remoteParams);
    this.remoteCommitment = fromJSON(PedersenCommitment, json.remoteCommitment);
    this.localDecommitment = fromJSON(PedersenDecommitment, json.localDecommitment);

    return this;
  }

  static fromJSON(json) {
    return new SyncSession().fromJSON(json);
  }

  createCommitment() {
    assert(this.x, "The key must be initialized to start a commitment");

    const Q = this.crypto.g.mul(this.x);
    const proof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.x
    });

    const data = {
      Q: encodePoint(Q),
      proof: toJSON(proof)
    };

    const cmt = this.pedersenScheme.commit(Buffer.from(JSON.stringify(data), 'ascii'));

    // A decommitment needs to be saved until we receive a remote commitment
    this.localDecommitment = cmt.decommitment;

    return {
      params: this.pedersenScheme.getParams(),
      commitment: cmt.commitment
    };
  }

  processCommitment(commitment) {
    this.remoteCommitment = commitment.commitment;
    this.remoteParams = commitment.params;
    return this.localDecommitment;
  }

  processDecommitment(decommitment) {
    assert(PedersenScheme.verify(this.remoteParams, this.remoteCommitment, decommitment));

    const data = JSON.parse(decommitment.message.toString('ascii'));

    const Q = decodePoint(this.crypto, data.Q);
    const proof = fromJSON(SchnorrProof, data.proof);

    assert(proof.verify(Q));

    return SyncData.fromOptions({
      curve: this.curve,
      Q: Q
    });
  }
}
