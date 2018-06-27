'use strict';

import assert from 'assert';

import elliptic from 'elliptic';

const utils = elliptic.utils;

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import {
  PedersenScheme,
  PedersenParameters,
  PedersenCommitment,
  PedersenDecommitment
} from '../pedersenscheme';

import { SchnorrProof } from "../schnorrproof";

import { KeyPair } from "./keypair";
import { matchCurve } from "../../curves";

import {
    toJSON,
    fromJSON,
    decodePoint,
    encodePoint,
    decodeBN,
    encodeBN
} from "../../convert"

export class PartialSignature {
  constructor() {
    this.s = null;
  }

  fromOptions(options) {
    this.s = options.s;

    return this;
  }

  static fromOptions(options) {
    return new PartialSignature().fromOptions(options);
  }

  toJSON() {
    return {
      s: encodeBN(this.s)
    };
  }

  fromJSON(json) {
    this.s = decodeBN(json.s);

    return this;
  }

  static fromJSON(json) {
    return new PartialSignature().fromJSON(json);
  }
}

export class Signer {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.localPrivateKey = null;
    this.compoundPublic = null;
    this.message = null;

    this.r = null;
    this.R = null;

    // Pedersen commitment\decommitment scheme, initialized with random parameters
    this.pedersenScheme = null;
    // Pedersen scheme parameters, received from the remote participant
    this.remoteParams = null;
    // R commitment from the remote participant awaiting for decommitment to be received
    this.remoteCommitment = null;
    // local R decommitment awaiting for the remote commitment to be received
    this.localDecommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = options.localPrivateKey;
    this.compoundPublic = options.compoundPublic;
    this.message = options.message;

    this.pedersenScheme = PedersenScheme.generate(this.curve);

    const rb = KeyPair.hash(this.localPrivateKey.messagePrefix, this.message);

    this.r = utils.intFromLE(rb).umod(this.crypto.curve.n);

    return this;
  }

  static fromOptions(options) {
    return new Signer().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      localPrivateKey: toJSON(this.localPrivateKey),
      compoundPublic: encodePoint(this.compoundPublic),
      r: encodeBN(this.r),
      R: encodePoint(this.R),
      message: this.message.toString('hex'),
      pedersenScheme: toJSON(this.pedersenScheme),
      remoteParams: toJSON(this.remoteParams),
      remoteCommitment: toJSON(this.remoteCommitment),
      localDecommitment: toJSON(this.localDecommitment)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = fromJSON(json.localPrivateKey);
    this.compoundPublic = decodePoint(this.crypto, json.compoundPublic);
    this.message = Buffer.from(json.message, 'hex');

    this.r = decodeBN(json.r);
    this.R = decodePoint(json.crypto, json.R);

    this.pedersenScheme = fromJSON(PedersenScheme, json.pedersenScheme);
    this.remoteParams = fromJSON(PedersenParameters, json.remoteParams);
    this.remoteCommitment = fromJSON(PedersenCommitment, json.remoteCommitment);
    this.localDecommitment = fromJSON(PedersenDecommitment, json.localDecommitment);

    return this;
  }

  static fromJSON(json) {
    return new Signer().fromJSON(json);
  }

  createCommitment() {
    assert(this.r, "The key must be initialized to create a commitment");

    const R = this.crypto.g.mul(this.r);
    const proof = SchnorrProof.fromOptions({
        curve: this.curve,
        x: this.r
    });

    const data = {
      R: encodePoint(R),
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

    const R = decodePoint(this.crypto, data.R);
    const proof = fromJSON(SchnorrProof, data.proof);

    assert(proof.verify(R));

    this.R = this.crypto.g.mul(this.r).add(R);
  }

  computePartialSignature() {
    assert(this.r && this.R);

    const Rencoded = this.crypto.encodePoint(this.R);

    const hb = KeyPair.hash(Rencoded, this.crypto.encodePoint(this.compoundPublic), this.message);

    const h = utils.intFromLE(hb).mul(this.localPrivateKey.private);

    const s = this.r.add(h).umod(this.crypto.curve.n);

    return PartialSignature.fromOptions({ s: s });
  }

  combineSignatures(s1, s2) {
    assert(s1);

    if (!s2) {
      s2 = this.computePartialSignature();
    }

    const S = s1.s.add(s2.s).umod(this.crypto.curve.n);

    const Rencoded = this.crypto.encodePoint(this.R);

    return this.crypto.makeSignature({ R: this.R, S: S, Rencoded: Rencoded });
  }
}
