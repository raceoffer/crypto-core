'use strict';

import assert from 'assert';

import BN from 'bn.js';
import elliptic from 'elliptic';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { SchnorrProof } from './schnorrproof';
import { PedersenScheme } from './pedersenscheme';

export class SignerEddsa {
  constructor() {
    // Pedersen commitment\decommitment scheme, initialized with random parameters
    this.pedersenScheme = null;
    this.compoundKey = null;
    this.message = null;

    this.r = null;

    this.R = null;

    // Pedersen scheme parameters, received from the remote participant
    this.remoteParams = null;
    // R commitment from the remote participant awaiting for decommitment to be received
    this.commitment = null;
    // local R decommitment awaiting for the remote commitment to be received
    this.decommitment = null;
  }

  fromOptions(options) {
    assert(options.compoundKey);
    assert(options.message);
    assert(options.curve);

    this.eddsa = elliptic.eddsa(options.curve);

    this.compoundKey = options.compoundKey;
    this.pedersenScheme = PedersenScheme.generate(this.eddsa);
    this.message = elliptic.utils.parseBytes(options.message);

    this.r = this.eddsa.hashInt(this.compoundKey.localPrivateKey.messagePrefix(), this.message);

    return this;
  }

  static fromOptions(options) {
    return new SignerEddsa().fromOptions(options);
  }

  createCommitment() {
    assert(this.r, "The key must be initialized to create a commitment");

    const data = {
      R: Buffer.from(this.eddsa.g.mul(this.r).encode(true)).toString('hex'),
      proof: SchnorrProof.fromSecret(this.eddsa, this.r).toJSON()
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
    // Verifies that the decommitment matches a previously published commitment
    assert(PedersenScheme.verify(this.eddsa, this.remoteParams, this.commitment, decommitment));

    const data = JSON.parse(decommitment.message);

    const R = this.eddsa.curve.decodePoint(Buffer.from(data.R,'hex'));

    // Verifies a Schnorr proof of knowledge of the discrete log
    assert(SchnorrProof.fromJSON(this.eddsa, data.proof).verify(R));

    this.R = this.eddsa.g.mul(this.r).add(R);
  }

  computePartialSignature() {
    assert(this.r && this.R);

    const Rencoded = this.eddsa.encodePoint(this.R);
    const h = this.eddsa.hashInt(Rencoded, this.compoundKey.compoundPublicKey.pubBytes(), this.message);

    return {
      s: this.r.add(h.mul(this.compoundKey.localPrivate)).umod(this.eddsa.curve.n).toString(16)
    };
  }

  combineSignatures(s1, s2) {
    assert(s1);

    if (!s2) {
      s2 = this.computePartialSignature();
    }

    const S = new BN(s1.s, 16).add(new BN(s2.s, 16)).umod(this.eddsa.curve.n);

    const Rencoded = this.eddsa.encodePoint(this.R);

    return this.eddsa.makeSignature({ R: this.R, S: S, Rencoded: Rencoded });
  }
}
