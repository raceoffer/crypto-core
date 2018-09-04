'use strict';

import assert from 'assert';

import BN from 'bn.js';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

import { PedersenScheme } from '../pedersenscheme';

import { randomBytes } from '../../utils';

import {
  toJSON,
  encodePoint,
  encodeBigInteger,
  encodeBN,
  toBigInteger,
  Field,
  generateMessage
} from '../../convert';

import { PaillierPublicKey } from './paillierkeys';
import { SchnorrProof } from '../schnorrproof';

import { Root } from 'protobufjs';
import * as proto from './paillierverifier.json';

const root = Root.fromJSON(proto);

export const InitialData = generateMessage(
  'InitialData', {
    pedersenParameters: [Field.Point],
    publicPoint: [Field.Point],
    schnorrProof: [Field.Custom, SchnorrProof]
  },
  root
);

export const ChallengeCommitment = generateMessage(
  'ChallengeCommitment', {
    challenge: [Field.BigInteger],
    revealCommitment: [Field.Point]
  },
  root
);

export const ChallengeDecommitment = generateMessage(
  'ChallengeDecommitment', {
    revealDecommitment: [Field.BN],
    a: [Field.BN],
    b: [Field.BN]
  },
  root
);

export const VerifierSyncData = generateMessage(
  'ChallengeDecommitment', {
    publicPoint: [Field.Point],
    paillierPublicKey: [Field.Custom, PaillierPublicKey],
    ciphertext: [Field.BigInteger]
  },
  root
);

export class PaillierVerifier extends generateMessage(
  'PaillierVerifier', {
    localPrivateKey: [Field.BN],
    localPedersenScheme: [Field.Custom, PedersenScheme],
    a: [Field.BN],
    b: [Field.BN],
    remotePublicPoint:[Field.Point],
    remotePaillierPublicKey: [Field.Custom, PaillierPublicKey],
    remoteCiphertext: [Field.BigInteger],
    remotePedersenParameters: [Field.Point],
    remoteInitialCommitment: [Field.Point],
    localRevealDecommitment: [Field.BN],
    remoteResponseCommitment: [Field.Point]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new PaillierVerifier().fromOptions(options);
  }
  
  static fromJSON(json) {
    return new PaillierVerifier().fromJSON(json);
  }

  static fromBytes(bytes) {
    return new PaillierVerifier().fromBytes(bytes);
  }

  processInitialCommitment(remote) {
    this.remotePedersenParameters = remote.pedersenParameters;
    this.remoteInitialCommitment = remote.initialCommitment;

    const schnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateKey
    });

    const publicPoint = this.crypto.g.mul(this.localPrivateKey);

    return InitialData.fromOptions({
      curve: this.curve,
      pedersenParameters: this.localPedersenScheme.getParameters(),
      publicPoint: publicPoint,
      schnorrProof: schnorrProof
    });
  }

  processInitialDecommitment(remote) {
    const InitialCommitmentMessage = root.lookupType('InitialCommitmentMessage');

    const initialCommitmentMessage = new Buffer(InitialCommitmentMessage.encode({
      paillierPublicKey: toJSON(remote.paillierPublicKey),
      publicPoint: encodePoint(remote.publicPoint),
      chiphertext: encodeBigInteger(remote.chiphertext)
    }).finish());

    assert(PedersenScheme.verify(
      this.curve,
      this.remotePedersenParameters,
      initialCommitmentMessage,
      this.remoteInitialCommitment,
      remote.initialDecommitment
    ));

    this.remotePublicPoint = remote.publicPoint;
    this.remotePaillierPublicKey = remote.paillierPublicKey;
    this.remoteCiphertext = remote.chiphertext;

    this.a = new BN(randomBytes(32));
    this.b = new BN(randomBytes(32));

    const challenge = this.remotePaillierPublicKey.add(
      this.remotePaillierPublicKey.mult(
        this.remoteCiphertext,
        toBigInteger(this.a)),
      this.remotePaillierPublicKey.encrypt(
        toBigInteger(this.b)));

    const ChallengeCommitmentMessage = root.lookupType('ChallengeCommitmentMessage');

    const challengeCommitmentMessage = new Buffer(ChallengeCommitmentMessage.encode({
      a: encodeBN(this.a),
      b: encodeBN(this.b)
    }).finish());

    const { commitment, decommitment } = this.localPedersenScheme.commit(challengeCommitmentMessage);

    this.localRevealDecommitment = decommitment;

    return ChallengeCommitment.fromOptions({
      curve: this.curve,
      challenge: challenge,
      revealCommitment: commitment
    });
  }

  processResponseCommitment(remote) {
    this.remoteResponseCommitment = remote.responseCommitment;

    return ChallengeDecommitment.fromOptions({
      curve: this.curve,
      revealDecommitment: this.localRevealDecommitment,
      a: this.a,
      b: this.b
    });
  }

  processResponseDecommitment(remote) {
    const message = encodePoint(remote.response);

    assert(PedersenScheme.verify(
      this.curve,
      this.remotePedersenParameters,
      message,
      this.remoteResponseCommitment,
      remote.responseDecommitment
    ));

    assert(this.remotePublicPoint.mul(this.a).add(this.crypto.g.mul(this.b)).eq(remote.response));

    return VerifierSyncData.fromOptions({
      curve: this.curve,
      publicPoint: this.remotePublicPoint,
      paillierPublicKey: this.remotePaillierPublicKey,
      ciphertext: this.remoteCiphertext
    });
  }
}
