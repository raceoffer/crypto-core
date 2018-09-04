'use strict';

import assert from 'assert';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { PedersenScheme } from '../pedersenscheme';

import {
  toJSON,
  encodePoint,
  encodeBigInteger,
  encodeBN,
  toBigInteger,
  toBN,
  generateMessage,
  Field
} from "../../convert";

import { PaillierPublicKey, PaillierSecretKey } from "./paillierkeys";

import { Root } from 'protobufjs';
import * as proto from './paillierprover.json';

const root = Root.fromJSON(proto);

export const InitialCommitment = generateMessage(
  'InitialCommitment', {
    pedersenParameters: [Field.Point],
    initialCommitment: [Field.Point]
  },
  root
);

export const InitialDecommitment = generateMessage(
  'InitialDecommitment', {
    paillierPublicKey: [Field.Custom, PaillierPublicKey],
    publicPoint: [Field.Point],
    chiphertext: [Field.BigInteger],
    initialDecommitment: [Field.BN]
  },
  root
);

export const ResponseCommitment = generateMessage(
  'ResponseCommitment', {
    responseCommitment: [Field.Point]
  },
  root
);

export const ResponseDecommitment = generateMessage(
  'ResponseDecommitment', {
    responseDecommitment: [Field.BN],
    response: [Field.Point]
  },
  root
);

export const ProverSyncData = generateMessage(
  'ProverSyncData', {
    publicPoint: [Field.Point]
  },
  root
);

export class PaillierProver extends generateMessage(
  'PaillierProver', {
    localPaillierPublicKey: [Field.Custom, PaillierPublicKey],
    localPaillierSecretKey: [Field.Custom, PaillierSecretKey],
    localPrivateKey: [Field.BN],
    localPedersenScheme: [Field.Custom, PedersenScheme],
    alpha: [Field.BN],
    remotePublicPoint: [Field.Point],
    remotePedersenParameters: [Field.Point],
    localChiphertext: [Field.BigInteger],
    localInitialDecommitment: [Field.BN],
    remoteRevealCommitment: [Field.Point],
    localResponseDecommitment: [Field.BN]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new PaillierProver().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new PaillierProver().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new PaillierProver().fromBytes(bytes);
  }

  createInitialCommitment() {
    const publicPoint = this.crypto.g.mul(this.localPrivateKey);

    this.localChiphertext = this.localPaillierPublicKey.encrypt(toBigInteger(this.localPrivateKey));

    const InitialCommitmentMessage = root.lookupType('InitialCommitmentMessage');

    const initialCommitmentMessage = new Buffer(InitialCommitmentMessage.encode({
      paillierPublicKey: toJSON(this.localPaillierPublicKey),
      publicPoint: encodePoint(publicPoint),
      chiphertext: encodeBigInteger(this.localChiphertext)
    }).finish());

    const { commitment, decommitment } = this.localPedersenScheme.commit(initialCommitmentMessage);

    this.localInitialDecommitment = decommitment;

    return InitialCommitment.fromOptions({
      curve: this.curve,
      pedersenParameters: this.localPedersenScheme.getParameters(),
      initialCommitment: commitment
    });
  }

  processInitialData(remote) {
    assert(remote.schnorrProof.verify(remote.publicPoint));

    this.remotePublicPoint = remote.publicPoint;
    this.remotePedersenParameters = remote.pedersenParameters;
    
    return InitialDecommitment.fromOptions({
      curve: this.curve,
      paillierPublicKey: this.localPaillierPublicKey,
      publicPoint: this.crypto.g.mul(this.localPrivateKey),
      chiphertext: this.localChiphertext,
      initialDecommitment: this.localInitialDecommitment
    });
  }

  processChallengeCommitment(remote) {
    this.alpha = toBN(this.localPaillierSecretKey.decrypt(remote.challenge));

    this.remoteRevealCommitment = remote.revealCommitment;

    const response = this.crypto.g.mul(this.alpha);

    const message = encodePoint(response);

    const { commitment, decommitment } = this.localPedersenScheme.commit(message);

    this.localResponseDecommitment = decommitment;

    return ResponseCommitment.fromOptions({
      curve: this.curve,
      responseCommitment: commitment
    });
  }

  processChallengeDecommitment(remote) {
    const ChallengeCommitmentMessage = root.lookupType('ChallengeCommitmentMessage');

    const challengeCommitmentMessage = new Buffer(ChallengeCommitmentMessage.encode({
      a: encodeBN(remote.a),
      b: encodeBN(remote.b)
    }).finish());

    assert(PedersenScheme.verify(
      this.curve,
      this.remotePedersenParameters,
      challengeCommitmentMessage,
      this.remoteRevealCommitment,
      remote.revealDecommitment
    ));

    const alpha = this.localPrivateKey.mul(remote.a).iadd(remote.b);

    assert(this.alpha.cmp(alpha) === 0);
    
    const response = this.crypto.g.mul(this.alpha);

    return {
      responseDecommitment: ResponseDecommitment.fromOptions({
        curve: this.curve,
        responseDecommitment: this.localResponseDecommitment,
        response: response
      }),
      proverSyncData: ProverSyncData.fromOptions({
        curve: this.curve,
        publicPoint: this.remotePublicPoint
      })
    };
  }
}
