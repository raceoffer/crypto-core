'use strict';

import assert from 'assert';

import BN from 'bn.js';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

import { PedersenScheme } from '../pedersenscheme';

import { randomBytes } from '../../utils';
import { matchCurve } from "../../curves";

import {
  toJSON,
  fromJSON,
  encodePoint,
  decodePoint,
  encodeBigInteger,
  decodeBigInteger,
  decodeBN,
  encodeBN,
  toBigInteger
} from "../../convert";

import { PaillierPublicKey } from "./paillierkeys";
import { SchnorrProof } from '../schnorrproof';

export class InitialData {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.pedersenParameters = null;
    this.publicPoint = null;
    this.schnorrProof = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.pedersenParameters = options.pedersenParameters;
    this.publicPoint = options.publicPoint;
    this.schnorrProof = options.schnorrProof;

    return this;
  }

  static fromOptions(options) {
    return new InitialData().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      pedersenParameters: encodePoint(this.pedersenParameters, hex),
      publicPoint: encodePoint(this.publicPoint, hex),
      schnorrProof: toJSON(this.schnorrProof, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.pedersenParameters = decodePoint(this.crypto, json.pedersenParameters, hex);
    this.publicPoint = decodePoint(this.crypto, json.publicPoint, hex);
    this.schnorrProof = fromJSON(SchnorrProof, json.schnorrProof, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new InitialData().fromJSON(json, hex);
  }
}

export class ChallengeCommitment {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.challenge = null;
    this.revealCommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.challenge = options.challenge;
    this.revealCommitment = options.revealCommitment;

    return this;
  }

  static fromOptions(options) {
    return new ChallengeCommitment().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      challenge: encodeBigInteger(this.challenge, hex),
      revealCommitment: encodePoint(this.revealCommitment, hex),
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.challenge = decodeBigInteger(json.challenge, hex);
    this.revealCommitment = decodePoint(this.crypto, json.revealCommitment, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new ChallengeCommitment().fromJSON(json, hex);
  }
}

export class ChallengeDecommitment {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.revealDecommitment = null;
    this.a = null;
    this.b = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.revealDecommitment = options.revealDecommitment;
    this.a = options.a;
    this.b = options.b;

    return this;
  }

  static fromOptions(options) {
    return new ChallengeDecommitment().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      revealDecommitment: encodeBN(this.revealDecommitment, hex),
      a: encodeBN(this.a, hex),
      b: encodeBN(this.b, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.revealDecommitment = decodeBN(json.revealDecommitment, hex);
    this.a = decodeBN(json.a, hex);
    this.b = decodeBN(json.b, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new ChallengeDecommitment().fromJSON(json, hex);
  }
}

export class VerifierSyncData {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.publicPoint = null;
    this.paillierPublicKey = null;
    this.ciphertext = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.publicPoint = options.publicPoint;
    this.paillierPublicKey = options.paillierPublicKey;
    this.ciphertext = options.ciphertext;

    return this;
  }

  static fromOptions(options) {
    return new VerifierSyncData().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      publicPoint: encodePoint(this.publicPoint, hex),
      paillierPublicKey: toJSON(this.paillierPublicKey, hex),
      ciphertext: encodeBigInteger(this.ciphertext, hex),
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.publicPoint = decodePoint(this.crypto, json.publicPoint, hex);
    this.paillierPublicKey = fromJSON(PaillierPublicKey, json.paillierPublicKey, hex);
    this.ciphertext = decodeBigInteger(json.ciphertext, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new VerifierSyncData().fromJSON(json, hex);
  }
}

export class PaillierVerifier {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.localPrivateKey = null;

    this.localPedersenScheme = null;

    this.a = null;
    this.b = null;

    this.remotePublicPoint = null;
    this.remotePaillierPublicKey = null;
    this.remoteCiphertext = null;

    this.remotePedersenParameters = null;
    this.remoteInitialCommitment = null;
    this.localRevealDecommitment = null;
    this.remoteResponseCommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = options.localPrivateKey;
    this.localPedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new PaillierVerifier().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      localPrivateKey: encodeBN(this.localPrivateKey, hex),
      localPedersenScheme: toJSON(this.localPedersenScheme, hex),
      a: encodeBN(this.a, hex),
      b: encodeBN(this.b, hex),
      remotePublicPoint: encodePoint(this.remotePublicPoint, hex),
      remotePaillierPublicKey: toJSON(this.remotePaillierPublicKey, hex),
      remoteCiphertext: encodeBigInteger(this.remoteCiphertext, hex),
      remotePedersenParameters: encodePoint(this.remotePedersenParameters),
      remoteInitialCommitment: encodePoint(this.remoteInitialCommitment),
      localRevealDecommitment: encodeBN(this.localRevealDecommitment, hex),
      remoteResponseCommitment: encodePoint(this.remoteResponseCommitment, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = decodeBN(json.localPrivateKey, hex);
    this.localPedersenScheme = fromJSON(PedersenScheme, json.localPedersenScheme, hex);
    this.a = decodeBN(json.a, hex);
    this.b = decodeBN(json.b, hex);
    this.remotePublicPoint = decodePoint(this.crypto, json.remotePublicPoint, hex);
    this.remotePaillierPublicKey = fromJSON(PaillierPublicKey, json.remotePaillierPublicKey, hex);
    this.remoteCiphertext = decodeBigInteger(json.remoteCiphertext, hex);
    this.remotePedersenParameters = decodePoint(this.crypto, json.remotePedersenParameters);
    this.remoteInitialCommitment = decodePoint(this.crypto, json.remoteInitialCommitment);
    this.localRevealDecommitment = decodeBN(json.localRevealDecommitment, hex);
    this.remoteResponseCommitment = decodePoint(this.crypto, json.remoteResponseCommitment, hex);

    return this;
  }

  static fromJSON(json) {
    return new PaillierVerifier().fromJSON(json);
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
    const data = {
      paillierPublicKey: toJSON(remote.paillierPublicKey, true),
      publicPoint: encodePoint(remote.publicPoint, true),
      chiphertext: encodeBigInteger(remote.chiphertext, true)
    };

    const message = Buffer.from(JSON.stringify(data), 'ascii');

    assert(PedersenScheme.verify(
      this.curve,
      this.remotePedersenParameters,
      message,
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

    const { commitment, decommitment } = this.localPedersenScheme.commit(Buffer.from(JSON.stringify({
      a: encodeBN(this.a, true),
      b: encodeBN(this.b, true)
    }), 'ascii'));

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
