'use strict';

import assert from 'assert';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { PedersenScheme } from '../pedersenscheme';
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
  toBigInteger,
  toBN
} from "../../convert";

import { PaillierPublicKey, PaillierSecretKey } from "./paillierkeys";

export class InitialCommitment {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.pedersenParameters = null;
    this.initialCommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.pedersenParameters = options.pedersenParameters;
    this.initialCommitment = options.initialCommitment;

    return this;
  }

  static fromOptions(options) {
    return new InitialCommitment().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      pedersenParameters: encodePoint(this.pedersenParameters, hex),
      initialCommitment: encodePoint(this.initialCommitment, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.pedersenParameters = decodePoint(this.crypto, json.pedersenParameters, hex);
    this.initialCommitment = decodePoint(this.crypto, json.initialCommitment, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new InitialCommitment().fromJSON(json, hex);
  }
}

export class InitialDecommitment {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.paillierPublicKey = null;
    this.publicPoint = null;
    this.chiphertext = null;
    this.initialDecommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.paillierPublicKey = options.paillierPublicKey;
    this.publicPoint = options.publicPoint;
    this.chiphertext = options.chiphertext;
    this.initialDecommitment = options.initialDecommitment;

    return this;
  }

  static fromOptions(options) {
    return new InitialDecommitment().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      paillierPublicKey: toJSON(this.paillierPublicKey, hex),
      publicPoint: encodePoint(this.publicPoint, hex),
      chiphertext: encodeBigInteger(this.chiphertext, hex),
      initialDecommitment: encodeBN(this.initialDecommitment)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.paillierPublicKey = fromJSON(PaillierPublicKey, json.paillierPublicKey, hex);
    this.publicPoint = decodePoint(this.crypto, json.publicPoint, hex);
    this.chiphertext = decodeBigInteger(json.chiphertext, hex);
    this.initialDecommitment = decodeBN(json.initialDecommitment, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new InitialDecommitment().fromJSON(json, hex);
  }
}

export class ResponseCommitment {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.responseCommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.responseCommitment = options.responseCommitment;

    return this;
  }

  static fromOptions(options) {
    return new ResponseCommitment().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      responseCommitment: encodePoint(this.responseCommitment, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.responseCommitment = decodePoint(this.crypto, json.responseCommitment, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new ResponseCommitment().fromJSON(json, hex);
  }
}

export class ProoverSyncData {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.publicPoint = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.publicPoint = options.publicPoint;

    return this;
  }

  static fromOptions(options) {
    return new ProoverSyncData().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      publicPoint: encodePoint(this.publicPoint, hex),
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.publicPoint = decodePoint(this.crypto, json.publicPoint, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new ProoverSyncData().fromJSON(json, hex);
  }
}

export class ResponseDecommitment {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.responseDecommitment = null;
    this.response = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.responseDecommitment = options.responseDecommitment;
    this.response = options.response;

    return this;
  }

  static fromOptions(options) {
    return new ResponseDecommitment().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      responseDecommitment: encodeBN(this.responseDecommitment, hex),
      response: encodePoint(this.response, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.responseDecommitment = decodeBN(json.responseDecommitment, hex);
    this.response = decodePoint(this.crypto, json.response, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new ResponseDecommitment().fromJSON(json, hex);
  }
}

export class PaillierProver {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.localPaillierPublicKey = null;
    this.localPaillierSecretKey = null;
    this.localPrivateKey = null;

    this.localPedersenScheme = null;

    this.alpha = null;

    this.remotePublicPoint = null;

    this.remotePedersenParameters = null;

    this.localChiphertext = null;
    this.localInitialDecommitment = null;
    this.remoteRevealCommitment = null;
    this.localResponseDecommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPaillierPublicKey = options.localPaillierPublicKey;
    this.localPaillierSecretKey = options.localPaillierSecretKey;
    this.localPrivateKey = options.localPrivateKey;

    this.localPedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new PaillierProver().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      localPaillierPublicKey: toJSON(this.localPaillierPublicKey, hex),
      localPaillierSecretKey: toJSON(this.localPaillierSecretKey, hex),
      localPrivateKey: encodeBN(this.localPrivateKey, hex),
      localPedersenScheme: toJSON(this.localPedersenScheme, hex),
      alpha: encodeBN(this.alpha, hex),
      remotePublicPoint: encodePoint(this.remotePublicPoint, hex),
      remotePedersenParams: encodePoint(this.remotePedersenParams, hex),
      localChiphertext: encodeBigInteger(this.localChiphertext, hex),
      localInitialDecommitment: encodeBN(this.localInitialDecommitment, hex),
      remoteRevealCommitment: encodePoint(this.remoteRevealCommitment, hex),
      localResponseDecommitment: encodeBN(this.localResponseDecommitment, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPaillierPublicKey = fromJSON(PaillierPublicKey, json.localPaillierPublicKey, hex);
    this.localPaillierSecretKey = fromJSON(PaillierSecretKey, json.localPaillierSecretKey, hex);
    this.localPrivateKey = decodeBN(json.localPrivateKey, hex);
    this.localPedersenScheme = fromJSON(PedersenScheme, json.localPedersenScheme, hex);
    this.alpha = decodeBN(json.alpha, hex);
    this.remotePublicPoint = decodePoint(this.crypto, json.remotePublicPoint, hex);
    this.remotePedersenParams = decodePoint(this.crypto, json.iComremotePedersenParamsmitment, hex);
    this.localChiphertext = decodeBigInteger(json.localChiphertext, hex),
    this.localInitialDecommitment = decodeBN(json.localInitialDecommitment, hex);
    this.remoteRevealCommitment = decodePoint(this.crypto, json.remoteRevealCommitment, hex);
    this.localResponseDecommitment = decodeBN(json.localResponseDecommitment, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new PaillierProver().fromJSON(json, hex);
  }

  createInitialCommitment() {
    const publicPoint = this.crypto.g.mul(this.localPrivateKey);

    this.localChiphertext = this.localPaillierPublicKey.encrypt(toBigInteger(this.localPrivateKey));

    const data = {
      paillierPublicKey: toJSON(this.localPaillierPublicKey, true),
      publicPoint: encodePoint(publicPoint, true),
      chiphertext: encodeBigInteger(this.localChiphertext, true)
    };

    const message = Buffer.from(JSON.stringify(data), 'ascii');

    const { commitment, decommitment } = this.localPedersenScheme.commit(message);

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
    const message = Buffer.from(JSON.stringify({
      a: encodeBN(remote.a, true),
      b: encodeBN(remote.b, true)
    }), 'ascii');

    assert(PedersenScheme.verify(
      this.curve,
      this.remotePedersenParameters,
      message,
      this.remoteRevealCommitment,
      remote.revealDecommitment
    ));

    const alpha = this.localPrivateKey.mul(remote.a).iadd(remote.b);

    assert(this.alpha.cmp(alpha) === 0);
    
    const response = this.crypto.g.mul(this.alpha);

    return {
      prooverSyncData: ProoverSyncData.fromOptions({
        curve: this.curve,
        publicPoint: this.remotePublicPoint
      }),
      responseDecommitment: ResponseDecommitment.fromOptions({
        curve: this.curve,
        responseDecommitment: this.localResponseDecommitment,
        response: response
      })
    };
  }
}
