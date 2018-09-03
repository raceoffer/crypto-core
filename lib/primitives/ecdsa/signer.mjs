'use strict';

import assert from 'assert';

import BN from 'bn.js';
import HmacDRBG from 'hmac-drbg';
import Signature from 'elliptic/lib/elliptic/ec/signature';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { SchnorrProof } from '../schnorrproof';
import { PedersenScheme } from '../pedersenscheme';

import { matchCurve } from '../../curves';
import { randomBytes } from "../../utils";

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
  toBN,
  decodeBuffer,
  encodeBuffer
} from "../../convert";

import { PaillierPublicKey, PaillierSecretKey } from "./paillierkeys";

export class EntropyCommitment {
  constructor () {
    this.curve = null;
    this.crypto = null;

    this.pedersenParameters = null;
    this.entropyCommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.pedersenParameters = options.pedersenParameters;
    this.entropyCommitment = options.entropyCommitment;

    return this;
  }

  static fromOptions(options) {
    return new EntropyCommitment().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      pedersenParameters: encodePoint(this.pedersenParameters, hex),
      entropyCommitment: encodePoint(this.entropyCommitment, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(json.curve);

    this.pedersenParameters = decodePoint(this.crypto, pedersenParameters, hex);
    this.entropyCommitment = decodePoint(this.crypto, entropyCommitment, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new EntropyCommitment().fromJSON(json, hex);
  }
}

export class EntropyDecommitment {
  constructor () {
    this.curve = null;
    this.crypto = null;

    this.publicEntropy = null;
    this.schnorrProof = null;
    this.entropyDecommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.publicEntropy = options.publicEntropy;
    this.schnorrProof = options.schnorrProof;
    this.entropyDecommitment = options.entropyDecommitment;

    return this;
  }

  static fromOptions(options) {
    return new EntropyDecommitment().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      publicEntropy: encodePoint(this.publicEntropy, hex),
      schnorrProof: toJSON(this.schnorrProof, hex),
      entropyDecommitment: encodeBN(this.entropyDecommitment, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(json.curve);

    this.publicEntropy = decodePoint(this.crypto, json.publicEntropy, hex);
    this.schnorrProof = fromJSON(SchnorrProof, json.schnorrProof, hex);
    this.entropyDecommitment = decodeBN(json.entropyDecommitment, hex);

    return this;
  }

  static fromJSON(json, hex) {
    return new EntropyDecommitment().fromJSON(json, hex);
  }
}

export class PartialSignature {
  constructor() {
    this.e = null;
  }

  fromOptions(options) {
    this.e = options.e;

    return this;
  }

  static fromOptions(options) {
    return new PartialSignature().fromOptions(options);
  }

  toJSON() {
    return {
      e: encodeBigInteger(this.e)
    };
  }

  fromJSON(json) {
    this.e = decodeBigInteger(json.e);

    return this;
  }

  static fromJSON(json) {
    return new PartialSignature().fromJSON(json);
  }
}

function generateK(crypto, privateKey, message) {
  const key = privateKey;
  const msg = crypto._truncateToN(new BN(message, 16));

  const bytes = crypto.n.byteLength();
  const bkey = key.toArray('be', bytes);

  const nonce = msg.toArray('be', bytes);

  const drbg = new HmacDRBG({
    hash: crypto.hash,
    entropy: bkey,
    nonce: nonce,
    pers: null,
    persEnc: 'utf8'
  });

  const ns1 = crypto.n.sub(new BN(1));

  let k = null;
  do {
    k = new BN(drbg.generate(bytes));
    k = crypto._truncateToN(k, true);
  } while (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0);

  return k;
}

export class PartialSigner {
  constructor() {
    this.curve = null;
    this.crypto = null;

    this.localPrivateKey = null;

    this.message = null;
    
    this.localPaillierSecretKey = null;

    this.localPrivateEntropy = null;
    this.compoundPublicEntropy = null;
    this.compoundScalarEntropy = null;

    this.localSchnorrProof = null;
    this.localPedersenScheme = null;
    this.localEntropyDecommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = options.localPrivateKey;

    this.message = options.message;

    this.localPaillierSecretKey = options.localPaillierSecretKey;

    this.localPedersenScheme = PedersenScheme.generate(this.curve);

    this.k = generateK(this.localPrivateKey, this.message);

    return this;
  }

  static fromOptions(options) {
    return new PartialSigner().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      localPrivateKey: encodeBN(this.localPrivateKey, hex),
      message: hex ? encodeBuffer(this.message, hex) : this.message,
      localPaillierSecretKey: toJSON(this.localPaillierSecretKey, hex),
      localPrivateEntropy: encodeBN(this.localPrivateEntropy, hex),
      compoundPublicEntropy: encodePoint(this.compoundPublicEntropy, hex),
      compoundScalarEntropy: encodeBN(this.compoundScalarEntropy, hex),
      localSchnorrProof: toJSON(this.localSchnorrProof, hex),
      localPedersenScheme: toJSON(this.localPedersenScheme, hex),
      localEntropyDecommitment: toJSON(this.localEntropyDecommitment, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = decodeBN(json.localPrivateKey, hex);

    this.message = hex ? decodeBuffer(json.message, hex) : json.message;

    this.localPaillierSecretKey = fromJSON(PaillierSecretKey, json.localPaillierSecretKey, hex);
    
    this.localPrivateEntropy = decodeBN(json.localPrivateEntropy, hex);
    this.compoundPublicEntropy = decodePoint(this.crypto, json.compoundPublicEntropy, hex);
    this.compoundScalarEntropy = decodeBN(json.compoundScalarEntropy, hex);

    this.localSchnorrProof = fromJSON(SchnorrProof, json.localSchnorrProof, hex);
    this.localPedersenScheme = fromJSON(PedersenScheme, json.localPedersenScheme, hex);
    this.localDecommitment = fromJSON(PedersenDecommitment, json.localDecommitment, hex);

    return this;
  }

  static fromJSON(json) {
    return new PartialSigner().fromJSON(json);
  }

  createEntropyCommitment() {
    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);
    
    this.localSchnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateEntropy
    });

    const EntropyCommitmentMessage = root.lookupType('EntropyCommitmentMessage');

    const entropyCommitmentMessage = new Buffer(EntropyCommitmentMessage.create({
      publicEntropy: encodePoint(publicEntropy),
      schnorrProof: toJSON(schnorrProof)
    }).finish());

    const { commitment, decommitment } = this.localPedersenScheme.commit(entropyCommitmentMessage);

    this.localEntropyDecommitment = decommitment;

    return EntropyCommitment.fromOptions({
      curve: this.curve,
      pedersenParameters: this.pedersenScheme.getParameters(),
      entropyCommitment: commitment
    });
  }

  processEntropyData(remote) {
    assert(remote.schnorrProof.verify(remote.publicEntropy));

    this.compoundPublicEntropy = remote.publicEntropy.mul(this.localPrivateEntropy);
    this.compoundScalarEntropy = this.compoundPublicEntropy.getX().umod(this.crypto.n);

    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);

    return EntropyDecommitment.fromOptions({
      curve: this.curve,
      publicEntropy: publicEntropy,
      schnorrProof: this.localSchnorrProof,
      entropyDecommitment: this.localEntropyDecommitment
    });
  }

  finalizeSignature(remote) {
    const d = toBN(this.localPaillierSecretKey.decrypt(remote.partialSignature));

    let S = this.localPrivateEntropy.invm(this.crypto.n).mul(d).umod(this.crypto.n);

    let recoveryParameter = (this.compoundPublicEntropy.getY().isOdd() ? 1 : 0) | (this.R.getX().cmp(this.compoundScalarEntropy) !== 0 ? 2 : 0);

    if (S.cmp(this.crypto.nh) > 0) {
      S = this.crypto.n.sub(S);
      recoveryParameter ^= 1;
    }

    return new Signature({
      r: this.compoundScalarEntropy,
      s: S,
      recoveryParam: recoveryParameter
    });
  }
}

export class PartialSignerShard {
  constructor () {
    this.curve = null;
    this.crypto = null;

    this.localPrivateKey = null;

    this.message = null;

    this.remotePaillierPublicKey = null;
    this.remoteCiphertext = null;

    this.localPrivateEntropy = null;
    this.compoundPublicEntropy = null;
    this.compoundScalarEntropy = null;

    this.remotePedersnParameters = null;
    this.remoteEntropyCommitment = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = options.localPrivateKey;

    this.message = options.message;
    
    this.remotePaillierPublicKey = options.remotePaillierPublicKey;
    this.remotePrivateCiphertext = options.remotePrivateCiphertext;

    this.k = generateK(this.localPrivateKey, this.message);

    return this;
  }

  static fromOptions(options) {
    return new PartialSignerShard().fromOptions(options);
  }

  toJSON(hex) {
    return {
      curve: this.curve,
      localPrivateKey: encodeBN(this.localPrivateKey, hex),
      message: hex ? encodeBuffer(this.message, hex) : this.message,
      remotePaillierPublicKey: toJSON(this.remotePaillierPublicKey, hex),
      remotePrivateCiphertext: encodeBigInteger(this.remotePrivateCiphertext, hex),
      localPrivateEntropy: encodeBN(this.localPrivateEntropy, hex),
      compoundPublicEntropy: encodePoint(this.compoundPublicEntropy, hex),
      compoundScalarEntropy: encodeBN(this.compoundScalarEntropy, hex),
      remotePedersenParameterss: toJSON(this.remotePedersenParameterss, hex),
      remoteEntropyCommitment: toJSON(this.remoteEntropyCommitment, hex)
    };
  }

  fromJSON(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = decodeBN(json.localPrivateKey, hex);

    this.message = hex ? decodeBuffer(json.message) : json.message;

    this.remotePaillierPublicKey = fromJSON(PaillierPublicKey, json.remotePaillierPublicKey, hex);
    this.remotePrivateCiphertext = decodeBigInteger(json.remotePrivateCiphertext, hex);
    
    this.localPrivateEntropy = decodeBN(json.localPrivateEntropy, hex);
    this.compoundPublicEntropy = decodePoint(this.crypto, json.compoundPublicEntropy, hex);
    this.compoundScalarEntropy = decodeBN(json.compoundScalarEntropy, hex);

    this.remotePedersenParameterss = fromJSON(PedersenParameters, json.remotePedersenParameterss, hex);
    this.remoteEntropyCommitment = fromJSON(PedersenCommitment, json.remoteEntropyCommitment, hex);

    return this;
  }

  static fromJSON(json) {
    return new PartialSignerShard().fromJSON(json);
  }

  processEntropyCommitment(remote) {
    this.remotePedersenParameters = remote.pedersenParameters;
    this.remoteEntropyCommitment = remote.entropyCommitment;

    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);
    const schnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateEntropy
    });

    return EntropyData.fromOptions({
      curve: this.curve,
      publicEntropy: publicEntropy,
      schnorrProof: schnorrProof
    });
  }

  processEntropyDecommitment(remote) {
    const EntropyCommitmentMessage = root.lookupType('EntropyCommitmentMessage');

    const entropyCommitmentMessage = new Buffer(EntropyCommitmentMessage.create({
      publicEntropy: encodePoint(remote.publicEntropy),
      schnorrProof: toJSON(remote.schnorrProof)
    }).finish());

    assert(PedersenScheme.verify(
      this.curve,
      this.remotePedersenParameters,
      entropyCommitmentMessage,
      this.remoteEntropyCommitment,
      remote.entropyDecommitment
    ));

    assert(remote.schnorrProof.verify(remote.publicEntropy));

    this.compoundPublicEntropy = remote.publicEntropy.mul(this.localPrivateEntropy);
    this.compoundScalarEntropy = this.compoundPublicEntropy.getX().umod(this.crypto.n);

    const p = this.remotePaillierPublicKey;
    const c = this.remotePrivateCiphertext;
    const x = this.localPrivateKey;
    const m = this.crypto._truncateToN(new BN(this.message, 16));

    const t = new BN(randomBytes(32));

    const a = this.k.invm(this.crypto.n).mul(x).mul(this.r).umod(this.crypto.n);
    const b = this.k.invm(this.crypto.n).mul(m).umod(this.crypto.n).add(t.mul(this.crypto.n));
    const e = p.add(p.mult(c, toBigInteger(a)), p.encrypt(toBigInteger(b)));

    return PartialSignature.fromOptions({ partialSignature: e });
  }
}
