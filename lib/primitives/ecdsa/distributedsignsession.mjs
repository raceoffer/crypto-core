'use strict';

import assert from 'assert';

import BN from 'bn.js';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { PaillierPublicKey, PaillierSecretKey } from './paillierkeys';
import { SchnorrProof } from '../schnorrproof';
import { PedersenScheme } from '../pedersenscheme';

import { randomBytes } from '../../utils';

import {
  toJSON,
  encodePoint,
  toBigInteger,
  toBN,
  Field,
  generateMessage
} from '../../convert';

import HmacDRBG from 'hmac-drbg';

import { Root } from 'protobufjs';
import * as proto from './distributedsignsession.json';

const root = Root.fromJSON(proto);

export const EcdsaEntropyCommitment = generateMessage(
  'EcdsaEntropyCommitment', {
    pedersenParameters: [Field.Point],
    entropyCommitment: [Field.Point]
  },
  root
);

export const EcdsaEntropyDecommitment = generateMessage(
  'EcdsaEntropyDecommitment', {
    publicEntropy: [Field.Point],
    schnorrProof: [Field.Custom, SchnorrProof],
    entropyDecommitment: [Field.BN]
  },
  root
);

export const EcdsaEntropyData = generateMessage(
  'EcdsaEntropyData', {
    publicEntropy: [Field.Point],
    schnorrProof: [Field.Custom, SchnorrProof]
  },
  root
);

export const EcdsaPartialSignature = generateMessage(
  'EcdsaPartialSignature', {
    partialSignature: [Field.BigInteger]
  },
  root
);

export const EcdsaSignature = generateMessage(
  'EcdsaSignature', {
    compoundScalarEntropy: [Field.BN],
    signature: [Field.BN],
    recoveryParameter: [Field.Number]
  },
  root
);

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

export class DistributedEcdsaSignSession extends generateMessage(
  'DistributedEcdsaSignSession', {
    localPrivateKey: [Field.BN],
    message: [Field.Buffer],
    localPaillierSecretKey: [Field.Custom, PaillierSecretKey],
    localPrivateEntropy: [Field.BN],
    compoundPublicEntropy: [Field.Point],
    compoundScalarEntropy: [Field.BN],
    localSchnorrProof: [Field.Custom, SchnorrProof],
    localPedersenScheme: [Field.Custom, PedersenScheme],
    localEntropyDecommitment: [Field.BN]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPrivateEntropy = generateK(this.crypto, this.localPrivateKey, this.message);
    this.localPedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new DistributedEcdsaSignSession().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedEcdsaSignSession().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEcdsaSignSession().fromBytes(bytes);
  }

  createEntropyCommitment() {
    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);
    
    this.localSchnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateEntropy
    });

    const EntropyCommitmentMessage = root.lookupType('EcdsaEntropyCommitmentMessage');

    const entropyCommitmentMessage = new Buffer(EntropyCommitmentMessage.encode({
      publicEntropy: encodePoint(publicEntropy),
      schnorrProof: toJSON(this.localSchnorrProof)
    }).finish());

    const { commitment, decommitment } = this.localPedersenScheme.commit(entropyCommitmentMessage);

    this.localEntropyDecommitment = decommitment;

    return EcdsaEntropyCommitment.fromOptions({
      curve: this.curve,
      pedersenParameters: this.localPedersenScheme.getParameters(),
      entropyCommitment: commitment
    });
  }

  processEntropyData(remote) {
    assert(remote.schnorrProof.verify(remote.publicEntropy));

    this.compoundPublicEntropy = remote.publicEntropy.mul(this.localPrivateEntropy);
    this.compoundScalarEntropy = this.compoundPublicEntropy.getX().umod(this.crypto.n);

    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);

    return EcdsaEntropyDecommitment.fromOptions({
      curve: this.curve,
      publicEntropy: publicEntropy,
      schnorrProof: this.localSchnorrProof,
      entropyDecommitment: this.localEntropyDecommitment
    });
  }

  finalizeSignature(remote) {
    const d = toBN(this.localPaillierSecretKey.decrypt(remote.partialSignature));

    let signature = this.localPrivateEntropy.invm(this.crypto.n).mul(d).umod(this.crypto.n);

    let recoveryParameter = (this.compoundPublicEntropy.getY().isOdd() ? 1 : 0) | (this.compoundPublicEntropy.getX().cmp(this.compoundScalarEntropy) !== 0 ? 2 : 0);

    if (signature.cmp(this.crypto.nh) > 0) {
      signature = this.crypto.n.sub(signature);
      recoveryParameter ^= 1;
    }

    return EcdsaSignature.fromOptions({
      curve: this.curve,
      compoundScalarEntropy: this.compoundScalarEntropy,
      signature: signature,
      recoveryParameter: recoveryParameter
    });
  }
}

export class DistributedEcdsaSignSessionShard extends generateMessage(
  'DistributedEcdsaSignSessionShard', {
    localPrivateKey: [Field.BN],
    message: [Field.Buffer],
    remotePaillierPublicKey: [Field.Custom, PaillierPublicKey],
    remotePrivateCiphertext: [Field.BigInteger],
    localPrivateEntropy: [Field.BN],
    compoundPublicEntropy: [Field.Point],
    compoundScalarEntropy: [Field.BN],
    remotePedersenParameters: [Field.Point],
    remoteEntropyCommitment: [Field.Point]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPrivateEntropy = generateK(this.crypto, this.localPrivateKey, this.message);

    return this;
  }

  static fromOptions(options) {
    return new DistributedEcdsaSignSessionShard().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedEcdsaSignSessionShard().fromJSON(json, hex);
  }

  static fromBytes(json) {
    return new DistributedEcdsaSignSessionShard().fromBytes(json);
  }

  processEntropyCommitment(remote) {
    this.remotePedersenParameters = remote.pedersenParameters;
    this.remoteEntropyCommitment = remote.entropyCommitment;

    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);
    const schnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateEntropy
    });

    return EcdsaEntropyData.fromOptions({
      curve: this.curve,
      publicEntropy: publicEntropy,
      schnorrProof: schnorrProof
    });
  }

  processEntropyDecommitment(remote) {
    const EntropyCommitmentMessage = root.lookupType('EcdsaEntropyCommitmentMessage');

    const entropyCommitmentMessage = new Buffer(EntropyCommitmentMessage.encode({
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

    const k = this.localPrivateEntropy;
    const r = this.compoundScalarEntropy;
    const p = this.remotePaillierPublicKey;
    const c = this.remotePrivateCiphertext;
    const x = this.localPrivateKey;
    const m = this.crypto._truncateToN(new BN(this.message, 16));

    const t = new BN(randomBytes(32));

    const a = k.invm(this.crypto.n).mul(x).mul(r).umod(this.crypto.n);
    const b = k.invm(this.crypto.n).mul(m).umod(this.crypto.n).add(t.mul(this.crypto.n));
    const e = p.add(p.mult(c, toBigInteger(a)), p.encrypt(toBigInteger(b)));

    return EcdsaPartialSignature.fromOptions({
      curve: this.curve,
      partialSignature: e
    });
  }
}
