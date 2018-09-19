'use strict';

const assert = require('assert');
const { utils } = require('elliptic');
const { Buffer } = require('buffer');

const { EddsaKeyPair } = require("./keypair");
const { PedersenScheme } = require('../pedersenscheme');
const { SchnorrProof } = require("../schnorrproof");

const {
  toJSON,
  encodePoint,
  generateMessage,
  Field
} = require("../../convert");

const { Root } = require('protobufjs');
const proto = require('./distributedsignsession.json');

const root = Root.fromJSON(proto);

const EddsaEntropyCommitment = generateMessage(
  'EddsaEntropyCommitment', {
    pedersenParameters: [Field.Point],
    entropyCommitment: [Field.Point]
  },
  root
);

const EddsaEntropyDecommitment = generateMessage(
  'EddsaEntropyDecommitment', {
    publicEntropy: [Field.Point],
    schnorrProof: [Field.Custom, SchnorrProof],
    entropyDecommitment: [Field.BN]
  },
  root
);

const EddsaEntropyData = generateMessage(
  'EddsaEntropyData', {
    publicEntropy: [Field.Point],
    schnorrProof: [Field.Custom, SchnorrProof]
  },
  root
);

const EddsaPartialSignature = generateMessage(
  'EddsaPartialSignature', {
    partialSignature: [Field.BN]
  },
  root
);

const EddsaSignature = generateMessage(
  'EddsaSignature', {
    compoundPublicEntropy: [Field.Point],
    signature: [Field.BN]
  },
  root
);

function generateR(crypto, privateKey, message) {
  const rb = EddsaKeyPair.hash(privateKey.messagePrefix, message);
  return utils.intFromLE(rb).umod(crypto.curve.n);
}

class DistributedEddsaSignSession extends generateMessage(
  'DistributedEddsaSignSession', {
    localPrivateKey: [Field.Custom, EddsaKeyPair],
    message: [Field.Buffer],
    compoundPublicPoint: [Field.Point],
    compoundPublicEntropy: [Field.Point],
    localPrivateEntropy: [Field.BN],
    localPedersenScheme: [Field.Custom, PedersenScheme],
    localEntropyDecommitment: [Field.BN]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPrivateEntropy = generateR(this.crypto, this.localPrivateKey, this.message);
    this.localPedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new DistributedEddsaSignSession().fromOptions(options);
  }
  
  static fromJSON(json, hex) {
    return new DistributedEddsaSignSession().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEddsaSignSession().fromBytes(bytes);
  }

  createEntropyCommitment() {
    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);
    this.localSchnorrProof = SchnorrProof.fromOptions({
        curve: this.curve,
        x: this.localPrivateEntropy
    });

    const EntropyCommitmentMessage = root.lookupType('EddsaEntropyCommitmentMessage');

    const entropyCommitmentMessage = new Buffer(EntropyCommitmentMessage.encode({
      publicEntropy: encodePoint(publicEntropy),
      schnorrProof: toJSON(this.localSchnorrProof)
    }).finish());

    const { commitment, decommitment } = this.localPedersenScheme.commit(entropyCommitmentMessage);

    this.localEntropyDecommitment = decommitment;

    return EddsaEntropyCommitment.fromOptions({
      curve: this.curve,
      pedersenParameters: this.localPedersenScheme.getParameters(),
      entropyCommitment: commitment
    });
  }

  processEntropyData(remote) {
    assert(remote.schnorrProof.verify(remote.publicEntropy));

    this.compoundPublicEntropy = remote.publicEntropy.add(this.crypto.g.mul(this.localPrivateEntropy));

    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);

    return EddsaEntropyDecommitment.fromOptions({
      curve: this.curve,
      publicEntropy: publicEntropy,
      schnorrProof: this.localSchnorrProof,
      entropyDecommitment: this.localEntropyDecommitment
    });
  }

  finalizeSignature(remote) {
    const Rencoded = this.crypto.encodePoint(this.compoundPublicEntropy);

    const hb = EddsaKeyPair.hash(Rencoded, this.crypto.encodePoint(this.compoundPublicPoint), this.message);

    const h = utils.intFromLE(hb).mul(this.localPrivateKey.private);

    const s = this.localPrivateEntropy.add(h).umod(this.crypto.curve.n);

    const signature = remote.partialSignature.add(s).umod(this.crypto.curve.n);

    return EddsaSignature.fromOptions({
      curve: this.curve,
      compoundPublicEntropy: this.compoundPublicEntropy,
      signature: signature
    });
  }
}

class DistributedEddsaSignSessionShard extends generateMessage(
  'DistributedEddsaSignSessionShard', {
    localPrivateKey: [Field.Custom, EddsaKeyPair],
    message: [Field.Buffer],
    compoundPublicPoint: [Field.Point],
    compoundPublicEntropy: [Field.Point],
    localPrivateEntropy: [Field.BN],
    remotePedersenParameters: [Field.Point],
    remoteEntropyCommitment: [Field.Point]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPrivateEntropy = generateR(this.crypto, this.localPrivateKey, this.message);

    return this;
  }

  static fromOptions(options) {
    return new DistributedEddsaSignSessionShard().fromOptions(options);
  }
  
  static fromJSON(json, hex) {
    return new DistributedEddsaSignSessionShard().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEddsaSignSessionShard().fromBytes(bytes);
  }

  processEntropyCommitment(remote) {
    this.remotePedersenParameters = remote.pedersenParameters;
    this.remoteEntropyCommitment = remote.entropyCommitment;

    const publicEntropy = this.crypto.g.mul(this.localPrivateEntropy);
    const schnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateEntropy
    });

    return EddsaEntropyData.fromOptions({
      curve: this.curve,
      publicEntropy: publicEntropy,
      schnorrProof: schnorrProof
    });
  }

  processEntropyDecommitment(remote) {
    const EntropyCommitmentMessage = root.lookupType('EddsaEntropyCommitmentMessage');

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

    this.compoundPublicEntropy = remote.publicEntropy.add(this.crypto.g.mul(this.localPrivateEntropy));

    const Rencoded = this.crypto.encodePoint(this.compoundPublicEntropy);

    const hb = EddsaKeyPair.hash(Rencoded, this.crypto.encodePoint(this.compoundPublicPoint), this.message);

    const h = utils.intFromLE(hb).mul(this.localPrivateKey.private);

    const s = this.localPrivateEntropy.add(h).umod(this.crypto.curve.n);

    return EddsaPartialSignature.fromOptions({
      curve: this.curve,
      partialSignature: s
    });
  }
}

module.exports = {
  EddsaEntropyCommitment,
  EddsaEntropyDecommitment,
  EddsaEntropyData,
  EddsaPartialSignature,
  EddsaSignature,
  DistributedEddsaSignSession,
  DistributedEddsaSignSessionShard
};
