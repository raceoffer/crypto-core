'use strict';

const assert = require('assert');

const { Buffer } = require('buffer');

const { EddsaKeyPair } = require('../eddsa/keypair');
const { SchnorrProof } = require('../schnorrproof');
const { PedersenScheme } = require('../pedersenscheme');

const {
  toJSON,
  encodePoint,
  generateMessage,
  Field
} = require('../../convert');

const { Root } = require('protobufjs');
const proto = require('./distributedsyncsession.json');

const root = Root.fromJSON(proto);

const EddsaCommitment = generateMessage(
  'EddsaCommitment', {
    pedersenParameters: [Field.Point],
    commitment: [Field.Point]
  },
  root
);

const EddsaDecommitment = generateMessage(
  'EddsaDecommitment', {
    publicPoint: [Field.Point],
    schnorrProof: [Field.Custom, SchnorrProof],
    decommitment: [Field.BN]
  },
  root
);

const EddsaData = generateMessage(
  'EddsaData', {
    publicPoint: [Field.Point],
    schnorrProof: [Field.Custom, SchnorrProof]
  },
  root
);

const EddsaSyncData = generateMessage(
  'EcdsaSyncData', {
    publicPoint: [Field.Point]
  },
  root
);

class DistributedEddsaSyncSession extends generateMessage(
  'DistributedEddsaSyncSession', {
    localPrivateKey: [Field.Custom, EddsaKeyPair],
    localPedersenScheme: [Field.Custom, PedersenScheme],
    localSchnorrProof: [Field.Custom, SchnorrProof],
    localDecommitment: [Field.BN]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPedersenScheme = PedersenScheme.generate(this.curve);

    return this;
  }

  static fromOptions(options) {
    return new DistributedEddsaSyncSession().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedEddsaSyncSession().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEddsaSyncSession().fromBytes(bytes);
  }

  createCommitment() {
    const publicPoint = this.crypto.g.mul(this.localPrivateKey.private);
    this.localSchnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateKey.private
    });

    const CommitmentMessage = root.lookupType('EddsaCommitmentMessage');

    const commitmentMessage = new Buffer(CommitmentMessage.encode({
      publicPoint: encodePoint(publicPoint),
      schnorrProof: toJSON(this.localSchnorrProof)
    }).finish());

    const { commitment, decommitment } = this.localPedersenScheme.commit(commitmentMessage);

    this.localDecommitment = decommitment;

    return EddsaCommitment.fromOptions({
      curve: this.curve,
      pedersenParameters: this.localPedersenScheme.getParameters(),
      commitment: commitment
    });
  }

  processData(remote) {
    assert(remote.schnorrProof.verify(remote.publicPoint));

    const publicPoint = remote.publicPoint;
    
    return {
      decommitment: EddsaDecommitment.fromOptions({
        curve: this.curve,
        publicPoint: this.crypto.g.mul(this.localPrivateKey.private),
        schnorrProof: this.localSchnorrProof,
        decommitment: this.localDecommitment
      }),
      syncData: EddsaSyncData.fromOptions({
        curve: this.curve,
        publicPoint: publicPoint
      })
    };
  }
}

class DistributedEddsaSyncSessionShard extends generateMessage(
  'DistributedEddsaSyncSessionShard', {
    localPrivateKey: [Field.Custom, EddsaKeyPair],
    remotePedersenParameters: [Field.Point],
    remoteCommitment: [Field.Point]
  },
  root
) {
  static fromOptions(options) {
    return new DistributedEddsaSyncSessionShard().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedEddsaSyncSessionShard().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEddsaSyncSessionShard().fromBytes(bytes);
  }

  processCommitment(remote) {
    this.remotePedersenParameters = remote.pedersenParameters;
    this.remoteCommitment = remote.commitment;

    const publicPoint = this.crypto.g.mul(this.localPrivateKey.private);

    const schnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateKey.private
    });

    return EddsaData.fromOptions({
      curve: this.curve,
      publicPoint: publicPoint,
      schnorrProof: schnorrProof
    });
  }

  processDecommitment(remote) {
    const CommitmentMessage = root.lookupType('EddsaCommitmentMessage');

    const commitmentMessage = new Buffer(CommitmentMessage.encode({
      publicPoint: encodePoint(remote.publicPoint),
      schnorrProof: toJSON(remote.schnorrProof)
    }).finish());

    assert(PedersenScheme.verify(
      this.curve,
      this.remotePedersenParameters,
      commitmentMessage,
      this.remoteCommitment,
      remote.decommitment
    ));

    assert(remote.schnorrProof.verify(remote.publicPoint));

    const publicPoint = remote.publicPoint;

    return EddsaSyncData.fromOptions({
      curve: this.curve,
      publicPoint: publicPoint
    });
  }
}

module.exports = {
  EddsaCommitment,
  EddsaDecommitment,
  EddsaData,
  EddsaSyncData,
  DistributedEddsaSyncSession,
  DistributedEddsaSyncSessionShard
};
