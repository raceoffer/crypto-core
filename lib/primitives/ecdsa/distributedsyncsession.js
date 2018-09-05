'use strict';

const assert = require('assert');
const BN = require('bn.js');

const { Buffer } = require('buffer');

const { PaillierPublicKey, PaillierSecretKey } = require('./paillierkeys');
const { SchnorrProof } = require('../schnorrproof');
const { PedersenScheme } = require('../pedersenscheme');

const { randomBytes } = require('../../utils');

const {
  toJSON,
  encodePoint,
  encodeBigInteger,
  encodeBN,
  toBigInteger,
  toBN,
  generateMessage,
  Field
} = require('../../convert');

const { Root } = require('protobufjs');
const proto = require('./distributedsyncsession.json');

const root = Root.fromJSON(proto);

const EcdsaInitialCommitment = generateMessage(
  'EcdsaInitialCommitment', {
    pedersenParameters: [Field.Point],
    initialCommitment: [Field.Point]
  },
  root
);

const EcdsaInitialDecommitment = generateMessage(
  'EcdsaInitialDecommitment', {
    paillierPublicKey: [Field.Custom, PaillierPublicKey],
    publicPoint: [Field.Point],
    chiphertext: [Field.BigInteger],
    initialDecommitment: [Field.BN]
  },
  root
);

const EcdsaResponseCommitment = generateMessage(
  'EcdsaResponseCommitment', {
    responseCommitment: [Field.Point]
  },
  root
);

const EcdsaResponseDecommitment = generateMessage(
  'EcdsaResponseDecommitment', {
    responseDecommitment: [Field.BN],
    response: [Field.Point]
  },
  root
);

const EcdsaSyncData = generateMessage(
  'EcdsaSyncData', {
    publicPoint: [Field.Point]
  },
  root
);

class DistributedEcdsaSyncSession extends generateMessage(
  'DistributedEcdsaSyncSession', {
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
    return new DistributedEcdsaSyncSession().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedEcdsaSyncSession().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEcdsaSyncSession().fromBytes(bytes);
  }

  createInitialCommitment() {
    const publicPoint = this.crypto.g.mul(this.localPrivateKey);

    this.localChiphertext = this.localPaillierPublicKey.encrypt(toBigInteger(this.localPrivateKey));

    const InitialCommitmentMessage = root.lookupType('EcdsaInitialCommitmentMessage');

    const initialCommitmentMessage = new Buffer(InitialCommitmentMessage.encode({
      paillierPublicKey: toJSON(this.localPaillierPublicKey),
      publicPoint: encodePoint(publicPoint),
      chiphertext: encodeBigInteger(this.localChiphertext)
    }).finish());

    const { commitment, decommitment } = this.localPedersenScheme.commit(initialCommitmentMessage);

    this.localInitialDecommitment = decommitment;

    return EcdsaInitialCommitment.fromOptions({
      curve: this.curve,
      pedersenParameters: this.localPedersenScheme.getParameters(),
      initialCommitment: commitment
    });
  }

  processInitialData(remote) {
    assert(remote.schnorrProof.verify(remote.publicPoint));

    this.remotePublicPoint = remote.publicPoint;
    this.remotePedersenParameters = remote.pedersenParameters;
    
    return EcdsaInitialDecommitment.fromOptions({
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

    return EcdsaResponseCommitment.fromOptions({
      curve: this.curve,
      responseCommitment: commitment
    });
  }

  processChallengeDecommitment(remote) {
    const ChallengeCommitmentMessage = root.lookupType('EcdsaChallengeCommitmentMessage');

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
      responseDecommitment: EcdsaResponseDecommitment.fromOptions({
        curve: this.curve,
        responseDecommitment: this.localResponseDecommitment,
        response: response
      }),
      proverSyncData: EcdsaSyncData.fromOptions({
        curve: this.curve,
        publicPoint: this.remotePublicPoint
      })
    };
  }
}

const EcdsaInitialData = generateMessage(
  'EcdsaInitialData', {
    pedersenParameters: [Field.Point],
    publicPoint: [Field.Point],
    schnorrProof: [Field.Custom, SchnorrProof]
  },
  root
);

const EcdsaChallengeCommitment = generateMessage(
  'EcdsaChallengeCommitment', {
    challenge: [Field.BigInteger],
    revealCommitment: [Field.Point]
  },
  root
);

const EcdsaChallengeDecommitment = generateMessage(
  'EcdsaChallengeDecommitment', {
    revealDecommitment: [Field.BN],
    a: [Field.BN],
    b: [Field.BN]
  },
  root
);

const EcdsaShardSyncData = generateMessage(
  'EcdsaShardSyncData', {
    publicPoint: [Field.Point],
    paillierPublicKey: [Field.Custom, PaillierPublicKey],
    ciphertext: [Field.BigInteger]
  },
  root
);

class DistributedEcdsaSyncSessionShard extends generateMessage(
  'DistributedEcdsaSyncSessionShard', {
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
    return new DistributedEcdsaSyncSessionShard().fromOptions(options);
  }
  
  static fromJSON(json) {
    return new DistributedEcdsaSyncSessionShard().fromJSON(json);
  }

  static fromBytes(bytes) {
    return new DistributedEcdsaSyncSessionShard().fromBytes(bytes);
  }

  processInitialCommitment(remote) {
    this.remotePedersenParameters = remote.pedersenParameters;
    this.remoteInitialCommitment = remote.initialCommitment;

    const schnorrProof = SchnorrProof.fromOptions({
      curve: this.curve,
      x: this.localPrivateKey
    });

    const publicPoint = this.crypto.g.mul(this.localPrivateKey);

    return EcdsaInitialData.fromOptions({
      curve: this.curve,
      pedersenParameters: this.localPedersenScheme.getParameters(),
      publicPoint: publicPoint,
      schnorrProof: schnorrProof
    });
  }

  processInitialDecommitment(remote) {
    const InitialCommitmentMessage = root.lookupType('EcdsaInitialCommitmentMessage');

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

    const ChallengeCommitmentMessage = root.lookupType('EcdsaChallengeCommitmentMessage');

    const challengeCommitmentMessage = new Buffer(ChallengeCommitmentMessage.encode({
      a: encodeBN(this.a),
      b: encodeBN(this.b)
    }).finish());

    const { commitment, decommitment } = this.localPedersenScheme.commit(challengeCommitmentMessage);

    this.localRevealDecommitment = decommitment;

    return EcdsaChallengeCommitment.fromOptions({
      curve: this.curve,
      challenge: challenge,
      revealCommitment: commitment
    });
  }

  processResponseCommitment(remote) {
    this.remoteResponseCommitment = remote.responseCommitment;

    return EcdsaChallengeDecommitment.fromOptions({
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

    return EcdsaShardSyncData.fromOptions({
      curve: this.curve,
      publicPoint: this.remotePublicPoint,
      paillierPublicKey: this.remotePaillierPublicKey,
      ciphertext: this.remoteCiphertext
    });
  }
}

module.exports = {
  EcdsaChallengeCommitment,
  EcdsaChallengeDecommitment,
  EcdsaInitialCommitment,
  EcdsaInitialDecommitment,
  EcdsaInitialData,
  EcdsaResponseCommitment,
  EcdsaResponseDecommitment,
  EcdsaSyncData,
  EcdsaShardSyncData,
  DistributedEcdsaSyncSession,
  DistributedEcdsaSyncSessionShard
};
