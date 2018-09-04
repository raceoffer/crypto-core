const chai = require('chai');
const core = require('..');

const toBytes = core.Convert.toJSON;
const fromBytes = core.Convert.fromJSON;

const Curve = core.Curve;
const PaillierProover = core.PaillierProver;
const PaillierVerifier = core.PaillierVerifier;
const KeyChain = core.KeyChain;
const DistributedKeyEcdsa = core.DistributedKeyEcdsa;
const DistributedKeyShardEcdsa = core.DistributedKeyShardEcdsa;
const InitialCommitment = core.InitialCommitment;
const InitialDecommitment = core.InitialDecommitment;
const ChallengeCommitment = core.ChallengeCommitment;
const ChallengeDecommitment = core.ChallengeDecommitment;
const ResponseCommitment = core.ResponseCommitment;
const ResponseDecommitment = core.ResponseDecommitment;
const InitialData = core.InitialData;
const ProverSyncData = core.ProverSyncData;
const VerifierSyncData = core.VerifierSyncData;

const rewrap = (type, value) => fromBytes(type, toBytes(value));

const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

describe('Basic', () => {
  it('should work', async () => {
    const keyChain = KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const { publicKey, secretKey } = DistributedKeyEcdsa.generatePaillierKeys();

    const distributedKey = rewrap(DistributedKeyEcdsa, DistributedKeyEcdsa.fromOptions({
      curve: Curve.secp256k1,
      secret: initiatorPrivateBytes,
      localPaillierPublicKey: publicKey,
      localPaillierSecretKey: secretKey
    }));

    const distributedKeyShard = rewrap(DistributedKeyShardEcdsa, DistributedKeyShardEcdsa.fromOptions({
      curve: Curve.secp256k1,
      secret: verifierPrivateBytes
    }));

    const prover = rewrap(PaillierProover, distributedKey.startSyncSession());
    const verifier = rewrap(PaillierVerifier, distributedKeyShard.startSyncSession());

    const initialCommitment = rewrap(InitialCommitment, prover.createInitialCommitment());
    const initialData = rewrap(InitialData, verifier.processInitialCommitment(initialCommitment));

    const initialDecommitment = rewrap(InitialDecommitment, prover.processInitialData(initialData));
    const challengeCommitment = rewrap(ChallengeCommitment, verifier.processInitialDecommitment(initialDecommitment));

    const responseCommitment = rewrap(ResponseCommitment, prover.processChallengeCommitment(challengeCommitment));
    const challengeDecommitment = rewrap(ChallengeDecommitment, verifier.processResponseCommitment(responseCommitment));

    const { responseDecommitment, proverSyncData } = prover.processChallengeDecommitment(challengeDecommitment);

    const verifierSyncData = rewrap(VerifierSyncData, verifier.processResponseDecommitment(rewrap(ResponseDecommitment, responseDecommitment)));

    distributedKey.importSyncData(rewrap(ProverSyncData, proverSyncData));
    distributedKeyShard.importSyncData(verifierSyncData);

    const distributedSigner = distributedKey.startSignSession(Buffer.from('ffaaddaa0066ff', 'hex'));
    const distributedSignerShard = distributedKeyShard.startSignSession(Buffer.from('ffaaddaa0066ff', 'hex'));

    const entropyCommitment = distributedSigner.createEntropyCommitment();
    const entropyData = distributedSignerShard.processEntropyCommitment(entropyCommitment);

    const entropyDecommitment = distributedSigner.processEntropyData(entropyData);
    const partialSignature = distributedSignerShard.processEntropyDecommitment(entropyDecommitment);

    const signature = distributedSigner.finalizeSignature(partialSignature);
  }).timeout(10000);
});
