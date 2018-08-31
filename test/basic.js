const chai = require('chai');
const core = require('..');

const toJSON = core.Convert.toJSON;
const fromJSON = core.Convert.fromJSON;

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
const SyncData = core.SyncData;

const rewrap = (type, value) => fromJSON(type, toJSON(value));

const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

describe('Basic', () => {
  it('should work', async () => {
    const keyChain = KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const paillierKeys = DistributedKeyEcdsa.generatePaillierKeys();

    const distributedKey = rewrap(DistributedKeyEcdsa, DistributedKeyEcdsa.fromOptions({
      curve: 'secp256k1',
      secret: initiatorPrivateBytes,
      paillierKeys
    }));

    const distributedKeyShard = rewrap(DistributedKeyShardEcdsa, DistributedKeyShardEcdsa.fromOptions({
      curve: 'secp256k1',
      secret: verifierPrivateBytes
    }));

    const proover = rewrap(PaillierProover, distributedKey.startSyncSession());
    const verifier = rewrap(PaillierVerifier, distributedKeyShard.startSyncSession());

    const initialCommitment = rewrap(InitialCommitment, proover.createInitialCommitment());
    const initialData = rewrap(InitialData, verifier.processInitialCommitment(initialCommitment));

    const initialDecommitment = rewrap(InitialDecommitment, proover.processInitialData(initialData));
    const challengeCommitment = rewrap(ChallengeCommitment, verifier.processInitialDecommitment(initialDecommitment));

    const responseCommitment = rewrap(ResponseCommitment, proover.processChallengeCommitment(challengeCommitment));
    const challengeDecommitment = rewrap(ChallengeDecommitment, verifier.processResponseCommitment(responseCommitment));

    const responseDecommitment = rewrap(ResponseDecommitment, proover.processChallengeDecommitment(challengeDecommitment));
    const syncData = rewrap(SyncData, verifier.processResponseDecommitment(responseDecommitment));

    distributedKey.importSyncData(initialData);
    distributedKeyShard.importSyncData(syncData);

    console.log(distributedKey.compoundPublic());
    console.log(distributedKeyShard.compoundPublic());
  }).timeout(10000);
});
