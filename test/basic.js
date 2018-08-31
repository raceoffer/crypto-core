const chai = require('chai');
const core = require('..');

const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

describe('Basic', () => {
  it('should work', async () => {
    const keyChain = core.KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const paillierKeys = core.DistributedKeyEcdsa.generatePaillierKeys();

    const distributedKey = core.DistributedKeyEcdsa.fromOptions({
      curve: 'secp256k1',
      secret: initiatorPrivateBytes,
      paillierKeys
    });

    const distributedKeyShard = core.DistributedKeyShardEcdsa.fromOptions({
      curve: 'secp256k1',
      secret: verifierPrivateBytes
    });

    const proover = distributedKey.startSyncSession();
    const verifier = distributedKeyShard.startSyncSession();

    const initialCommitment = proover.createInitialCommitment();
    const initialData = verifier.processInitialCommitment(initialCommitment);

    const initialDecommitment = proover.processInitialData(initialData);
    const challengeCommitment = verifier.processInitialDecommitment(initialDecommitment);

    const responseCommitment = proover.processChallengeCommitment(challengeCommitment);
    const challengeDecommitment = verifier.processResponseCommitment(responseCommitment);

    const responseDecommitment = proover.processChallengeDecommitment(challengeDecommitment);
    const syncData = verifier.processResponseDecommitment(responseDecommitment);

    distributedKey.importSyncData(initialData);
    distributedKeyShard.importSyncData(syncData);

    console.log(distributedKey.compoundPublic());
    console.log(distributedKeyShard.compoundPublic());
  }).timeout(10000);
});
