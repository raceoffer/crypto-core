const chai = require('chai');
const core = require('..');

const rewrap = (value) => core.Convert.fromBytes(value.constructor, core.Convert.toBytes(value));

const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

describe('ETH', () => {
  it('should sign a transaction transferring 0.1 eth to itself', async () => {
    const keyChain = core.KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const { publicKey, secretKey } = core.DistributedEcdsaKey.generatePaillierKeys();

    const distributedKey = rewrap(core.DistributedEcdsaKey.fromOptions({
      curve: core.Curve.secp256k1,
      secret: initiatorPrivateBytes,
      localPaillierPublicKey: publicKey,
      localPaillierSecretKey: secretKey
    }));

    const distributedKeyShard = rewrap(core.DistributedEcdsaKeyShard.fromOptions({
      curve: core.Curve.secp256k1,
      secret: verifierPrivateBytes
    }));

    const prover = rewrap(distributedKey.startSyncSession());
    const verifier = rewrap(distributedKeyShard.startSyncSession());

    const initialCommitment = rewrap(prover.createInitialCommitment());
    const initialData = rewrap(verifier.processInitialCommitment(initialCommitment));

    const initialDecommitment = rewrap(prover.processInitialData(initialData));
    const challengeCommitment = rewrap(verifier.processInitialDecommitment(initialDecommitment));

    const responseCommitment = rewrap(prover.processChallengeCommitment(challengeCommitment));
    const challengeDecommitment = rewrap(verifier.processResponseCommitment(responseCommitment));

    const { responseDecommitment, proverSyncData } = prover.processChallengeDecommitment(challengeDecommitment);

    const verifierSyncData = rewrap(verifier.processResponseDecommitment(rewrap(responseDecommitment)));

    distributedKey.importSyncData(rewrap(proverSyncData));
    distributedKeyShard.importSyncData(verifierSyncData);

    const ethWallet = core.EthereumWallet.fromOptions({
      network: core.EthereumWallet.Testnet,
      point: distributedKey.compoundPublic(),
      endpoint: 'https://rinkeby.infura.io/dlYX0gLUjGGCk7IBFq2C'
    });

    chai.expect(ethWallet.address).to.equal('0xd2A383c19e3bbC73FBbCf7f71AAC59Ec1FE65BfB');

    const iTX = rewrap(await ethWallet.prepareTransaction(core.EthereumTransaction.create(), ethWallet.address, ethWallet.toInternal(0.01)));
    const vTX = rewrap(await ethWallet.prepareTransaction(core.EthereumTransaction.create(), ethWallet.address, ethWallet.toInternal(0.01)));

    const iSignSession = rewrap(iTX.startSignSession(distributedKey));
    const vSignSession = rewrap(vTX.startSignSessionShard(distributedKeyShard));

    const entropyCommitment = rewrap(iSignSession.createEntropyCommitment());
    const entropyData = rewrap(vSignSession.processEntropyCommitment(entropyCommitment));

    const entropyDecommitment = rewrap(iSignSession.processEntropyData(entropyData));
    const partialSignature = rewrap(vSignSession.processEntropyDecommitment(entropyDecommitment));

    const signature = rewrap(iSignSession.finalizeSignature(partialSignature));

    iTX.applySignature(signature);

    chai.expect(rewrap(iTX).verify()).to.be.true;
  }).timeout(15000);
});
