const chai = require('chai');

const {
  KeyChain,
  DistributedEcdsaKey,
  DistributedEcdsaKeyShard,
  BitcoinTransaction,
  BitcoinWallet,
  Convert,
  Curve
} = require('..');

const rewrap = (value) => Convert.fromBytes(value.constructor, Convert.toBytes(value));

const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

describe('BTC', () => {
  it('should sign a transaction transferring 0.01 btc to itself', async () => {
    const keyChain = KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const { publicKey, secretKey } = DistributedEcdsaKey.generatePaillierKeys();

    const distributedKey = rewrap(DistributedEcdsaKey.fromOptions({
      curve: Curve.secp256k1,
      secret: initiatorPrivateBytes,
      localPaillierPublicKey: publicKey,
      localPaillierSecretKey: secretKey
    }));

    const distributedKeyShard = rewrap(DistributedEcdsaKeyShard.fromOptions({
      curve: Curve.secp256k1,
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

    const btcWallet = BitcoinWallet.fromOptions({
      network: BitcoinWallet.Testnet,
      point: distributedKey.compoundPublic(),
      endpoint: 'https://test-insight.bitpay.com/api'
    });

    chai.expect(btcWallet.address).to.equal('mxp56RZQeyJk5duzbL3nch5NHweovqBnJR');

    const iTX = rewrap(await btcWallet.prepareTransaction(BitcoinTransaction.create(), btcWallet.address, btcWallet.toInternal(0.01)));
    const vTX = rewrap(await btcWallet.prepareTransaction(BitcoinTransaction.create(), btcWallet.address, btcWallet.toInternal(0.01)));

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
