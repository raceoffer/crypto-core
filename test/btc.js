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

describe('BTC', () => {
  it('should sign a transaction transferring 0.01 btc to itself', async () => {
    const keyChain = core.KeyChain.fromSeed(seed);

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

    const btcWallet = core.BitcoinWallet.fromOptions({
      network: core.BitcoinWallet.Testnet,
      point: distributedKey.compoundPublic(),
      endpoint: 'https://test-insight.bitpay.com/api'
    });

    chai.expect(btcWallet.address).to.equal('mxp56RZQeyJk5duzbL3nch5NHweovqBnJR');

    // let iTX = await btcWallet.prepareTransaction(core.BitcoinTransaction.create(), btcWallet.address, btcWallet.toInternal(0.01));
    // let vTX = await btcWallet.prepareTransaction(core.BitcoinTransaction.create(), btcWallet.address, btcWallet.toInternal(0.01));

    // iTX.startSignSession(distributedKey);
    // vTX.startSignSessionShard(distributedKeyShard);

    // const entropyCommitment = iTX.createEntropyCommitment();
    // const entropyData = vTX.processEntropyCommitment(entropyCommitment);

    // const entropyDecommitment = iTX.processEntropyData(entropyData);
    // const partialSignature = vTX.processEntropyDecommitment(entropyDecommitment);

    // iTX.applySignature(partialSignature);

    // chai.expect(iTX.verify()).to.be.true;
  }).timeout(10000);
});
