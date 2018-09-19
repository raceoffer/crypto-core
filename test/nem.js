const chai = require('chai');

const {
  KeyChain,
  DistributedEddsaKey,
  NemWallet,
  NemTransaction,
  Convert,
  Curve
} = require('..');

const rewrap = (value) => Convert.fromBytes(value.constructor, Convert.toBytes(value));

const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

describe('NEM', () => {
  it('should sign a transaction transferring 10 nem to itself', async () => {
    const keyChain = KeyChain.fromSeed(seed);
    
    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);
    
    const distributedKey = rewrap(DistributedEddsaKey.fromOptions({
      curve: Curve.ed25519,
      secret: initiatorPrivateBytes
    }));
    
    const distributedKeyShard = rewrap(DistributedEddsaKey.fromOptions({
      curve: Curve.ed25519,
      secret: verifierPrivateBytes
    }));

    const prover = rewrap(distributedKey.startSyncSession());
    const verifier = rewrap(distributedKeyShard.startSyncSessionShard());
    
    const commitment = rewrap(prover.createCommitment());
    const data = rewrap(verifier.processCommitment(commitment));

    const { decommitment, syncData } = prover.processData(data);
    const verifierSyncData = rewrap(verifier.processDecommitment(rewrap(decommitment)));

    distributedKey.importSyncData(rewrap(syncData));
    distributedKeyShard.importSyncData(verifierSyncData);

    const nemWallet = NemWallet.fromOptions({
      network: NemWallet.Testnet,
      point: distributedKey.compoundPublic()
    });
    
    chai.expect(nemWallet.address).to.equal('TBIOTLAM5TOEWV5ECCE7MR3PSQFV76BTS5IHBXX2');

    const iTX = rewrap(await nemWallet.prepareTransaction(rewrap(NemTransaction.create()), nemWallet.address, nemWallet.toInternal(10)));
    const vTX = rewrap(await nemWallet.prepareTransaction(rewrap(NemTransaction.create()), nemWallet.address, nemWallet.toInternal(10)));
    
    const iSignSession = rewrap(iTX.startSignSession(distributedKey));
    const vSignSession = rewrap(vTX.startSignSessionShard(distributedKeyShard));

    const entropyCommitment = rewrap(iSignSession.createEntropyCommitment());
    const entropyData = rewrap(vSignSession.processEntropyCommitment(entropyCommitment));

    const entropyDecommitment = rewrap(iSignSession.processEntropyData(entropyData));
    const partialSignature = rewrap(vSignSession.processEntropyDecommitment(entropyDecommitment));

    const signature = rewrap(iSignSession.finalizeSignature(partialSignature));

    iTX.applySignature(signature);
    
    chai.expect(iTX.verify()).to.be.true;
  }).timeout(10000);
});
