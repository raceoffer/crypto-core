const chai = require('chai');
const core = require('..');

const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');
const rewrap = arg => core.Marshal.unwrap(JSON.parse(JSON.stringify(core.Marshal.wrap(arg))));

describe('NEM', () => {
  it('should sign a transaction transferring 10 nem to itself', async () => {
    const keyChain = core.KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const initiator = rewrap(core.CompoundKeyEddsa.fromOptions({
        curve: 'ed25519',
        secret: initiatorPrivateBytes
    }));

    const verifier = rewrap(core.CompoundKeyEddsa.fromOptions({
        curve: 'ed25519',
        secret: verifierPrivateBytes
    }));

    const iSyncSession = rewrap(initiator.startSyncSession());
    const vSyncSession = rewrap(verifier.startSyncSession());

    const iCommitment = rewrap(iSyncSession.createCommitment());
    const vCommitment = rewrap(vSyncSession.createCommitment());

    const iDecommitment = rewrap(iSyncSession.processCommitment(vCommitment));
    const vDecommitment = rewrap(vSyncSession.processCommitment(iCommitment));

    const iSyncData = rewrap(iSyncSession.processDecommitment(vDecommitment));
    const vSyncData = rewrap(vSyncSession.processDecommitment(iDecommitment));

    initiator.importSyncData(iSyncData);
    verifier.importSyncData(vSyncData);

    const nemWallet = core.NemWallet.fromOptions({
        network: core.NemWallet.Testnet,
        point: initiator.compoundPublic()
    });

    chai.expect(nemWallet.address).to.equal('TBIOTLAM5TOEWV5ECCE7MR3PSQFV76BTS5IHBXX2');

    const iTX = rewrap(await nemWallet.prepareTransaction(rewrap(core.NemTransaction.create()), nemWallet.address, nemWallet.toInternal(10)));
    const vTX = rewrap(await nemWallet.prepareTransaction(rewrap(core.NemTransaction.create()), nemWallet.address, nemWallet.toInternal(10)));

    iTX.startSignSession(initiator);
    vTX.startSignSession(verifier);

    const iSCommitment = rewrap(iTX.createCommitment());
    const vSCommitment = rewrap(vTX.createCommitment());

    const iSDecommitment = rewrap(iTX.processCommitment(vSCommitment));
    const vSDecommitment = rewrap(vTX.processCommitment(iSCommitment));

    iTX.processDecommitment(vSDecommitment);
    vTX.processDecommitment(iSDecommitment);

    const vPartialSignature = rewrap(vTX.computeSignature());

    iTX.applySignature(vPartialSignature);

    chai.expect(iTX.verify()).to.be.true;
  }).timeout(10000);
});
