const chai = require('chai');
const core = require('..');

const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');
const rewrap = arg => core.Marshal.unwrap(JSON.parse(JSON.stringify(core.Marshal.wrap(arg))));

describe('BTC', () => {
  it('should sign a transaction transferring 0.01 btc to itself', async () => {
    const keyChain = core.KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const paillierKeys = rewrap(core.CompoundKeyEcdsa.generatePaillierKeys());

    let initiator = rewrap(core.CompoundKeyEcdsa.fromOptions({
      curve: 'secp256k1',
      secret: initiatorPrivateBytes,
      paillierKeys
    }));

    let verifier = rewrap(core.CompoundKeyEcdsa.fromOptions({
      curve: 'secp256k1',
      secret: verifierPrivateBytes,
      paillierKeys
    }));

    const iProover = rewrap(initiator.startSyncSession());
    const vProover = rewrap(verifier.startSyncSession());

    const iiCommitment = rewrap(iProover.createInitialCommitment());
    const viCommitment = rewrap(vProover.createInitialCommitment());

    const iiDecommitment = rewrap(iProover.processInitialCommitment(viCommitment));
    const viDecommitment = rewrap(vProover.processInitialCommitment(iiCommitment));

    const iVerifier = rewrap(iProover.processInitialDecommitment(viDecommitment));
    const vVerifier = rewrap(vProover.processInitialDecommitment(iiDecommitment));

    const ivCommitment = rewrap(iVerifier.createCommitment());
    const vvCommitment = rewrap(vVerifier.createCommitment());

    const ipCommitment = rewrap(iProover.processCommitment(vvCommitment));
    const vpCommitment = rewrap(vProover.processCommitment(ivCommitment));

    const ivDecommitment = rewrap(iVerifier.processCommitment(vpCommitment));
    const vvDecommitment = rewrap(vVerifier.processCommitment(ipCommitment));

    const ipDecommitment = rewrap(iProover.processDecommitment(vvDecommitment));
    const vpDecommitment = rewrap(vProover.processDecommitment(ivDecommitment));

    const iSyncData = rewrap(iVerifier.processDecommitment(vpDecommitment));
    const vSyncData = rewrap(vVerifier.processDecommitment(ipDecommitment));

    initiator = rewrap(initiator);
    verifier = rewrap(verifier);

    initiator.importSyncData(iSyncData);
    verifier.importSyncData(vSyncData);

    initiator = rewrap(initiator);
    verifier = rewrap(verifier);

    const btcWallet = core.BitcoinWallet.fromOptions({
      network: core.BitcoinWallet.Testnet,
      point: initiator.compoundPublic(),
      endpoint: 'https://test-insight.bitpay.com/api'
    });

    chai.expect(btcWallet.address).to.equal('mxp56RZQeyJk5duzbL3nch5NHweovqBnJR');

    let iTX = rewrap(await btcWallet.prepareTransaction(rewrap(core.BitcoinTransaction.create()), btcWallet.address, btcWallet.toInternal(0.01)));
    let vTX = rewrap(await btcWallet.prepareTransaction(rewrap(core.BitcoinTransaction.create()), btcWallet.address, btcWallet.toInternal(0.01)));

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

    iTX = rewrap(iTX);

    chai.expect(iTX.verify()).to.be.true;
  }).timeout(10000);
});
