(async (
    core,
    assert,
    Buffer
) => {
    const rewrap = arg => core.Marshal.unwrap(JSON.parse(JSON.stringify(core.Marshal.wrap(arg))));

    try {
        const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

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
            point: initiator.compoundPublic
        });

        console.log(nemWallet.address, ':', nemWallet.fromInternal((await nemWallet.getBalance()).unconfirmed), 'NEM');

        const iTX = rewrap(await nemWallet.prepareTransaction(rewrap(core.NemTransaction.create()), 'TCLT5GRRTWIOHXE2NGXLAXLTU24OSM7YZXBDBEZR', nemWallet.toInternal(1)));
        const vTX = rewrap(await nemWallet.prepareTransaction(rewrap(core.NemTransaction.create()), 'TCLT5GRRTWIOHXE2NGXLAXLTU24OSM7YZXBDBEZR', nemWallet.toInternal(1)));

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

        assert(iTX.verify());

        const blob = iTX.toRaw();

        await nemWallet.sendSignedTransaction(blob);

        console.log('OK');
    } catch (e) {
        console.error(e);
    }
})(
    require('..'),
    require('assert'),
    require('buffer').Buffer
);

(async (
  core,
  assert,
  Buffer
) => {
  const rewrap = arg => core.Marshal.unwrap(JSON.parse(JSON.stringify(core.Marshal.wrap(arg))));

  try {
    const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

    const keyChain = core.KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const paillierKeys = core.CompoundKeyEcdsa.generatePaillierKeys();

    const initiator = rewrap(core.CompoundKeyEcdsa.fromOptions({
      curve: 'secp256k1',
      secret: initiatorPrivateBytes,
      paillierKeys
    }));

    const verifier = rewrap(core.CompoundKeyEcdsa.fromOptions({
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

    initiator.importSyncData(iSyncData);
    verifier.importSyncData(vSyncData);

    const ethWallet = core.EthereumWallet.fromOptions({
      network: core.EthereumWallet.Testnet,
      point: initiator.compoundPublic,
      endpoint: 'https://rinkeby.infura.io/dlYX0gLUjGGCk7IBFq2C'
    });

    console.log(ethWallet.address, ':', ethWallet.fromInternal((await ethWallet.getBalance()).unconfirmed), 'ETH');

    let iTX = rewrap(await ethWallet.prepareTransaction(rewrap(core.EthereumTransaction.create()), '0x28ea64196afb9b0a15dadad1cf8fcfb5669973d5', ethWallet.toInternal(0.01)));
    let vTX = rewrap(await ethWallet.prepareTransaction(rewrap(core.EthereumTransaction.create()), '0x28ea64196afb9b0a15dadad1cf8fcfb5669973d5', ethWallet.toInternal(0.01)));

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

    assert(iTX.verify());

    const blob = iTX.toRaw();

    await ethWallet.sendSignedTransaction(blob);

    console.log('OK');
  } catch (e) {
    console.error(e);
  }
})(
  require('..'),
  require('assert'),
  require('buffer').Buffer
);