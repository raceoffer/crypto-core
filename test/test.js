(async (
    core,
    assert,
    eddsa,
    Buffer,
    nem
) => {
    try {
        const Convert = nem.utils.convert;
        const Serialization = nem.utils.serialization;

        const seed = Buffer.from('9ff992e811d4b2d2407ad33b263f567698c37bd6631bc0db90223ef10bce7dca28b8c670522667451430a1cb10d1d6b114234d1c2220b2f4229b00cadfc91c4d', 'hex');

        const keyChain = core.KeyChain.fromSeed(seed);

        const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
        const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

        let initiator = core.CompoundKeyEddsa.fromSecret(initiatorPrivateBytes, 'ed25519');
        let verifier = core.CompoundKeyEddsa.fromSecret(verifierPrivateBytes, 'ed25519');

        const iSyncSession = initiator.startSyncSession();
        const vSyncSession = verifier.startSyncSession();

        const iCommitment = iSyncSession.createCommitment();
        const vCommitment = vSyncSession.createCommitment();

        const iDecommitment = iSyncSession.processCommitment(vCommitment);
        const vDecommitment = vSyncSession.processCommitment(iCommitment);

        const iSyncData = iSyncSession.processDecommitment(vDecommitment);
        const vSyncData = vSyncSession.processDecommitment(iDecommitment);

        initiator.importSyncData(iSyncData);
        verifier.importSyncData(vSyncData);

        const nemWallet = core.NemWallet.fromOptions({
            network: core.NemWallet.Testnet,
            point: initiator.compoundPublic
        });

        console.log(nemWallet.address, ':', nemWallet.fromInternal((await nemWallet.getBalance()).unconfirmed), 'NEM');

        const tx = await nemWallet.prepareTransaction({fromOptions: tx => tx}, 'TCLT5G-RRTWIO-HXE2NG-XLAXLT-U24OSM-7YZXBD-BEZR', 10);

        const hash = Serialization.serializeTransaction(tx);

        const iSigner = initiator.startSignSession(hash);
        const vSigner = verifier.startSignSession(hash);

        const iSCommitment = iSigner.createCommitment();
        const vSCommitment = vSigner.createCommitment();

        const iSDecommitment = iSigner.processCommitment(vSCommitment);
        const vSDecommitment = vSigner.processCommitment(iSCommitment);

        iSigner.processDecommitment(vSDecommitment);
        vSigner.processDecommitment(iSDecommitment);

        const vPartialSignature = vSigner.computePartialSignature();

        const signature = iSigner.combineSignatures(vPartialSignature).toHex().toLowerCase();

        assert(nem.crypto.verifySignature(nemWallet.publicKey, hash, signature));

        const blob = {
            'data': Convert.ua2hex(hash),
            'signature': signature
        };

        //await nemWallet.sendSignedTransaction(blob);

        console.log('OK');
    } catch (e) {
        console.error(e);
    }
})(
    require('..'),
    require('assert'),
    require('elliptic').eddsa('ed25519'),
    require('buffer').Buffer,
    require('nem-sdk').default
);