((
    core,
    nem
)=>{
    const Convert = nem.utils.convert;
    const Serialization = nem.utils.serialization;
    const Requests = nem.com.requests;

    const endpoint = nem.model.objects.create("endpoint")(nem.model.nodes.defaultTestnet, nem.model.nodes.defaultPort);

    const common = nem.model.objects.create("common")('', core.Utils.randomBytes(32).toString('hex'));

    const transferTransaction = nem.model.objects.create("transferTransaction")("TBCI2A67UQZAKCR6NS4JWAEICEIGEIM72G3MVW5S", 10, "Hello");

    const transactionEntity = nem.model.transactions.prepare("transferTransaction")(common, transferTransaction, nem.model.network.data.testnet.id);

    const hash = Serialization.serializeTransaction(transactionEntity);

    const keyPair = core.KeyPair.fromHex(common.privateKey, 'ed25519');

    const signature = keyPair.sign(hash).toHex().toLowerCase();

    const blob = {
        'data': Convert.ua2hex(hash),
        'signature': signature
    };

    Requests.transaction.announce(endpoint, JSON.stringify(blob)).then(r => {
        console.log(r);
    });
})(
    require('..'),
    require('nem-sdk').default
);

((
    core,
    assert,
    eddsa
) => {
    const seed = core.Utils.randomBytes(64);

    const keyChain = core.KeyChain.fromSeed(seed);

    const initiatorPrivateBytes = keyChain.getAccountSecret(60, 0);
    const verifierPrivateBytes = keyChain.getAccountSecret(60, 1);

    const messageBytes = core.Utils.randomBytes(32);

    let initiator = core.CompoundKeyEddsa.fromSecret(initiatorPrivateBytes, 'ed25519');
    let verifier = core.CompoundKeyEddsa.fromSecret(verifierPrivateBytes, 'ed25519');

    initiator = core.Marshal.unwrap(JSON.parse(JSON.stringify(core.Marshal.wrap(initiator))));
    verifier = core.Marshal.unwrap(JSON.parse(JSON.stringify(core.Marshal.wrap(verifier))));

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

    const iSigner = initiator.startSignSession(messageBytes);
    const vSigner = verifier.startSignSession(messageBytes);

    const iSCommitment = iSigner.createCommitment();
    const vSCommitment = vSigner.createCommitment();

    const iSDecommitment = iSigner.processCommitment(vSCommitment);
    const vSDecommitment = vSigner.processCommitment(iSCommitment);

    iSigner.processDecommitment(vSDecommitment);
    vSigner.processDecommitment(iSDecommitment);

    const vPartialSignature = vSigner.computePartialSignature();

    const signature = iSigner.combineSignatures(vPartialSignature);

    assert(eddsa.verify(messageBytes, signature, initiator.compoundPublicKey));

    console.log('Eddsa OK');
})(
    require('..'),
    require('assert'),
    require('elliptic').eddsa('ed25519')
);