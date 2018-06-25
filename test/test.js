((
    core,
    assert,
    eddsa,
    Buffer,
    nem
)=>{
    const Helpers = nem.utils.helpers;
    const Convert = nem.utils.convert;
    const Serialization = nem.utils.serialization;
    const Requests = nem.com.requests;
    const Network = nem.model.network;
    const Transactions = nem.model.transactions;
    const Fees = nem.model.fees;
    const TransactionTypes = nem.model.transactionTypes;
    const Objects = nem.model.objects;

    const construct = function(senderPublicKey, recipientCompressedKey, amount, message, msgFee, due, mosaics, mosaicsFee, network) {
        let timeStamp = Helpers.createNEMTimeStamp();
        let version = mosaics ? Network.getVersion(2, network) : Network.getVersion(1, network);
        let data = Objects.create("commonTransactionPart")(TransactionTypes.transfer, senderPublicKey, timeStamp, due, version);
        let fee = mosaics ? mosaicsFee : Fees.currentFeeFactor * Fees.calculateMinimum(amount / 1000000);
        let totalFee = Math.floor((msgFee + fee) * 1000000);
        let custom = {
            'recipient': recipientCompressedKey.toUpperCase().replace(/-/g, ''),
            'amount': amount,
            'fee': totalFee,
            'message': message,
            'mosaics': mosaics
        };
        return Helpers.extendObj(data, custom);
    };

    const prepare = function(publicKey, tx, network){
        assert(!tx.isMultisig);

        let actualSender = publicKey;
        let recipientCompressedKey = tx.recipient.toString();
        let amount = Math.round(tx.amount * 1000000);
        let message = Transactions.prepareMessage(null, tx);
        let msgFee = Fees.calculateMessage(message, false);
        let due = network === Network.data.testnet.id ? 60 : 24 * 60;
        let mosaics = null;
        let mosaicsFee = null;
        return construct(actualSender, recipientCompressedKey, amount, message, msgFee, due, mosaics, mosaicsFee, network);
    };

    const endpoint = nem.model.objects.create("endpoint")(nem.model.nodes.defaultTestnet, nem.model.nodes.defaultPort);

    const seed = core.Utils.randomBytes(64);

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

    const transferTransaction = nem.model.objects.create("transferTransaction")("TBCI2A67UQZAKCR6NS4JWAEICEIGEIM72G3MVW5S", 10, "Hello");

    const publicKey = Buffer.from(eddsa.encodePoint(initiator.compoundPublic)).toString('hex');

    const transactionEntity = prepare(publicKey, transferTransaction, nem.model.network.data.testnet.id);

    const hash = Serialization.serializeTransaction(transactionEntity);

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

    //const signature = initiator.localPrivateKey.sign(hash).toHex().toLowerCase();

    assert(nem.crypto.verifySignature(publicKey, hash, signature));

    const blob = {
        'data': Convert.ua2hex(hash),
        'signature': signature
    };

    Requests.transaction.announce(endpoint, JSON.stringify(blob)).then(r => {
        console.log(r);
    });
})(
    require('..'),
    require('assert'),
    require('elliptic').eddsa('ed25519'),
    require('buffer').Buffer,
    require('nem-sdk').default
);