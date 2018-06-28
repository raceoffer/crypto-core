'use strict';

import nem from 'nem-sdk';
import buffer from 'buffer';
import elliptic from 'elliptic';
import assert from 'assert';
import BN from 'bn.js';

const Nem = nem.default;
const eddsa = elliptic.eddsa('ed25519');
const Buffer = buffer.Buffer;

export class NemWallet {
    constructor() {
        this.network = null;
        this.address = null;
        this.publicKey = null;
        this.endpoint = null;
    }

    static address(publicKey) {
        return Nem.model.address.toAddress(publicKey, Nem.model.network.data.testnet.id);
    }

    fromOptions(options) {
        this.network = options.network || NemWallet.Mainnet;
        this.publicKey = Buffer.from(eddsa.encodePoint(options.point)).toString('hex');
        this.address = NemWallet.address(this.publicKey);

        // should somehow depend on options.endpoint
        this.endpoint = Nem.model.objects.create("endpoint")(
            Nem.model.nodes.defaultTestnet,
            Nem.model.nodes.defaultPort
        );

        return this;
    }

    static fromOptions(options) {
        return new NemWallet().fromOptions(options);
    }

    verifyAddress(address) {
        return Nem.model.address.isValid(address);
    }

    async getBalance() {
        const data = await Nem.com.requests.account.data(this.endpoint, this.address);

        return {
            confirmed: new BN(data.account.balance),
            unconfirmed: new BN(data.account.balance)
        };
    }

    async prepareTransaction(transaction, to, value, fee) {
        const construct = function(senderPublicKey, recipientCompressedKey, amount, message, msgFee, due, mosaics, mosaicsFee, network) {
            const timeStamp = Nem.utils.helpers.createNEMTimeStamp();
            const version = mosaics ? Nem.model.network.getVersion(2, network) : Nem.model.network.getVersion(1, network);
            const data = Nem.model.objects.create("commonTransactionPart")(Nem.model.transactionTypes.transfer, senderPublicKey, timeStamp, due, version);
            const fee = mosaics ? mosaicsFee : Nem.model.fees.currentFeeFactor * Nem.model.fees.calculateMinimum(amount / 1000000);
            const totalFee = Math.floor((msgFee + fee) * 1000000);
            const custom = {
                'recipient': recipientCompressedKey.toUpperCase().replace(/-/g, ''),
                'amount': amount,
                'fee': totalFee,
                'message': message,
                'mosaics': mosaics
            };
            return Nem.utils.helpers.extendObj(data, custom);
        };

        const prepare = function(publicKey, tx, network){
            assert(!tx.isMultisig);

            const actualSender = publicKey;
            const recipientCompressedKey = tx.recipient.toString();
            const amount = Math.round(tx.amount * 1000000);
            const message = Nem.model.transactions.prepareMessage(null, tx);
            const msgFee = Nem.model.fees.calculateMessage(message, false);
            const due = network === Nem.model.network.data.testnet.id ? 60 : 24 * 60;
            const mosaics = null;
            const mosaicsFee = null;
            return construct(actualSender, recipientCompressedKey, amount, message, msgFee, due, mosaics, mosaicsFee, network);
        };

        const transferTransaction = Nem.model.objects.create("transferTransaction")(to, this.fromInternal(value));

        const transactionEntity = prepare(this.publicKey, transferTransaction, Nem.model.network.data.testnet.id);

        return await transaction.fromOptions(transactionEntity);
    }

    async sendSignedTransaction(blob) {
        await Nem.com.requests.transaction.announce(this.endpoint, JSON.stringify(blob));
    }

    fromInternal(value) {
        return value.toNumber() / 1000000;
    }

    toInternal(value) {
        return new BN(value * 1000000);
    }
}

NemWallet.Mainnet = 'main';
NemWallet.Testnet = 'testnet';