import assert from 'assert';
import nem from 'nem-sdk';
import BN from 'bn.js';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { Signer, Signature } from '../../primitives/eddsa/signer';
import { fromJSON, toJSON, encodeBuffer, decodeBuffer } from '../../convert';

const Nem = nem.default;

export class NemTransaction {
    constructor() {
        this.tx = null;
        this.hash = null;
        this.signature = null;

        this.signer = null;
    }

    static create() {
        return new NemTransaction();
    }

    fromOptions(tx) {
        this.tx = tx;

        return this;
    }

    static fromOptions(tx) {
        return new NemTransaction().fromOptions(tx);
    }

    estimateSize() {
        return 1;
    }

    estimateFee() {
        return new BN(1);
    }

    validate(ignored) {
        const statistics = this.totalOutputs();

        return !(!statistics.outputs || statistics.outputs.length !== 1 || statistics.outputs[0].value.isNeg());
    }

    totalOutputs() {
        assert(this.tx);
        //return { outputs: [{ address: this.tx.to, value: new BN(this.tx.value.substring(2), 16) }] };
    }

    toJSON() {
        return {
            tx: this.tx,
            hash: encodeBuffer(this.hash),
            signature: toJSON(this.signature),
            signer: toJSON(this.signer)
        };
    }

    fromJSON(json) {
        this.tx = json.tx;
        this.hash = decodeBuffer(json.hash);
        this.signature = fromJSON(Signature, json.signature);
        this.signer = fromJSON(Signer, json.signer);
        return this;
    }

    static fromJSON(json) {
        return new NemTransaction().fromJSON(json);
    }

    startSignSession(key) {
        this.hash = Buffer.from(Nem.utils.serialization.serializeTransaction(this.tx));
        this.signer = key.startSignSession(this.hash);
    }

    createCommitment() {
        return this.signer.createCommitment();
    }

    processCommitment(commitment) {
        return this.signer.processCommitment(commitment);
    }

    processDecommitment(decommitment) {
        this.signer.processDecommitment(decommitment);
    }

    computeSignature() {
        return this.signer.computePartialSignature();
    }

    applySignature(signature) {
        this.signature = this.signer.finalizeSignature(signature);
    }

    verify() {
        return Nem.crypto.verifySignature(this.tx.signer, this.hash, this.signature.toHex());
    }

    toRaw() {
        assert(this.signature);
        return {
            'data': Nem.utils.convert.ua2hex(this.hash),
            'signature': this.signature.toHex()
        };
    }
}

NemTransaction.Mainnet = 'main';
NemTransaction.Testnet = 'testnet';
