const assert = require("assert");

function LitecoreTransaction(options) {
    if(!(this instanceof LitecoreTransaction))
        return new LitecoreTransaction(options);

    this.network = LitecoreTransaction.Testnet;

    this.tx = null;

    // library-dependent types
    this.PublicKey = null;
    this.PrivateKey = null;
    this.Hash = null;
    this.BN = null;
    this.Transaction = null;
    this.BufferUtil = null;
    this.Signature = null;
    this.TXSignature = null;

    if(options) {
        this.fromOptions(options);
    }
}

LitecoreTransaction.Mainnet = 'main';
LitecoreTransaction.Testnet = 'testnet';

LitecoreTransaction.prototype.networkName = function (network) {
    return network;
};

LitecoreTransaction.prototype.defaultSigtype = function () {
    return this.Signature.SIGHASH_ALL;
};

LitecoreTransaction.prototype.fromOptions = function fromOptions(options) {
    this.network = options.network;

    return this;
};

LitecoreTransaction.fromOptions = function fromOptions(options) {
    return new LitecoreTransaction().fromOptions(options);
};

LitecoreTransaction.prototype.estimateSize = function estimatedSize() {
    return Math.ceil(this.tx._estimateSize() / 100) / 10;
};

LitecoreTransaction.prototype.totalOutputs = function totalOutputs() {
    assert(this.tx);

    const transaformer = output => {
        return {
            address: output.script.toAddress(this.networkName(this.network)).toString(),
            value: output.satoshis
        };
    };

    const change = this.tx.outputs.filter((output, i) => i === this.tx._changeIndex).map(transaformer);
    const outputs = this.tx.outputs.filter((output, i) => i !== this.tx._changeIndex).map(transaformer);
    const inputs = this.tx.inputs.map(input => input.output).map(transaformer);

    return { inputs, outputs, change };
};

LitecoreTransaction.prototype.prepare = function(options) {
    assert(false);
};

LitecoreTransaction.prototype.toJSON = function toJSON() {
    return {
        tx: this.tx.toObject(),
        network: this.network
    };
};

LitecoreTransaction.prototype.fromJSON = function fromJSON(json) {
    this.tx.fromObject(json.tx);
    this.network = json.network;
    return this;
};

LitecoreTransaction.fromJSON = function fromJSON(json) {
    return new LitecoreTransaction().fromJSON(json);
};

LitecoreTransaction.prototype.mapInputs = function mapInputs(compoundKeys) {
    assert(this.tx);

    if (!Array.isArray(compoundKeys)) {
        compoundKeys = [ compoundKeys ];
    }

    return this.tx.inputs.map((input, index) => {
        let compoundKey = null;
        switch (input.constructor.name) {
            case 'PublicKeyHashInput':
                compoundKey = compoundKeys.find(compoundKey => {
                    const publicKeyBuffer = Buffer.from(compoundKey.getCompoundPublicKey().encode(true, 'array'));
                    const hashData = this.Hash.sha256ripemd160(publicKeyBuffer);
                    return this.BufferUtil.equals(hashData, input.output.script.getPublicKeyHash());
                }) || null;
                break;
            case 'PublicKeyInput':
                compoundKey = compoundKeys.find(compoundKey => {
                    const publicKeyString = compoundKey.getCompoundPublicKey('hex');
                    return publicKeyString === input.output.script.getPublicKey().toString('hex');
                }) || null;
                break;
        }
        return {
            key: compoundKey,
            index: index
        }
    });
};

LitecoreTransaction.prototype.getHashes = function(mapping, sigtype) {
    assert(this.tx);

    sigtype = sigtype || this.defaultSigtype();
    return mapping.map((item) => {
        const index = item.index;
        const input = this.tx.inputs[index];

        assert(input);

        const hash = this.Transaction.sighash.sighash(this.tx, sigtype, index, input.output.script, input.output.satoshisBN);

        const reversebuf = function(buf) {
            const buf2 = new Buffer(buf.length);
            for (let i = 0; i < buf.length; i++) {
                buf2[i] = buf[buf.length - 1 - i];
            }
            return buf2;
        };

        return reversebuf(hash);
    });
};

LitecoreTransaction.prototype.normalizeSignatures = function(mapping, rawSignatures, sigtype) {
    assert(this.tx);

    sigtype = sigtype || this.defaultSigtype();

    return mapping.map((entry, i) => {
        const index = entry.index;
        const input = this.tx.inputs[index];
        const publicKey = new this.PublicKey(entry.key.getCompoundPublicKey(), { network: this.networkName(this.network) });
        const rawSignature = rawSignatures[i];

        const signature = new this.Signature({
            r: this.BN.fromString(rawSignature.r.toString(16), 16),
            s: this.BN.fromString(rawSignature.s.toString(16), 16),
            compressed: publicKey.compressed,
            nhashtype: sigtype
        });

        return new this.TXSignature({
            publicKey: publicKey,
            prevTxId: input.prevTxId,
            outputIndex: input.outputIndex,
            inputIndex: index,
            signature: signature,
            sigtype: sigtype
        });
    });
};

LitecoreTransaction.prototype.applySignatures = function(signatures) {
    assert(this.tx);

    signatures.forEach((signature) => {
        this.tx.applySignature(signature);
    });
};

LitecoreTransaction.prototype.toRaw = function () {
    assert(this.tx);

    assert(this.tx.isFullySigned());
    return this.tx.serialize();
};

LitecoreTransaction.prototype.verify = function () {
    assert(this.tx);

    return this.tx.verify();
};

LitecoreTransaction.prototype.startSign = function(hashes,keyMap) {
    return keyMap.map((key,i) => key.key.startSign(hashes[i]));
};

LitecoreTransaction.prototype.createEntropyCommitments = function(signers) {
    return signers.map(signer => signer.createEntropyCommitment());
};

LitecoreTransaction.prototype.processEntropyCommitments = function(signers,commitments) {
    return signers.map((signer,i) => signer.processEntropyCommitment(commitments[i]));
};

LitecoreTransaction.prototype.processEntropyDecommitments = function(signers,decommitments) {
    signers.forEach((signer,i) => signer.processEntropyDecommitment(decommitments[i]));
};

LitecoreTransaction.prototype.computeCiphertexts = function (signers) {
    return signers.map(signer => signer.computeCiphertext());
};

LitecoreTransaction.prototype.extractSignatures = function (signers,ciphertexts) {
    return signers.map((signer,i) => signer.extractSignature(ciphertexts[i]));
};

module.exports = LitecoreTransaction;