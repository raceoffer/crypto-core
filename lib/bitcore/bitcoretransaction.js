const assert = require('assert');

function BitcoreTransaction() {
  this.PublicKey = null;
  this.PrivateKey = null;
  this.Hash = null;
  this.BN = null;
  this.Transaction = null;
  this.BufferUtil = null;
  this.Signature = null;
  this.TXSignature = null;

  this.network = null;

  this.tx = null;

  this.signers = null;
}

BitcoreTransaction.Mainnet = 'main';
BitcoreTransaction.Testnet = 'testnet';

BitcoreTransaction.prototype.networkName = function (network) {
  return network;
};

BitcoreTransaction.prototype.defaultSigtype = function () {
  return this.Signature.SIGHASH_ALL;
};

BitcoreTransaction.prototype.fromOptions = function fromOptions(options) {
  this.network = options.network || BitcoreTransaction.Testnet;
  this.tx = new this.Transaction();

  return this;
};

BitcoreTransaction.fromOptions = function fromOptions(options) {
  return new BitcoreTransaction().fromOptions(options);
};

BitcoreTransaction.prototype.estimateSize = function estimatedSize() {
  return Math.ceil(this.tx._estimateSize() / 100) / 10;
};

BitcoreTransaction.prototype.totalOutputs = function totalOutputs() {
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

BitcoreTransaction.prototype.prepare = async function prepare(options) {
  if(!options) {
    options = {};
  }

  assert(options.utxos);
  assert(options.address);
  assert(options.value);

  this.tx = this.tx
    .from(options.utxos)
    .to(options.address, options.value);

  if(options.fee) {
    this.tx = this.tx.fee(options.fee);
  }

  this.tx = this.tx.change(options.from);

  assert(this.tx.hasAllUtxoInfo());
};

BitcoreTransaction.prototype.toJSON = function toJSON() {
  return {
    tx: this.tx.toObject(),
    network: this.network
  };
};

BitcoreTransaction.prototype.fromJSON = function fromJSON(json) {
  this.tx = new this.Transaction();
  this.tx.fromObject(json.tx);
  this.network = json.network;
  return this;
};

BitcoreTransaction.fromJSON = function fromJSON(json) {
  return new BitcoreTransaction().fromJSON(json);
};

BitcoreTransaction.prototype.mapInputs = function mapInputs(compoundKeys) {
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

BitcoreTransaction.prototype.getHashes = function(mapping, sigtype) {
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

BitcoreTransaction.prototype.normalizeSignatures = function(mapping, rawSignatures, sigtype) {
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

BitcoreTransaction.prototype.applySignatures = function(signatures) {
  assert(this.tx);

  signatures.forEach((signature) => {
    this.tx.applySignature(signature);
  });
};

BitcoreTransaction.prototype.toRaw = function () {
  assert(this.tx);

  assert(this.tx.isFullySigned());
  return this.tx.serialize();
};

BitcoreTransaction.prototype.verify = function () {
  assert(this.tx);

  return this.tx.verify();
};

BitcoreTransaction.prototype.startSign = function(hashes, keyMap) {
  this.signers = keyMap.map((key,i) => key.key.startSign(hashes[i]));
};

BitcoreTransaction.prototype.createEntropyCommitments = function() {
  return this.signers.map(signer => signer.createEntropyCommitment());
};

BitcoreTransaction.prototype.processEntropyCommitments = function(commitments) {
  return this.signers.map((signer,i) => signer.processEntropyCommitment(commitments[i]));
};

BitcoreTransaction.prototype.processEntropyDecommitments = function(decommitments) {
  this.signers.forEach((signer,i) => signer.processEntropyDecommitment(decommitments[i]));
};

BitcoreTransaction.prototype.computeCiphertexts = function () {
  return this.signers.map(signer => signer.computeCiphertext());
};

BitcoreTransaction.prototype.extractSignatures = function (ciphertexts) {
  return this.signers.map((signer,i) => signer.extractSignature(ciphertexts[i]));
};

module.exports = BitcoreTransaction;
