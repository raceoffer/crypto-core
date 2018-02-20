const assert = require("assert");

function Transaction(options) {
  if(!(this instanceof Transaction))
    return new Transaction(options);

  this.network = Transaction.Testnet;

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

Transaction.Mainnet = 'main';
Transaction.Testnet = 'testnet';

Transaction.prototype.networkName = function (network) {
  return network;
};

Transaction.prototype.defaultSigtype = function () {
  return this.Signature.SIGHASH_ALL;
};

Transaction.prototype.fromOptions = function fromOptions(options) {
  this.network = options.network;

  return this;
};

Transaction.fromOptions = function fromOptions(options) {
  return new Transaction().fromOptions(options);
};

Transaction.prototype.totalOutputs = function totalOutputs() {
  assert(this.tx);

  return Object.entries(this.tx.outputs.reduce((result, output, i) => {
    if (i === this.tx._changeIndex) { // skip change
      return result;
    }

    const address = output.script.toAddress(this.networkName(this.network)).toString();
    if(typeof result[address] !== 'undefined') {
      result[address] += output.satoshis;
    } else {
      result[address] = output.satoshis;
    }

    return result;
  }, {})).map((array) => { return { address: array[0], value: array[1] } });
};

Transaction.prototype.prepare = function(options) {
  assert(false);
};

Transaction.prototype.toJSON = function toJSON() {
  return {
    tx: this.tx.toObject(),
    network: this.network
  };
};

Transaction.prototype.fromJSON = function fromJSON(json) {
  this.tx.fromObject(json.tx);
  this.network = json.network;
  return this;
};

Transaction.fromJSON = function fromJSON(json) {
  return new Transaction().fromJSON(json);
};

Transaction.prototype.mapInputs = function mapInputs(compoundKeys) {
  assert(this.tx);

  if (!Array.isArray(compoundKeys)) {
    compoundKeys = [ compoundKeys ];
  }

  return this.tx.inputs.map((input, index) => {
    let compoundKey = null;
    switch (input.constructor.name) {
      case 'PublicKeyHashInput':
        compoundKey = compoundKeys.find(compoundKey => {
          const publicKeyBuffer = compoundKey.getCompoundPublicKey();
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

Transaction.prototype.getHashes = function(mapping, sigtype) {
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

Transaction.prototype.normalizeSignatures = function(mapping, rawSignatures, sigtype) {
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

Transaction.prototype.applySignatures = function(signatures) {
  assert(this.tx);

  signatures.forEach((signature) => {
    this.tx.applySignature(signature);
  });
};

Transaction.prototype.toRaw = function () {
  assert(this.tx);

  assert(this.tx.isFullySigned());
  return this.tx.serialize();
};

Transaction.prototype.verify = function () {
  assert(this.tx);

  return this.tx.verify();
}

Transaction.prototype.startSign = function(hashes,keyMap) {
  return keyMap.map((key,i) => key.key.startSign(hashes[i]));
};

Transaction.prototype.createEntropyCommitments = function(signers) {
  return signers.map(signer => signer.createEntropyCommitment());
};

Transaction.prototype.processEntropyCommitments = function(signers,commitments) {
  return signers.map((signer,i) => signer.processEntropyCommitment(commitments[i]));
};

Transaction.prototype.processEntropyDecommitments = function(signers,decommitments) {
  signers.forEach((signer,i) => signer.processEntropyDecommitment(decommitments[i]));
};

Transaction.prototype.computeCiphertexts = function (signers) {
  return signers.map(signer => signer.computeCiphertext());
};

Transaction.prototype.extractSignatures = function (signers,ciphertexts) {
  return signers.map((signer,i) => signer.extractSignature(ciphertexts[i]));
};

module.exports = Transaction;
