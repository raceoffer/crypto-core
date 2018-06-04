'use strict';

import assert from 'assert';
import BN from 'bn.js';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

export class BitcoreTransaction {
  constructor(
    PublicKey,
    PrivateKey,
    Hash,
    BN,
    Point,
    Transaction,
    BufferUtil,
    Signature,
    TXSignature,
    PublicKeyHashInput,
    PublicKeyInput
  ) {
    this.PublicKey = PublicKey;
    this.PrivateKey = PrivateKey;
    this.Hash = Hash;
    this.BN = BN;
    this.Point = Point;
    this.Transaction = Transaction;
    this.BufferUtil = BufferUtil;
    this.Signature = Signature;
    this.TXSignature = TXSignature;
    this.PublicKeyHashInput = PublicKeyHashInput;
    this.PublicKeyInput = PublicKeyInput;

    this.network = null;
    this.tx = null;
    this.signers = null;
  }

  networkName(network) {
    return network;
  }

  defaultSigtype() {
    return this.Signature.SIGHASH_ALL;
  }

  fromOptions(options) {
    assert(options.network);
    assert(options.utxo);
    assert(options.address);
    assert(options.value);
    assert(options.from);

    this.network = options.network || BitcoreTransaction.Testnet;
    this.tx = new this.Transaction();

    this.tx = this.tx
      .from(options.utxo)
      .to(options.address, options.value.toNumber());

    if(options.fee) {
      this.tx = this.tx.fee(options.fee.toNumber());
    }

    this.tx = this.tx.change(options.from);

    assert(this.tx.hasAllUtxoInfo());

    return this;
  }

  estimateSize() {
    return this.tx._estimateSize();
  }

  totalOutputs() {
    assert(this.tx);

    const transaformer = output => {
      return {
        address: output.script.toAddress(this.networkName(this.network)).toString(),
        value: new BN(output.satoshis)
      };
    };

    const change = this.tx.outputs.filter((output, i) => i === this.tx._changeIndex).map(transaformer);
    const outputs = this.tx.outputs.filter((output, i) => i !== this.tx._changeIndex).map(transaformer);
    const inputs = this.tx.inputs.map(input => input.output).map(transaformer);

    return { inputs, outputs, change };
  }

  estimateFee() {
    const statistics = this.totalOutputs();

    const fee = new BN();
    fee.iadd(statistics.inputs.reduce((sum, input) => sum.add(input.value), new BN()));
    fee.isub(statistics.outputs.reduce((sum, output) => sum.add(output.value), new BN()));
    fee.isub(statistics.change.reduce((sum, change) => sum.add(change.value), new BN()));

    return fee;
  }

  validate(address) {
    const statistics = this.totalOutputs();

    // check if every input belongs to owned address
    if (!statistics.inputs
      || statistics.inputs.length < 1
      || statistics.inputs.some(input => input.address !== address)) {
      return false;
    }

    // check if change goes to owned address
    if (statistics.change.some(change => change.address !== address)) {
      return false;
    }

    return true;
  }

  toJSON() {
    return {
      tx: this.tx.toObject(),
      network: this.network
    };
  }

  fromJSON(json) {
    this.tx = new this.Transaction();
    this.tx.fromObject(json.tx);
    this.network = json.network;
    return this;
  }

  mapInputs(compoundKeys) {
    assert(this.tx);

    if (!Array.isArray(compoundKeys)) {
      compoundKeys = [ compoundKeys ];
    }

    return this.tx.inputs.map((input, index) => {
      let compoundKey = null;
      if (input instanceof this.PublicKeyHashInput) {
        compoundKey = compoundKeys.find(compoundKey => {
          const publicKeyBuffer = Buffer.from(compoundKey.getCompoundPublicKey().encode(true, 'array'));
          const hashData = this.Hash.sha256ripemd160(publicKeyBuffer);
          return this.BufferUtil.equals(hashData, input.output.script.getPublicKeyHash());
        }) || null;
      }
      if (input instanceof this.PublicKeyInput) {
        compoundKey = compoundKeys.find(compoundKey => {
          const publicKeyString = compoundKey.getCompoundPublicKey('hex');
          return publicKeyString === input.output.script.getPublicKey().toString('hex');
        }) || null;
      }
      return {
        key: compoundKey,
        index: index
      };
    });
  }

  getHashes(mapping, sigtype) {
    assert(this.tx);

    sigtype = sigtype || this.defaultSigtype();
    return mapping.map((item) => {
      const index = item.index;
      const input = this.tx.inputs[index];

      assert(input);

      const hash = this.Transaction.Sighash.sighash(this.tx, sigtype, index, input.output.script, input.output.satoshisBN);

      const reversebuf = function(buf) {
        const buf2 = new Buffer(buf.length);
        for (let i = 0; i < buf.length; i++) {
          buf2[i] = buf[buf.length - 1 - i];
        }
        return buf2;
      };

      return reversebuf(hash);
    });
  }

  normalizeSignatures(mapping, rawSignatures, sigtype) {
    assert(this.tx);

    sigtype = sigtype || this.defaultSigtype();

    return mapping.map((entry, i) => {
      const index = entry.index;
      const input = this.tx.inputs[index];
      const key = entry.key.getCompoundPublicKey();
      const publicKey = new this.PublicKey(
        new this.Point(
          this.BN.fromString(key.x.toString(16), 16),
          this.BN.fromString(key.y.toString(16), 16),
          true
        ), {
          network: this.networkName(this.network)
        });
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
  }

  applySignatures(signatures) {
    assert(this.tx);

    signatures.forEach((signature) => {
      this.tx.applySignature(signature);
    });
  }

  toRaw() {
    assert(this.tx);

    assert(this.tx.isFullySigned());
    return this.tx.serialize();
  }

  verify() {
    assert(this.tx);

    return this.tx.verify();
  }

  startSign(hashes, keyMap) {
    this.signers = keyMap.map((key,i) => key.key.startSign(hashes[i]));
  }

  createEntropyCommitments() {
    return this.signers.map(signer => signer.createEntropyCommitment());
  }

  processEntropyCommitments(commitments) {
    return this.signers.map((signer,i) => signer.processEntropyCommitment(commitments[i]));
  }

  processEntropyDecommitments(decommitments) {
    this.signers.forEach((signer,i) => signer.processEntropyDecommitment(decommitments[i]));
  }

  computeCiphertexts() {
    return this.signers.map(signer => signer.computeCiphertext());
  }

  extractSignatures(ciphertexts) {
    return this.signers.map((signer,i) => signer.extractSignature(ciphertexts[i]));
  }
}

BitcoreTransaction.Mainnet = 'main';
BitcoreTransaction.Testnet = 'testnet';
