'use strict';

import assert from 'assert';
import BN from 'bn.js';
import {
  Field,
  generateMessage
} from "../../convert";

import {
  DistributedEcdsaKey,
  DistributedEcdsaKeyShard
} from '../../primitives/ecdsa/distributedkey';

import {
  DistributedEcdsaSignSession,
  DistributedEcdsaSignSessionShard,
  EcdsaEntropyCommitment,
  EcdsaEntropyDecommitment,
  EcdsaEntropyData,
  EcdsaPartialSignature,
  EcdsaSignature
} from '../../primitives/ecdsa/distributedsignsession';

import { Root } from 'protobufjs';
import * as proto from './bitcoretransaction.json';

const root = Root.fromJSON(proto);

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

  toJSON() {
    return {
      tx: this.tx ? this.tx.toObject() : null,
      network: this.network
    };
  }

  fromJSON(json) {
    this.tx = json.tx ? new this.Transaction().fromObject(json.tx) : null;
    this.network = json.network;
    return this;
  }

  toBytes() {
    const Type = root.lookupType('BitcoreTransaction');
    return new Buffer(Type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const Type = root.lookupType('BitcoreTransaction');
    const obj = Type.decode(bytes);
    obj.tx.inputs.forEach(input => {
      input.sequenceNumber = parseInt(input.sequenceNumber);
      input.output.satoshis = parseInt(input.output.satoshis);
    });
    obj.tx.outputs.forEach(output => {
      output.satoshis = parseInt(output.satoshis);
    });
    return this.fromJSON(obj);
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

  startSignSession(key) {
    const mapping = this._mapInputs(key);
    const hashes = this._getHashes();
    return BitcoreSignSession.fromOptions({
      mapping: mapping,
      signers: mapping.map((key, i) => key.startSignSession(hashes[i]))
    });
  }

  startSignSessionShard(key) {
    const mapping = this._mapInputs(key);
    const hashes = this._getHashes();
    return BitcoreSignSessionShard.fromOptions({
      mapping: mapping,
      signers: mapping.map((key, i) => key.startSignSession(hashes[i]))
    });
  }

  applySignature(remote) {
    const normalizedSignature = this._normalizeSignatures(remote.mapping, remote.signature);

    normalizedSignature.forEach((signature) => {
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

  // sort-of-private methods

  _mapInputs(compoundKeys) {
    assert(this.tx);

    if (!Array.isArray(compoundKeys)) {
      compoundKeys = [ compoundKeys ];
    }

    return this.tx.inputs.map((input) => {
      let compoundKey = null;
      if (input instanceof this.PublicKeyHashInput) {
        compoundKey = compoundKeys.find(compoundKey => {
          const publicKeyBuffer = Buffer.from(compoundKey.compoundPublic().encode('array', true));
          const hashData = this.Hash.sha256ripemd160(publicKeyBuffer);
          return this.BufferUtil.equals(hashData, input.output.script.getPublicKeyHash());
        }) || null;
      }
      if (input instanceof this.PublicKeyInput) {
        compoundKey = compoundKeys.find(compoundKey => {
          const publicKeyString = compoundKey.compoundPublic().encode('hex', true);
          return publicKeyString === input.output.script.getPublicKey().toString('hex');
        }) || null;
      }
      return compoundKey;
    });
  }

  _getHashes(sigtype) {
    assert(this.tx);

    const reversebuf = function(buf) {
      const buf2 = new Buffer(buf.length);
      for (let i = 0; i < buf.length; i++) {
        buf2[i] = buf[buf.length - 1 - i];
      }
      return buf2;
    };

    sigtype = sigtype || this.defaultSigtype();
    return this.tx.inputs.map((input, index) => {
      return reversebuf(this.Transaction.Sighash.sighash(this.tx, sigtype, index, input.output.script, input.output.satoshisBN));
    });
  }

  _normalizeSignatures(mapping, rawSignatures, sigtype) {
    assert(this.tx);

    sigtype = sigtype || this.defaultSigtype();

    return this.tx.inputs.map((input, index) => {
      const key = mapping[index].compoundPublic();
      const publicKey = new this.PublicKey(
        new this.Point(
          this.BN.fromString(key.x.toString(16), 16),
          this.BN.fromString(key.y.toString(16), 16),
          true
        ), {
          network: this.networkName(this.network)
        });
      const rawSignature = rawSignatures[index];

      const signature = new this.Signature({
        r: this.BN.fromString(rawSignature.compoundScalarEntropy.toString(16), 16),
        s: this.BN.fromString(rawSignature.signature.toString(16), 16),
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
}

export const BitcoreEntropyCommitment = generateMessage(
  'BitcoreEntropyCommitment', {
    entropyCommitment: [Field.Array, Field.Custom, EcdsaEntropyCommitment]
  },
  root
);

export const BitcoreEntropyDecommitment = generateMessage(
  'BitcoreEntropyDecommitment', {
    entropyDecommitment: [Field.Array, Field.Custom, EcdsaEntropyDecommitment]
  },
  root
);

export const BitcoreSignature = generateMessage(
  'BitcoreSignature', {
    mapping: [Field.Array, Field.Custom, DistributedEcdsaKey],
    signature: [Field.Array, Field.Custom, EcdsaSignature]
  },
  root
);

export class BitcoreSignSession extends generateMessage(
  'BitcoreSignSession', {
    mapping: [Field.Array, Field.Custom, DistributedEcdsaKey],
    signers: [Field.Array, Field.Custom, DistributedEcdsaSignSession]
  },
  root
) {
  static fromOptions(options) {
    return new BitcoreSignSession().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new BitcoreSignSession().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new BitcoreSignSession().fromBytes(bytes);
  }

  createEntropyCommitment() {
    return BitcoreEntropyCommitment.fromOptions({
      entropyCommitment: this.signers.map((signer) => signer.createEntropyCommitment())
    });
  }

  processEntropyData(remote) {
    return BitcoreEntropyDecommitment.fromOptions({
      entropyDecommitment: this.signers.map((signer, i) => signer.processEntropyData(remote.entropyData[i]))
    });
  }

  finalizeSignature(remote) {
    return BitcoreSignature.fromOptions({
      mapping: this.mapping,
      signature: this.signers.map((signer, i) => signer.finalizeSignature(remote.partialSignature[i]))
    });
  }
}

export const BitcoreEntropyData = generateMessage(
  'BitcoreEntropyData', {
    entropyData: [Field.Array, Field.Custom, EcdsaEntropyData]
  },
  root
);

export const BitcorePartialSignature = generateMessage(
  'BitcorePartialSignature', {
    partialSignature: [Field.Array, Field.Custom, EcdsaPartialSignature]
  },
  root
);

export class BitcoreSignSessionShard extends generateMessage(
  'BitcoreSignSessionShard', {
    mapping: [Field.Array, Field.Custom, DistributedEcdsaKeyShard],
    signers: [Field.Array, Field.Custom, DistributedEcdsaSignSessionShard]
  },
  root
) {
  static fromOptions(options) {
    return new BitcoreSignSessionShard().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new BitcoreSignSessionShard().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new BitcoreSignSessionShard().fromBytes(bytes);
  }

  processEntropyCommitment(remote) {
    return BitcoreEntropyData.fromOptions({
      entropyData: this.signers.map((signer, i) => signer.processEntropyCommitment(remote.entropyCommitment[i]))
    });
  }

  processEntropyDecommitment(remote) {
    return BitcorePartialSignature.fromOptions({
      partialSignature: this.signers.map((signer, i) => signer.processEntropyDecommitment(remote.entropyDecommitment[i]))
    });
  }
}

BitcoreTransaction.Mainnet = 'main';
BitcoreTransaction.Testnet = 'testnet';
