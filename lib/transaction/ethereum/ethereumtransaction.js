'use strict';

const assert = require('assert');

const eth = require('eth-lib');
const helpers = require('web3-core-helpers');
const utils = require('web3-utils');
const abi = require('human-standard-token-abi');
const Decoder = require('ethereum-input-data-decoder');
const BN = require('bn.js');

const { Root } = require('protobufjs');
const proto = require('./ethereumtransaction.json');

const root = Root.fromJSON(proto);

const { Buffer } = require('buffer');

const { encodeBuffer, decodeBuffer } = require('../../convert');

class EthereumTransaction {
  constructor() {
    this.tx = null;
    this.rlpEncoded = null;
    this.hash = null;
    this.signature = null;

    this.data = false;

    this.decoder = new Decoder(abi);
  }

  static create() {
    return new EthereumTransaction();
  }

  fromOptions(tx, data) {
    this.tx = tx;
    this.data = data || false;
    
    const transaction = {
      nonce: utils.numberToHex(this.tx.nonce),
      to: this.tx.to ? helpers.formatters.inputAddressFormatter(this.tx.to) : '0x',
      data: this.tx.data || '0x',
      value: this.tx.value ? utils.numberToHex(this.tx.value) : '0x',
      gas: utils.numberToHex(this.tx.gasLimit || this.tx.gas),
      gasPrice: utils.numberToHex(Math.round(this.tx.gasPrice)),
      chainId: utils.numberToHex(this.tx.chainId)
    };

    this.rlpEncoded = eth.RLP.encode([
      eth.bytes.fromNat(transaction.nonce),
      eth.bytes.fromNat(transaction.gasPrice),
      eth.bytes.fromNat(transaction.gas),
      transaction.to.toLowerCase(),
      eth.bytes.fromNat(transaction.value),
      transaction.data,
      eth.bytes.fromNat(transaction.chainId || '0x1'),
      '0x',
      '0x']);

    this.hash = Buffer.from(eth.hash.keccak256(this.rlpEncoded).slice(2), 'hex');

    return this;
  }

  static fromOptions(tx, data) {
    return new EthereumTransaction().fromOptions(tx, data);
  }

  toJSON(hex) {
    return {
      tx: this.tx,
      data: this.data,
      rlpEncoded: this.rlpEncoded,
      hash: hex ? encodeBuffer(this.hash) : this.hash,
      signature: this.signature
    };
  }

  fromJSON(json, hex) {
    this.tx = json.tx;
    this.data = json.data;
    this.rlpEncoded = json.rlpEncoded;
    this.hash = hex ? decodeBuffer(json.hash) : Buffer.from(json.hash);
    this.signature = json.signature;
    return this;
  }

  static fromJSON(json, hex) {
    return new EthereumTransaction().fromJSON(json, hex);
  }

  toBytes() {
    const Type = root.lookupType('EthereumTransaction');
    return new Buffer(Type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const Type = root.lookupType('EthereumTransaction');
    return this.fromJSON(Type.decode(bytes));
  }

  static fromBytes(bytes) {
    return new EthereumTransaction().fromBytes(bytes);
  }

  estimateSize() {
    return this.tx.gas;
  }

  estimateFee() {
    return new BN(this.tx.gasPrice).mul(new BN(this.tx.gas));
  }

  validate(ignored) {
    const statistics = this.totalOutputs();

    return !(!statistics.outputs || statistics.outputs.length !== 1 || statistics.outputs[0].value.isNeg());
  }

  totalOutputs() {
    assert(this.tx);
    if (this.data) {
      const signature = this.decoder.decodeData(this.tx.data);
      return { outputs: [{
        address: '0x' + signature.inputs[0],
        value: signature.inputs[1]
      }]};
    } else {
      return { outputs: [{ address: this.tx.to, value: new BN(this.tx.value.substring(2), 16) }] };
    }
  }

  startSignSession(key) {
    return key.startSignSession(this.hash);
  }

  startSignSessionShard(key) {
    return this.startSignSession(key);
  }

  applySignature(rawSignature) {
    const addToV = eth.nat.toNumber(utils.numberToHex(this.tx.chainId) || '0x1') * 2 + 35;
    const normalized = eth.account.encodeSignature([
      eth.bytes.pad(1, eth.bytes.fromNumber(addToV + rawSignature.recoveryParameter)),
      eth.bytes.pad(32, eth.bytes.fromNat('0x' + rawSignature.compoundScalarEntropy.toString(16))),
      eth.bytes.pad(32, eth.bytes.fromNat('0x' + rawSignature.signature.toString(16)))
    ]);

    const rawTx = eth.RLP.decode(this.rlpEncoded).slice(0,6).concat(eth.account.decodeSignature(normalized));
    const rawTransaction = eth.RLP.encode(rawTx);

    const values = eth.RLP.decode(rawTransaction);

    this.signature = {
      messageHash: '0x' + this.hash.toString('hex'),
      v: values[6],
      r: values[7],
      s: values[8],
      rawTransaction: rawTransaction
    };
  }

  toRaw() {
    return this.signature.rawTransaction;
  }

  verify() {
    assert(this.signature);
    return true;
  }
}

EthereumTransaction.Mainnet = 'main';
EthereumTransaction.Testnet = 'testnet';

module.exports = {
  EthereumTransaction
};
