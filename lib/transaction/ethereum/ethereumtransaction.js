'use strict';

import assert from 'assert';

const eth = require('eth-lib');
const helpers = require('web3-core-helpers');
const utils = require('web3-utils');
const abi = require('human-standard-token-abi');
const Decoder = require('ethereum-input-data-decoder');
const BN = require('bn.js');

export class EthereumTransaction {
  constructor() {
    this.tx = null;
    this.rlpEncoded = null;
    this.hash = null;
    this.signedTransaction = null;

    this.signer = null;

    this.data = false;

    this.decoder = new Decoder(abi);
  }

  static create() {
    return new EthereumTransaction();
  }

  fromOptions(tx, data) {
    this.tx = tx;
    this.data = data || false;

    return this;
  }

  static fromOptions(tx, data) {
    return new EthereumTransaction().fromOptions(tx, data);
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
        address: signature.inputs.find(p => p.name === '_to').value,
        value: new BN(signature.inputs.find(p => p.name === '_value').value.substring(2), 16)
      }]};
    } else {
      return { outputs: [{ address: this.tx.to, value: new BN(this.tx.value.substring(2), 16) }] };
    }
  }

  toJSON() {
    return {
      tx: this.tx,
      data: this.data
    };
  }

  fromJSON(json) {
    this.tx = json.tx;
    this.data = json.data;
    return this;
  }

  static fromJSON(json) {
    return new EthereumTransaction().fromJSON(json);
  }

  mapInputs(compoundKey) {
    return compoundKey;
  }

  getHashes(ignored) {
    assert(this.tx);

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

    return this.hash;
  }

  normalizeSignatures(mapping, rawSignatures) {
    const addToV = eth.nat.toNumber(utils.numberToHex(this.tx.chainId) || '0x1') * 2 + 35;
    const normalized = eth.account.encodeSignature([
      eth.bytes.pad(1, eth.bytes.fromNumber(addToV + rawSignatures.recoveryParam)),
      eth.bytes.pad(32, eth.bytes.fromNat('0x' + rawSignatures.r.toString(16))),
      eth.bytes.pad(32, eth.bytes.fromNat('0x' + rawSignatures.s.toString(16)))
    ]);

    const rawTx = eth.RLP.decode(this.rlpEncoded).slice(0,6).concat(eth.account.decodeSignature(normalized));
    const rawTransaction = eth.RLP.encode(rawTx);

    const values = eth.RLP.decode(rawTransaction);

    return {
      messageHash: '0x' + this.hash.toString('hex'),
      v: values[6],
      r: values[7],
      s: values[8],
      rawTransaction: rawTransaction
    };
  }

  applySignatures(signatures) {
    this.signedTransaction = signatures;
  }

  toRaw() {
    return this.signedTransaction.rawTransaction;
  }

  verify() {
    assert(this.signedTransaction);
    return true;
  }

  startSign(hash, key) {
    this.signer = key.startSign(hash);
  }

  createEntropyCommitments() {
    return this.signer.createEntropyCommitment();
  }

  processEntropyCommitments(commitment) {
    return this.signer.processEntropyCommitment(commitment);
  }

  processEntropyDecommitments(decommitment) {
    this.signer.processEntropyDecommitment(decommitment);
  }

  computeCiphertexts() {
    return this.signer.computeCiphertext();
  }

  extractSignatures(ciphertext) {
    return this.signer.extractSignature(ciphertext);
  }
}

EthereumTransaction.Mainnet = 'main';
EthereumTransaction.Testnet = 'testnet';
