'use strict';

import assert from 'assert';

import eth from 'eth-lib';
import helpers from 'web3-core-helpers';
import utils from 'web3-utils';
import abi from 'human-standard-token-abi';
import Decoder from 'ethereum-input-data-decoder';
import BN from 'bn.js';

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { Signer } from '../../primitives/ecdsa/distributedsigner';
import {
  fromJSON,
  toJSON,
  decodeBuffer,
  encodeBuffer
} from '../../convert';

export class EthereumTransaction {
  constructor() {
    this.tx = null;
    this.rlpEncoded = null;
    this.hash = null;
    this.signature = null;

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
        address: '0x' + signature.inputs[0],
        value: signature.inputs[1]
      }]};
    } else {
      return { outputs: [{ address: this.tx.to, value: new BN(this.tx.value.substring(2), 16) }] };
    }
  }

  toJSON() {
    return {
      tx: this.tx,
      data: this.data,
      rlpEncoded: this.rlpEncoded,
      hash: encodeBuffer(this.hash),
      signature: this.signature,
      signer: toJSON(this.signer)
    };
  }

  fromJSON(json) {
    this.tx = json.tx;
    this.data = json.data;
    this.rlpEncoded = json.rlpEncoded;
    this.hash = decodeBuffer(json.hash);
    this.signature = json.signature;
    this.signer = fromJSON(Signer, json.signer);
    return this;
  }

  static fromJSON(json) {
    return new EthereumTransaction().fromJSON(json);
  }

  startSignSession(key) {
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
    const rawSignature = this.signer.finalizeSignature(signature);

    const addToV = eth.nat.toNumber(utils.numberToHex(this.tx.chainId) || '0x1') * 2 + 35;
    const normalized = eth.account.encodeSignature([
      eth.bytes.pad(1, eth.bytes.fromNumber(addToV + rawSignature.recoveryParam)),
      eth.bytes.pad(32, eth.bytes.fromNat('0x' + rawSignature.r.toString(16))),
      eth.bytes.pad(32, eth.bytes.fromNat('0x' + rawSignature.s.toString(16)))
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
