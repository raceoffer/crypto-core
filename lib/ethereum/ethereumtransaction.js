const assert = require("assert");
const eth = require('eth-lib');
const helpers = require('web3-core-helpers');
const utils = require('web3-utils');

function EthereumTransaction(options) {
  if(!(this instanceof EthereumTransaction))
    return new EthereumTransaction(options);

  this.tx = null;
  this.rlpEncoded = null;
  this.hash = null;
  this.signedTransaction = null;

  if(options) {
    this.fromOptions(options);
  }
}

EthereumTransaction.Mainnet = 'main';
EthereumTransaction.Testnet = 'testnet';

EthereumTransaction.prototype.fromOptions = function fromOptions(options) {
  return this;
};

EthereumTransaction.fromOptions = function fromOptions(options) {
  return new EthereumTransaction().fromOptions(options);
};

EthereumTransaction.prototype.totalOutputs = function totalOutputs() {
  assert(this.tx);
  return [{ address: this.tx.to, value: this.tx.value }];
};

EthereumTransaction.prototype.prepare = async function(options) {
  const tx = {
    from: options.from,
    to: options.to,
    value: options.value
  };

  if (options.gasPrice) {
    tx.gasPrice = options.gasPrice;
  }

  this.tx = await options.wallet.fill(tx);
};

EthereumTransaction.prototype.toJSON = function toJSON() {
  return {
    tx: this.tx
  };
};

EthereumTransaction.prototype.fromJSON = function fromJSON(json) {
  this.tx = json.tx;
  return this;
};

EthereumTransaction.fromJSON = function fromJSON(json) {
  return new EthereumTransaction().fromJSON(json);
};

EthereumTransaction.prototype.mapInputs = function mapInputs(compoundKey) {
  return compoundKey;
};

EthereumTransaction.prototype.getHashes = function(ignored) {
  assert(this.tx);

  const transaction = {
    nonce: utils.numberToHex(this.tx.nonce),
    to: this.tx.to ? helpers.formatters.inputAddressFormatter(this.tx.to) : '0x',
    data: this.tx.data || '0x',
    value: this.tx.value ? utils.numberToHex(this.tx.value) : '0x',
    gas: utils.numberToHex(this.tx.gasLimit || this.tx.gas),
    gasPrice: utils.numberToHex(this.tx.gasPrice),
    chainId: utils.numberToHex(this.tx.chainId)
  };

  this.rlpEncoded = eth.RLP.encode([
    eth.Bytes.fromNat(transaction.nonce),
    eth.Bytes.fromNat(transaction.gasPrice),
    eth.Bytes.fromNat(transaction.gas),
    transaction.to.toLowerCase(),
    eth.Bytes.fromNat(transaction.value),
    transaction.data,
    eth.Bytes.fromNat(transaction.chainId || '0x1'),
    '0x',
    '0x']);

  this.hash = Buffer.from(eth.Hash.keccak256(this.rlpEncoded).slice(2), 'hex');

  return this.hash;
};

EthereumTransaction.prototype.normalizeSignatures = function(mapping, rawSignatures) {
  const addToV = eth.Nat.toNumber(utils.numberToHex(this.tx.chainId) || '0x1') * 2 + 35;
  const normalized = eth.Account.encodeSignature([
    eth.Bytes.pad(1, eth.Bytes.fromNumber(addToV + rawSignatures.recoveryParam)),
    eth.Bytes.pad(32, eth.Bytes.fromNat('0x' + rawSignatures.r.toString(16))),
    eth.Bytes.pad(32, eth.Bytes.fromNat('0x' + rawSignatures.s.toString(16)))
  ]);

  const rawTx = eth.RLP.decode(this.rlpEncoded).slice(0,6).concat(eth.Account.decodeSignature(normalized));
  const rawTransaction = eth.RLP.encode(rawTx);

  const values = eth.RLP.decode(rawTransaction);

  return {
    messageHash: '0x' + this.hash.toString('hex'),
    v: values[6],
    r: values[7],
    s: values[8],
    rawTransaction: rawTransaction
  };
};

EthereumTransaction.prototype.applySignatures = function(signatures) {
  this.signedTransaction = signatures;
};

EthereumTransaction.prototype.toRaw = function () {
  return this.signedTransaction.rawTransaction;
};

EthereumTransaction.prototype.verify = function () {
  assert(this.signedTransaction);
  return true; // dunno
};

EthereumTransaction.prototype.startSign = function(hashes, keyMap) {
  return keyMap.startSign(hashes);
};

EthereumTransaction.prototype.createEntropyCommitments = function(signers) {
  return signers.createEntropyCommitment();
};

EthereumTransaction.prototype.processEntropyCommitments = function(signers, commitments) {
  return signers.processEntropyCommitment(commitments);
};

EthereumTransaction.prototype.processEntropyDecommitments = function(signers, decommitments) {
  signers.processEntropyDecommitment(decommitments);
};

EthereumTransaction.prototype.computeCiphertexts = function (signers) {
  return signers.computeCiphertext();
};

EthereumTransaction.prototype.extractSignatures = function (signers, ciphertexts) {
  return signers.extractSignature(ciphertexts);
};

module.exports = EthereumTransaction;
