const assert = require("assert");
const eth = require('eth-lib');
const helpers = require('web3-core-helpers');
const utils = require('web3-utils');
const abi = require('human-standard-token-abi');
const decoder = require('abi-decoder');

decoder.addABI(abi);

function EthereumTransaction() {
  this.tx = null;
  this.rlpEncoded = null;
  this.hash = null;
  this.signedTransaction = null;

  this.signer = null;
}

EthereumTransaction.Mainnet = 'main';
EthereumTransaction.Testnet = 'testnet';

EthereumTransaction.prototype.fromOptions = function fromOptions(options) {
  this.tx = options;

  return this;
};

EthereumTransaction.fromOptions = function fromOptions(options) {
  return new EthereumTransaction().fromOptions(options);
};

EthereumTransaction.prototype.estimateSize = function estimatedSize() {
  return this.tx.gas;
};

EthereumTransaction.prototype.estimateFee = function estimateFee() {
  return this.tx.gasPrice * this.tx.gas;
};

EthereumTransaction.prototype.totalOutputs = function totalOutputs() {
  assert(this.tx);
  return { outputs: [{ address: this.tx.to, value: this.tx.value }] };
};

EthereumTransaction.prototype.transferData = function transferData() {
  assert(this.tx);
  const signature = decoder.decodeMethod(this.tx.data);
  return { outputs: [{
    address: signature.params.find(p => p.name === '_to').value,
    value: signature.params.find(p => p.name === '_value').value
  }]};
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
};

EthereumTransaction.prototype.normalizeSignatures = function(mapping, rawSignatures) {
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

EthereumTransaction.prototype.startSign = function(hash, key) {
  this.signer = key.startSign(hash);
};

EthereumTransaction.prototype.createEntropyCommitments = function() {
  return this.signer.createEntropyCommitment();
};

EthereumTransaction.prototype.processEntropyCommitments = function(commitment) {
  return this.signer.processEntropyCommitment(commitment);
};

EthereumTransaction.prototype.processEntropyDecommitments = function(decommitment) {
  this.signer.processEntropyDecommitment(decommitment);
};

EthereumTransaction.prototype.computeCiphertexts = function() {
  return this.signer.computeCiphertext();
};

EthereumTransaction.prototype.extractSignatures = function(ciphertext) {
  return this.signer.extractSignature(ciphertext);
};

module.exports = EthereumTransaction;
