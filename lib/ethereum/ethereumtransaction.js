const assert = require("assert");
const eth = require('eth-lib');
const helpers = require('web3-core-helpers');
const utils = require('web3-utils');
const SolidityCoder = require('web3-eth-abi');
const abi = require('human-standard-token-abi');
const Web3 = require('web3');

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

EthereumTransaction.prototype.decodeMethod = function(data) {
  const methodID = data.slice(2, 10);
  const abiItem = abi.find(method => {
    const signature = new Web3().sha3(method.name + "(" + method.inputs.map(function(input) {return input.type;}).join(",") + ")");
    return signature.slice(2, 10) === methodID;
  });
  if (abiItem) {
    const params = abiItem.inputs.map(function (item) { return item.type; });
    let decoded = SolidityCoder.decodeParams(params, data.slice(10));
    return {
      name: abiItem.name,
      params: decoded.map(function (param, index) {
        let parsedParam = param;
        const isUint = abiItem.inputs[index].type.indexOf("uint") === 0;
        const isInt = abiItem.inputs[index].type.indexOf("int") === 0;

        if (isUint || isInt) {
          const isArray = Array.isArray(param);

          if (isArray) {
            parsedParam = param.map(val => new Web3().toBigNumber(val).toString());
          } else {
            parsedParam = new Web3().toBigNumber(param).toString();
          }
        }
        return {
          name: abiItem.inputs[index].name,
          value: parsedParam,
          type: abiItem.inputs[index].type
        };
      })
    }
  }
};

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

EthereumTransaction.prototype.totalOutputs = function totalOutputs() {
  assert(this.tx);
  return { outputs: [{ address: this.tx.to, value: this.tx.value }] };
};

EthereumTransaction.prototype.transferData = function transferData() {
  assert(this.tx);
  const signature = this.decodeMethod(this.tx.data);
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
    gasPrice: utils.numberToHex(this.tx.gasPrice),
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
