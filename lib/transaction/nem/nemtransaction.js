const assert = require('assert');
const BN = require('bn.js');

const { Buffer } = require('buffer');

const { default: Nem } = require('nem-sdk');

const { encodeBuffer, decodeBuffer } = require('../../convert');

const { Root } = require('protobufjs');
const proto = require('./nemtransaction.json');

const root = Root.fromJSON(proto);

class NemTransaction {
  constructor() {
    this.tx = null;
    this.hash = null;
    this.signature = null;
  }
  
  static create() {
    return new NemTransaction();
  }
  
  fromOptions(tx) {
    this.tx = tx;
    this.hash = Buffer.from(Nem.utils.serialization.serializeTransaction(this.tx));
    
    return this;
  }
  
  static fromOptions(tx) {
    return new NemTransaction().fromOptions(tx);
  }
  
  toJSON(hex) {
    return {
      tx: this.tx,
      hash: hex ? encodeBuffer(this.hash) : this.hash,
      signature: this.signature
    };
  }
  
  fromJSON(json, hex) {
    this.tx = json.tx;
    this.hash = hex ? decodeBuffer(json.hash) : json.hash;
    this.signature = json.signature;
    return this;
  }
  
  static fromJSON(json, hex) {
    return new NemTransaction().fromJSON(json, hex);
  }

  toBytes() {
    const Type = root.lookupType('NemTransaction');
    return new Buffer(Type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const Type = root.lookupType('NemTransaction');
    return this.fromJSON(Type.decode(bytes));
  }

  static fromBytes(bytes) {
    return new NemTransaction().fromBytes(bytes);
  }
  
  estimateSize() {
    return 1;
  }
  
  estimateFee() {
    return new BN(this.tx.fee);
  }
  
  validate(ignored) {
    const statistics = this.totalOutputs();
    
    return !(!statistics.outputs || statistics.outputs.length !== 1 || statistics.outputs[0].value.isNeg());
  }
  
  totalOutputs() {
    assert(this.tx);
    return { outputs: [{ address: this.tx.recipient, value: new BN(this.tx.amount) }] };
  }

  startSignSession(key) {
    return key.startSignSession(this.hash);
  }

  startSignSessionShard(key) {
    return key.startSignSessionShard(this.hash);
  }
  
  applySignature(rawSignature) {
    this.signature = rawSignature.crypto.makeSignature({
      R: rawSignature.compoundPublicEntropy,
      S: rawSignature.signature,
      Rencoded: rawSignature.crypto.encodePoint(rawSignature.compoundPublicEntropy)
    }).toHex().toLowerCase();
  }
  
  verify() {
    return Nem.crypto.verifySignature(this.tx.signer, this.hash, this.signature);
  }
  
  toRaw() {
    assert(this.signature);
    return {
      'data': Nem.utils.convert.ua2hex(this.hash),
      'signature': this.signature
    };
  }
}

NemTransaction.Mainnet = 'main';
NemTransaction.Testnet = 'testnet';

module.exports = {
  NemTransaction
};
