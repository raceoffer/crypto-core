const assert = require('assert');
const BN = require('bn.js');

const { Buffer } = require('buffer');

const { default: Nem } = require('nem-sdk');

class NemTransaction {
  constructor() {
    this.tx = null;
    this.hash = null;
    this.signature = null;
    
    this.signer = null;
  }
  
  static create() {
    return new NemTransaction();
  }
  
  fromOptions(tx) {
    this.tx = tx;
    
    return this;
  }
  
  static fromOptions(tx) {
    return new NemTransaction().fromOptions(tx);
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
  
  toJSON() {
    return {
      tx: this.tx,
      hash: encodeBuffer(this.hash),
      signature: toJSON(this.signature),
      signer: toJSON(this.signer)
    };
  }
  
  fromJSON(json, hex) {
    this.tx = json.tx;
    this.hash = hex ? decodeBuffer(json.hash) : json.hash;
    this.signature = fromJSON(Signature, json.signature, hex);
    this.signer = fromJSON(Signer, json.signer, hex);
    return this;
  }
  
  static fromJSON(json, hex) {
    return new NemTransaction().fromJSON(json, hex);
  }
  
  startSignSession(key) {
    this.hash = Buffer.from(Nem.utils.serialization.serializeTransaction(this.tx));
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
    this.signature = this.signer.finalizeSignature(signature);
  }
  
  verify() {
    return Nem.crypto.verifySignature(this.tx.signer, this.hash, this.signature.toHex());
  }
  
  toRaw() {
    assert(this.signature);
    return {
      'data': Nem.utils.convert.ua2hex(this.hash),
      'signature': this.signature.toHex()
    };
  }
}

NemTransaction.Mainnet = 'main';
NemTransaction.Testnet = 'testnet';

module.exports = {
  NemTransaction
};
