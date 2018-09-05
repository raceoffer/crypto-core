const assert = require('assert');
const Neon = require('@cityofzion/neon-js');
const BN = require('bn.js');

const { Buffer } = require('buffer');

const { Root } = require('protobufjs');
const proto = require('./neotransaction.json');

const root = Root.fromJSON(proto);

class NeoTransaction {
  constructor() {
    this.tx = null;
    this.url = null;
    this.publicKey = null;
    this.signer = null;
    this.fees = null;
  }

  static create() {
    return new NeoTransaction();
  }

  fromOptions(options) {
    this.tx = options.tx;
    this.url = options.url;
    this.fees = options.fees;
    this.publicKey = Neon.wallet.getPublicKeyEncoded(options.publicKey.encode('hex', false));

    return this;
  }

  static fromOptions(options) {
    return new NeoTransaction().fromOptions(options);
  }

  toJSON(hex) {
    return {
      tx: this.tx,
      publicKey: this.publicKey,
      url: this.url,
      fees: this.fees,
    };
  }

  fromJSON(json, hex) {
    this.tx = json.tx;
    this.url = json.url;
    this.publicKey = json.publicKey;
    this.fees = json.fees;
    return this;
  }

  static fromJSON(json, hex) {
    return new NeoTransaction().fromJSON(json, hex);
  }

  toBytes() {
    const Type = root.lookupType('NeoTransaction');
    return new Buffer(Type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const Type = root.lookupType('NeoTransaction');
    return this.fromJSON(Type.decode(bytes));
  }

  static fromBytes(bytes) {
    return new NeoTransaction().fromBytes(bytes);
  }

  startSignSession(key) {
    const transaction = new Neon.tx.Transaction(this.tx);

    const tx = Neon.tx.serializeTransaction(transaction, false);
    const msgHash = Neon.u.sha256(tx);
    const msgHashHex = Buffer.from(msgHash, 'hex');

    return key.startSignSession(msgHashHex);
  }

  startSignSessionShard(key) {
    return this.startSignSession(key);
  }

  applySignature(signature) {
    const rawSignature = Buffer.concat([
      signature.compoundScalarEntropy.toArrayLike(Buffer, 'be', 32),
      signature.signature.toArrayLike(Buffer, 'be', 32)
    ]);

    const invocationScript = '40' + rawSignature.toString('hex');
    const verificationScript = Neon.wallet.getVerificationScriptFromPublicKey(this.publicKey);
    const witness = {invocationScript, verificationScript};

    this.tx.scripts ? this.tx.scripts.push(witness) : this.tx.scripts = [witness];
  }

  toRaw() {
    return {
      tx: this.tx,
      url: this.url
    };
  }

  verify() {
    assert(this.tx.scripts);
    return true;
  }

  estimateSize() {
    return 1;
  }

  estimateFee() {
    return new BN(this.fees);
  }

  validate(ignored) {
    const statistics = this.totalOutputs();

    return !(!statistics.outputs || statistics.outputs.length !== 1 || statistics.outputs[0].value.isNeg());
  }

  totalOutputs() {
    assert(this.tx);
    const output = this.tx.outputs[0];
    const address = Neon.wallet.getAddressFromScriptHash(output.scriptHash);

    return { outputs: [{ address: address, value: new BN(output.value) }] };
  }
}

NeoTransaction.Mainnet = 'main';
NeoTransaction.Testnet = 'testnet';

module.exports = {
  NeoTransaction
};
