import assert from 'assert';
import Neon from '@cityofzion/neon-js';

import buffer from 'buffer';

const Buffer = buffer.Buffer;

import {Signer} from '../../primitives/ecdsa/signer';
import {fromJSON, toJSON} from '../../convert';

export class NeoTransaction {
  constructor() {
    this.tx = null;
    this.url = null;
    this.signature = null;
    this.publicKey = null;
    this.signer = null;
  }

  static create() {
    return new NeoTransaction();
  }

  fromOptions(config) {
    this.tx = config.tx;
    this.url = config.url;

    return this;
  }

  static fromOptions(config) {
    return new NeoTransaction().fromOptions(config);
  }

  toJSON() {
    return {
      tx: this.tx,
      signer: toJSON(this.signer),
      signature: this.signature,
      publicKey: this.publicKey,
      url: this.url,
    };
  }

  fromJSON(json) {
    this.tx = json.tx;
    this.url = json.url;
    this.signer = fromJSON(Signer, json.signer);
    this.signature = json.signature;
    this.publicKey = json.publicKey;
    return this;
  }

  static fromJSON(json) {
    return new NeoTransaction().fromJSON(json);
  }

  startSignSession(key) {
    this.publicKey = Neon.wallet.getPublicKeyEncoded(key.compoundPublic().encode('hex', false));
    const tx = Neon.tx.serializeTransaction(new Neon.tx.Transaction(this.tx), false);
    const msgHash = Neon.u.sha256(tx);
    const msgHashHex = Buffer.from(msgHash, 'hex');
    this.signer = key.startSignSession(msgHashHex);
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
    const sig = this.signer.finalizeSignature(signature);

    const rawSignature = Buffer.concat([
      sig.r.toArrayLike(Buffer, 'be', 32),
      sig.s.toArrayLike(Buffer, 'be', 32)
    ]);

    const invocationScript = '40' + rawSignature.toString('hex');
    const verificationScript = Neon.wallet.getVerificationScriptFromPublicKey(this.publicKey);
    const witness = {invocationScript, verificationScript};

    this.signature = new Neon.tx.Transaction(this.tx);
    this.signature.scripts ? this.signature.scripts.push(witness) : this.signature.scripts = [witness];
  }

  toRaw() {
    return {
      tx: new Neon.tx.Transaction(this.signature),
      url: this.url
    };
  }

  verify() {
    assert(this.signature);
    return true;
  }
}

NeoTransaction.Mainnet = 'MainNet';
NeoTransaction.Testnet = 'TestNet';