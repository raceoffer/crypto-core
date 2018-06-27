import jspaillier from 'jspaillier';
import {
  toJSON,
  fromJSON,
  encodeBigInteger,
  decodeBigInteger
} from "../../convert";

function PaillierSecretKeyProxy(lambda, pubkey, x) {
  this.lambda = lambda;
  this.pubkey = pubkey;
  this.x = x;
}

PaillierSecretKeyProxy.prototype = jspaillier.privateKey.prototype;
PaillierSecretKeyProxy.prototype.constructor = PaillierSecretKeyProxy;

function PaillierPublicKeyProxy(bits, n, n2, np1, rncache) {
  this.bits = bits;
  this.n = n;
  this.n2 = n2;
  this.np1 = np1;
  this.rncache = rncache;
}

PaillierPublicKeyProxy.prototype = jspaillier.publicKey.prototype;
PaillierPublicKeyProxy.prototype.constructor = PaillierPublicKeyProxy;

export function generateKeys() {
  const paillierKeys = jspaillier.generateKeys(1024);
  return {
    publicKey: PaillierPublicKey.fromOptions({
      publicKey: paillierKeys.pub
    }),
    secretKey: PaillierSecretKey.fromOptions({
      secretKey: paillierKeys.sec
    }),
  }
}

export class PaillierSecretKey {
  constructor() {
    this.secretKey = null;
  }

  fromOptions(options) {
    this.secretKey = options.secretKey;
    return this;
  }

  static fromOptions(options) {
    return new PaillierSecretKey().fromOptions(options);
  }

  toJSON() {
    return {
      lambda: encodeBigInteger(this.secretKey.lambda),
      pubkey: toJSON(PaillierPublicKey.fromOptions({ publicKey: this.secretKey.pubkey })),
      x: encodeBigInteger(this.secretKey.x)
    }
  }

  fromJSON(json) {
    this.secretKey = new PaillierSecretKeyProxy(
      decodeBigInteger(json.lambda),
      fromJSON(PaillierPublicKey, json.pubkey).publicKey,
      decodeBigInteger(json.x)
    );

    return this;
  }

  static fromJSON(json) {
    return new PaillierSecretKey().fromJSON(json);
  }

  decrypt(x) {
    return this.secretKey.decrypt(x);
  }
}

export class PaillierPublicKey {
  constructor() {
    this.publicKey = null;
  }
  
  fromOptions(options) {
    this.publicKey = options.publicKey;
    return this;
  }
  
  static fromOptions(options) {
    return new PaillierPublicKey().fromOptions(options);
  }

  toJSON() {
    return {
      bits: this.publicKey.bits,
      n: encodeBigInteger(this.publicKey.n),
      n2: encodeBigInteger(this.publicKey.n2),
      np1: encodeBigInteger(this.publicKey.np1),
      rncache: this.publicKey.rncache.map(encodeBigInteger)
    }
  }

  fromJSON(json) {
    this.publicKey = new PaillierPublicKeyProxy(
      json.bits,
      decodeBigInteger(json.n),
      decodeBigInteger(json.n2),
      decodeBigInteger(json.np1),
      json.rncache.map(decodeBigInteger)
    );

    return this;
  }

  static fromJSON(json) {
    return new PaillierPublicKey().fromJSON(json);
  }

  add(a, b) {
    return this.publicKey.add(a, b);
  }

  mult(a, b) {
    return this.publicKey.mult(a, b);
  }

  encrypt(x) {
    return this.publicKey.encrypt(x);
  }
}