import jspaillier from 'jspaillier';
import {
  toJSON,
  fromJSON,
  encodeBigInteger,
  decodeBigInteger
} from "../../convert";

import { Root } from 'protobufjs';
import * as proto from './paillierkeys.json';

const root = Root.fromJSON(proto);

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
  };
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

  toJSON(hex) {
    return {
      lambda: encodeBigInteger(this.secretKey.lambda, hex),
      pubkey: toJSON(PaillierPublicKey.fromOptions({ publicKey: this.secretKey.pubkey }), hex),
      x: encodeBigInteger(this.secretKey.x, hex)
    };
  }

  fromJSON(json, hex) {
    this.secretKey = new PaillierSecretKeyProxy(
      decodeBigInteger(json.lambda, hex),
      fromJSON(PaillierPublicKey, json.pubkey, hex).publicKey,
      decodeBigInteger(json.x, hex)
    );

    return this;
  }

  static fromJSON(json, hex) {
    return new PaillierSecretKey().fromJSON(json, hex);
  }

  toBytes() {
    const type = root.lookupType('PaillierSecretKey');
    return new Buffer(type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const type = root.lookupType('PaillierSecretKey');
    return this.fromJSON(type.decode(bytes));
  }

  static fromBytes(bytes) {
    return new PaillierSecretKey().fromBytes(bytes);
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

  toJSON(hex) {
    return {
      bits: this.publicKey.bits,
      n: encodeBigInteger(this.publicKey.n, hex),
      n2: encodeBigInteger(this.publicKey.n2, hex),
      np1: encodeBigInteger(this.publicKey.np1, hex),
      rncache: this.publicKey.rncache.map((x) => encodeBigInteger(x, hex))
    };
  }

  fromJSON(json, hex) {
    this.publicKey = new PaillierPublicKeyProxy(
      json.bits,
      decodeBigInteger(json.n, hex),
      decodeBigInteger(json.n2, hex),
      decodeBigInteger(json.np1, hex),
      json.rncache.map(decodeBigInteger, hex)
    );

    return this;
  }

  static fromJSON(json, hex) {
    return new PaillierPublicKey().fromJSON(json, hex);
  }

  toBytes() {
    const type = root.lookupType('PaillierPublicKey');
    return new Buffer(type.encode(this.toJSON()).finish());
  }

  fromBytes(bytes) {
    const type = root.lookupType('PaillierPublicKey');
    return this.fromJSON(type.decode(bytes));
  }

  static fromBytes(bytes) {
    return new PaillierPublicKey().fromBytes(bytes);
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