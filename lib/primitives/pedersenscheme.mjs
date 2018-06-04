'use strict';

const ec = require('elliptic').ec('secp256k1');
const BN = require('bn.js');

export class PedersenScheme {
  constructor() {
    this.a = null;
    this.H = null;
  }

  generate() {
    this.a = ec.genKeyPair().getPrivate();
    this.H = ec.g.mul(this.a);
    return this;
  }

  static generate() {
    return new PedersenScheme().generate();
  }

  getParams() {
    return {
      H: Buffer.from(this.H.encode(true)).toString('hex')
    };
  }

  commit(message) {
    const x = new BN(Buffer.from(message,'utf-8'), 16);
    const r = ec.genKeyPair().getPrivate();
    const X = ec.g.mul(x);
    const R = this.H.mul(r);

    const C = R.add(X);

    return {
      commitment: {
        C: Buffer.from(C.encode(true)).toString('hex')
      },
      decommitment: {
        message: message,
        r: r.toString(16)
      }
    };
  }

  static verify(params, commitment, decommitment) {
    const H = ec.curve.decodePoint(Buffer.from(params.H,'hex'));
    const C = ec.curve.decodePoint(Buffer.from(commitment.C,'hex'));
    const x = new BN(Buffer.from(decommitment.message,'utf-8'), 16);
    const r = new BN(decommitment.r, 16);

    return C.eq(ec.g.mul(x).add(H.mul(r)));
  }
}
