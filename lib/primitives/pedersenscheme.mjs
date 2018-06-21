'use strict';

import BN from 'bn.js';
import buffer from 'buffer';

const Buffer = buffer.Buffer;

import { randomBytes } from "../utils";

export class PedersenScheme {
  constructor() {
    this.ec = null;

    this.a = null;
    this.H = null;
  }

  generate(ec) {
    this.ec = ec;

    this.a = new BN(randomBytes(32).toString('hex'), 16);
    this.H = this.ec.g.mul(this.a);
    return this;
  }

  static generate(ec) {
    return new PedersenScheme().generate(ec);
  }

  getParams() {
    return {
      H: Buffer.from(this.H.encode(true)).toString('hex')
    };
  }

  commit(message) {
    const x = new BN(Buffer.from(message,'utf-8'), 16);
    const r = new BN(randomBytes(32).toString('hex'), 16);
    const X = this.ec.g.mul(x);
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

  static verify(ec, params, commitment, decommitment) {
    const H = ec.curve.decodePoint(Buffer.from(params.H,'hex'));
    const C = ec.curve.decodePoint(Buffer.from(commitment.C,'hex'));
    const x = new BN(Buffer.from(decommitment.message,'utf-8'), 16);
    const r = new BN(decommitment.r, 16);

    return C.eq(ec.g.mul(x).add(H.mul(r)));
  }
}
