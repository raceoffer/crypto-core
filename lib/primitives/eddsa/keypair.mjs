import buffer from 'buffer';
import elliptic from 'elliptic';
import digest from 'js-sha3';
import { matchCurve } from "../../curves";

const Buffer = buffer.Buffer;
const utils = elliptic.utils;

export class KeyPair {
  constructor() {
    this.curve = null;
    this.crypto = null;
    this.secret = null;
  }

  static reverseBuffer(buffer) {
    const result = new Buffer(buffer.length);
    for (let i = 0, j = buffer.length - 1; i <= j; ++i, --j) {
      result[i] = buffer[j];
      result[j] = buffer[i];
    }
    return result;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);
    this.secret = KeyPair.reverseBuffer(options.secret);

    return this;
  }

  static fromOptions(options) {
    return new KeyPair().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      secret: this.secret.toString('hex')
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);
    this.secret = Buffer.from(json.secret, 'hex');

    return this;
  }

  static fromJSON(json) {
    return new KeyPair().fromJSON(json);
  }

  static hash(... args) {
    return Buffer.from(args.reduce((hash, current) => {
      return hash ? hash.update(current) : digest.keccak512.update(current);
    }, null).array());
  }

  get keyHash() {
    const privHash = Buffer.from(digest.keccak512.array(this.secret));

    privHash[0] &= 248;
    privHash[31] &= 127;
    privHash[31] |= 64;

    return privHash;
  }

  get messagePrefix() {
    return this.keyHash.slice(32);
  }

  get privateBytes() {
    return this.keyHash.slice(0, 32);
  }

  get private() {
    return utils.intFromLE(this.privateBytes);
  }

  get publicBytes() {
    return Buffer.from(this.crypto.encodePoint(this.public));
  }

  get public() {
    return this.crypto.g.mul(this.private)
  }

  sign(message) {
    const rb = KeyPair.hash(this.messagePrefix, message);

    const r = utils.intFromLE(rb).umod(this.crypto.curve.n);

    const R = this.crypto.g.mul(r);

    const Rencoded = this.crypto.encodePoint(R);

    const sb = KeyPair.hash(Rencoded, this.publicBytes, message);

    const s = utils.intFromLE(sb).mul(this.private);
    const S = r.add(s).umod(this.crypto.curve.n);
    return this.crypto.makeSignature({ R: R, S: S, Rencoded: Rencoded });
  }
}