const { Buffer } = require('buffer');
const { utils } = require('elliptic');
const digest = require('js-sha3');

const { Field, generateMessage } = require('../../convert');

const { Root } = require('protobufjs');
const proto = require('./keypair.json');

const root = Root.fromJSON(proto);

class EddsaKeyPair extends generateMessage(
  'EddsaKeyPair', {
    secret: [Field.Buffer]
  },
  root
) {
  static reverseBuffer(buffer) {
    const result = new Buffer(buffer.length);
    for (let i = 0, j = buffer.length - 1; i <= j; ++i, --j) {
      result[i] = buffer[j];
      result[j] = buffer[i];
    }
    return result;
  }

  fromOptions(options) {
    super.fromOptions(options);

    this.secret = EddsaKeyPair.reverseBuffer(options.secret);

    return this;
  }

  static fromOptions(options) {
    return new EddsaKeyPair().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new EddsaKeyPair().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new EddsaKeyPair().fromBytes(bytes);
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
    return this.crypto.g.mul(this.private);
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

module.exports = {
  EddsaKeyPair
};
