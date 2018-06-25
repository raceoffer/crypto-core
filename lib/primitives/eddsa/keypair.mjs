import buffer from 'buffer';
import elliptic from 'elliptic';
import digest from 'js-sha3';

const Buffer = buffer.Buffer;
const utils = elliptic.utils;

export class KeyPair {
    constructor() {
        this._secret = null;
        this._eddsa = null;
    }

    fromSecret(secret, curve = 'ed25519') {
        this._secret = secret;
        this._eddsa = elliptic.eddsa(curve);

        return this;
    }

    static fromSecret(secret, curve = 'ed25519') {
        return new KeyPair().fromSecret(secret, curve);
    }

    static reverseBuffer(buffer) {
        const result = new Buffer(buffer.length);
        for (let i = 0, j = buffer.length - 1; i <= j; ++i, --j) {
            result[i] = buffer[j];
            result[j] = buffer[i];
        }
        return result;
    }

    fromHex(hex, curve = 'ed25519') {
        return this.fromSecret(KeyPair.reverseBuffer(Buffer.from(hex, 'hex')), curve);
    }

    static fromHex(hex, curve = 'ed25519') {
        return new KeyPair().fromHex(hex, curve);
    }

    toHex() {
        return KeyPair.reverseBuffer(this._secret).toString('hex');
    }

    static hash(... args) {
        return Buffer.from(args.reduce((hash, current) => {
            return hash ? hash.update(current) : digest.keccak512.update(current);
        }, null).array());
    }

    get secret() {
        return this._secret;
    }

    get keyHash() {
        const privHash = Buffer.from(digest.keccak512.array(this._secret));

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
        return this._eddsa.encodePoint(this.public);
    }

    get public() {
        return this._eddsa.g.mul(this.private)
    }

    sign(message) {
        const rb = KeyPair.hash(this.messagePrefix, message);

        const r = utils.intFromLE(rb).umod(this._eddsa.curve.n);

        const R = this._eddsa.g.mul(r);

        const Rencoded = this._eddsa.encodePoint(R);

        const sb = KeyPair.hash(Rencoded, this.publicBytes, message);

        const s_ = utils.intFromLE(sb).mul(this.private);
        const S = r.add(s_).umod(this._eddsa.curve.n);
        return this._eddsa.makeSignature({ R: R, S: S, Rencoded: Rencoded });
    }
}