'use strict';

import { Signer } from './signer';
import { SyncSession } from './syncsession';
import { KeyPair } from './keypair';
import { matchCurve } from '../../curves';

import {
  toJSON,
  fromJSON,
  encodePoint,
  decodePoint
} from "../../convert";

export class CompoundKey {
  constructor() {
    this.curve = null;
    this.eddsa = null;

    // Own key (private)
    this.localPrivateKey = null;

    // External key (public only)
    this.remotePublic = null;

    // Compound key (public only)
    this.compoundPublic = null;
  }

  fromOptions(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = KeyPair.fromOptions({
      curve: this.curve,
      secret: options.secret
    });

    return this;
  }

  static fromOptions(options) {
    return new CompoundKey().fromOptions(options);
  }

  toJSON() {
    return {
      curve: this.curve,
      localPrivateKey: toJSON(this.localPrivateKey),
      remotePublic: encodePoint(this.remotePublic),
      compoundPublic: encodePoint(this.compoundPublic)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = fromJSON(KeyPair, json.localPrivateKey);
    this.remotePublic = decodePoint(this.crypto, json.remotePublic);
    this.compoundPublic = decodePoint(this.crypto, json.compoundPublic);

    return this;
  }

  static fromJSON(json) {
    return new CompoundKey().fromJSON(json);
  }

  get localPrivate() {
    return this.localPrivateKey.private;
  }

  get localPublic() {
    return this.localPrivateKey.public;
  }

  startSyncSession() {
    return SyncSession.fromOptions({
      curve: this.curve,
      x: this.localPrivate
    })
  }

  importSyncData(syncData) {
    const point = syncData.Q;
    const compound = this.localPublic.add(point);

    this.remotePublic = point;
    this.compoundPublic = compound;
  }

  startSignSession(message) {
    return Signer.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      compoundPublic: this.compoundPublic,
      message: message
    });
  }
}
