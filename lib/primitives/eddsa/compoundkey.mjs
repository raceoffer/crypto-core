'use strict';

import { Signer } from './signer';
import { SyncSession, SyncData } from './syncsession';
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
    this.remotePublicPoint = null;

    // Compound key (public only)
    this.compoundPublicPoint = null;
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
      remotePublicPoint: encodePoint(this.remotePublicPoint),
      compoundPublicPoint: encodePoint(this.compoundPublicPoint)
    };
  }

  fromJSON(json) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    this.localPrivateKey = fromJSON(KeyPair, json.localPrivateKey);
    this.remotePublicPoint = decodePoint(this.crypto, json.remotePublicPoint);
    this.compoundPublicPoint = decodePoint(this.crypto, json.compoundPublicPoint);

    return this;
  }

  static fromJSON(json) {
    return new CompoundKey().fromJSON(json);
  }

  localPrivate() {
    return this.localPrivateKey.private;
  }

  localPublic() {
    return this.localPrivateKey.public;
  }

  remotePublic() {
    return this.remotePublicPoint;
  }

  compoundPublic() {
    return this.compoundPublicPoint;
  }

  startSyncSession() {
    return SyncSession.fromOptions({
      curve: this.curve,
      x: this.localPrivate()
    });
  }

  extractSyncData() {
    assert(this.compoundPublicPoint);

    return SyncData.fromOptions({
      curve: this.curve,
      Q: this.remotePublic()
    });
  }

  importSyncData(syncData) {
    const point = syncData.Q;
    const compound = this.localPublic().add(point);

    this.remotePublicPoint = point;
    this.compoundPublicPoint = compound;
  }

  startSignSession(message) {
    return Signer.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      compoundPublic: this.compoundPublic(),
      message: message
    });
  }
}
