'use strict';

import assert from 'assert';

import elliptic from 'elliptic';

import { Signer } from "./signer";
import { SyncSession } from "./syncsession";

export class CompoundKey {
  constructor() {
    this.curve = null;
    this.eddsa = null;

    // Own key (private)
    this.localPrivateKey = null;

    // External key (public only)
    this.remotePublicKey = null;

    // Compound key (public only)
    this.compoundPublicKey = null;
  }

  static keyFromSecret(secret, curve = 'ed25519') {
    return elliptic.eddsa(curve).keyFromSecret(secret);
  }

  static fromSecret(secret, curve = 'ed25519') {
    return CompoundKey.fromOptions({
      localPrivateKey: CompoundKey.keyFromSecret(secret),
      curve: curve
    });
  }

  fromOptions(options) {
    assert(options.localPrivateKey, 'A private key is required');

    this.curve = options.curve || 'ed25519';
    this.eddsa = elliptic.eddsa(this.curve);
    this.localPrivateKey = options.localPrivateKey;

    return this;
  }

  static fromOptions(options) {
    return new CompoundKey().fromOptions(options);
  }

  get localPrivate() {
    return this.localPrivateKey.priv();
  }

  get localPublic() {
    return this.localPrivateKey.pub();
  }

  get compoundPublic() {
    if (!this.remotePublicKey){
      return null;
    }
    return this.compoundPublicKey.pub();
  }

  startSyncSession() {
    return SyncSession.fromOptions({
      curve: this.eddsa,
      x: this.localPrivate
    })
  }

  importSyncData(syncData) {
    const point = syncData.Q;
    const compound = this.localPublic.add(point);

    this.remotePublicKey = this.eddsa.keyFromPublic(point);
    this.compoundPublicKey = this.eddsa.keyFromPublic(compound);
  }

  startSignSession(message) {
    return Signer.fromOptions({
      message: message,
      compoundKey: this
    });
  }
}
