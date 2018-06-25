'use strict';

import assert from 'assert';

import elliptic from 'elliptic';

import { Signer } from "./signer";
import { SyncSession } from "./syncsession";
import { KeyPair } from "./keypair";

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

  static keyFromSecret(secret, curve = 'ed25519') {
    return KeyPair.fromSecret(secret, curve);
  }

  static fromSecret(secret, curve = 'ed25519') {
    return CompoundKey.fromOptions({
      localPrivateKey: CompoundKey.keyFromSecret(secret, curve),
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
    return this.localPrivateKey.private;
  }

  get localPublic() {
    return this.localPrivateKey.public;
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

    this.remotePublic = point;
    this.compoundPublic = compound;
  }

  startSignSession(message) {
    return Signer.fromOptions({
      message: message,
      compoundKey: this
    });
  }
}
