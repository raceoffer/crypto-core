'use strict';

const { EddsaKeyPair } = require('./keypair');

const { Field, generateMessage } = require('../../convert');

const {
  DistributedEddsaSyncSession,
  DistributedEddsaSyncSessionShard
} = require('./distributedsyncsession');

const {
  DistributedEddsaSignSession,
  DistributedEddsaSignSessionShard
} = require('./distributedsignsession');

const { Root } = require('protobufjs');
const proto = require('./distributedkey.json');

const root = Root.fromJSON(proto);

class DistributedEddsaKey extends generateMessage(
  'DistributedEddsaKey', {
    localPrivateKey: [Field.Custom, EddsaKeyPair],
    remotePublicPoint: [Field.Point],
    compoundPublicPoint: [Field.Point]
  },
  root
) {
  fromOptions(options) {
    super.fromOptions(options);

    this.localPrivateKey = EddsaKeyPair.fromOptions({
      curve: this.curve,
      secret: options.secret
    });

    return this;
  }

  static fromOptions(options) {
    return new DistributedEddsaKey().fromOptions(options);
  }

  static fromJSON(json, hex) {
    return new DistributedEddsaKey().fromJSON(json, hex);
  }

  static fromBytes(bytes) {
    return new DistributedEddsaKey().fromBytes(bytes);
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
    return DistributedEddsaSyncSession.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey
    });
  }

  startSyncSessionShard() {
    return DistributedEddsaSyncSessionShard.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey
    });
  }

  importSyncData(syncData) {
    const point = syncData.publicPoint;
    const compound = this.localPublic().add(point);

    this.remotePublicPoint = point;
    this.compoundPublicPoint = compound;
  }

  startSignSession(message) {
    return DistributedEddsaSignSession.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      compoundPublicPoint: this.compoundPublic(),
      message: message
    });
  }

  startSignSessionShard(message) {
    return DistributedEddsaSignSessionShard.fromOptions({
      curve: this.curve,
      localPrivateKey: this.localPrivateKey,
      compoundPublicPoint: this.compoundPublic(),
      message: message
    });
  }
}

module.exports = {
  DistributedEddsaKey
};
