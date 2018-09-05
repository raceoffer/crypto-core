const get = require('lodash/get');
const invoke = require('lodash/invoke');
const isFunction = require('lodash/isFunction');
const isUndefined = require('lodash/isUndefined');
const isNull = require('lodash/isNull');

const BN = require('bn.js');
const BigInteger = require('jsbn').BigInteger;
const Buffer = require('buffer').Buffer;

const matchCurve = require('./curves').matchCurve;

function toJSON(value, hex) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  if (isFunction(get(value, 'toJSON'))) {
    return invoke(value, 'toJSON', hex);
  }
}

function fromJSON(type, value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  if (isFunction(get(type, 'fromJSON'))) {
    return invoke(type, 'fromJSON', value, hex);
  }
}

function toBytes(value, hex) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  if (isFunction(get(value, 'toBytes'))) {
    return invoke(value, 'toBytes', hex);
  }
}

function fromBytes(type, value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  if (isFunction(get(type, 'fromBytes'))) {
    return invoke(type, 'fromBytes', value, hex);
  }
}

function encodePoint(value, hex) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  const buffer = Buffer.from(value.encode(true));

  return hex ? buffer.toString('hex') : buffer;
}

function decodePoint(crypto, value, hex) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  return crypto.curve.decodePoint(hex ? Buffer.from(value, 'hex') : value);
}

function encodeBN(value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return hex ? value.toString(16) : value.toArrayLike(Buffer);
}

function decodeBN(value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return hex ? new BN(value, 16) : new BN(value);
}

function encodeBuffer(value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return value.toString('hex');
}

function decodeBuffer(value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return new Buffer.from(value, 'hex');
}

function encodeBigInteger(value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return hex ? value.toString(16) : encodeBN(toBN(value));
}

function decodeBigInteger(value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return hex ? new BigInteger(value, 16) : toBigInteger(decodeBN(value));
}

function toBN(value) {
  return new BN(value.toString(16), 16);
}

function toBigInteger(value) {
  return new BigInteger(value.toString(16), 16);
}

const Field = {};
Field[Field.Number = 0] = 'Number';
Field[Field.Boolean = 1] = 'Boolean';
Field[Field.String = 2] = 'String';
Field[Field.Buffer = 3] = 'Buffer';
Field[Field.BN = 4] = 'BN';
Field[Field.BigInteger = 5] = 'BigInteger';
Field[Field.Point = 6] = 'Point';
Field[Field.Custom = 7] = 'Custom';
Field[Field.Array = 8] = 'Array';

function generateMessage(name, abi, root) {
  const Class = new Function(
    'return function ' + name + '() {}'
  )();

  Class.prototype.fromOptions = function(options) {
    this.curve = options.curve;
    this.crypto = matchCurve(this.curve);

    for (let property in abi) {
      if (abi.hasOwnProperty(property)) {
        if (options.hasOwnProperty(property)) {
          this[property] = options[property];
        }
      }
    }

    return this;
  };

  Class.prototype.toJSON = function(hex) {
    const result = {};

    result.curve = this.curve;

    const dispatch = (typeinfo, value) => {
      switch (typeinfo[0]) {
        case Field.Number:
        case Field.String:
        case Field.Boolean:
          return value;
        case Field.Buffer:
          return hex ? encodeBuffer(value) : value;
        case Field.BN:
          return encodeBN(value, hex);
        case Field.BigInteger:
          return encodeBigInteger(value, hex);
        case Field.Point:
          return encodePoint(value, hex);
        case Field.Custom:
          return toJSON(value, hex);
        case Field.Array:
          return value.map(v => dispatch(typeinfo.slice(1), v));
      }
    };

    for (let property in abi) {
      if (abi.hasOwnProperty(property)) {
        if (this.hasOwnProperty(property)) {
          const typeinfo = abi[property];
          const value = this[property];
          result[property] = dispatch(typeinfo, value);
        }
      }
    }

    return result;
  };

  Class.prototype.fromJSON = function(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    const dispatch = (typeinfo, value) => {
      switch (typeinfo[0]) {
        case Field.Number:
        case Field.String:
        case Field.Boolean:
          return value;
        case Field.Buffer:
          return hex ? decodeBuffer(value) : value;
        case Field.BN:
          return decodeBN(value, hex);
        case Field.BigInteger:
          return decodeBigInteger(value, hex);
        case Field.Point:
          return decodePoint(this.crypto, value, hex);
        case Field.Custom:
          return fromJSON(typeinfo[1], value, hex);
        case Field.Array:
          return value.map(v => dispatch(typeinfo.slice(1), v));
      }
    };

    for (let property in abi) {
      if (abi.hasOwnProperty(property)) {
        if (json.hasOwnProperty(property)) {
          const typeinfo = abi[property];
          const value = json[property];
          this[property] = dispatch(typeinfo, value);
        }
      }
    }

    return this;
  };

  Class.prototype.toBytes = function() {
    const type = root.lookupType(name);
    return new Buffer(type.encode(this.toJSON()).finish());
  };

  Class.prototype.fromBytes = function(bytes) {
    const type = root.lookupType(name);
    return this.fromJSON(type.decode(bytes));
  };

  Class.fromOptions = function(options) {
    return new Class().fromOptions(options);
  };
  
  Class.fromJSON = function(json, hex) {
    return new Class().fromJSON(json, hex);
  };

  Class.fromBytes = function(bytes) {
    return new Class().fromBytes(bytes);
  };

  return Class;
};

module.exports = {
  toJSON,
  fromJSON,
  toBytes,
  fromBytes,
  encodeBuffer,
  decodeBuffer,
  encodePoint,
  decodePoint,
  encodeBN,
  decodeBN,
  encodeBigInteger,
  decodeBigInteger,
  toBN,
  toBigInteger,
  Field,
  generateMessage
};
