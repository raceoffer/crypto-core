import get from 'lodash/get';
import invoke from 'lodash/invoke';
import isFunction from 'lodash/isFunction';
import isUndefined from 'lodash/isUndefined';
import isNull from 'lodash/isNull';

import BN from 'bn.js';

import JSBN from "jsbn";
const BigInteger = JSBN.BigInteger;

import buffer from 'buffer';
const Buffer = buffer.Buffer;

import { matchCurve } from './curves';

export function toJSON(value, hex) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  if (isFunction(get(value, 'toJSON'))) {
    return invoke(value, 'toJSON', hex);
  }
}

export function fromJSON(type, value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  if (isFunction(get(type, 'fromJSON'))) {
    return invoke(type, 'fromJSON', value, hex);
  }
}

export function toBytes(value, hex) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  if (isFunction(get(value, 'toBytes'))) {
    return invoke(value, 'toBytes', hex);
  }
}

export function fromBytes(type, value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  if (isFunction(get(type, 'fromBytes'))) {
    return invoke(type, 'fromBytes', value, hex);
  }
}

export function encodePoint(value, hex) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  const buffer = Buffer.from(value.encode(true));

  return hex ? buffer.toString('hex') : buffer;
}

export function decodePoint(crypto, value, hex) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  return crypto.curve.decodePoint(hex ? Buffer.from(value, 'hex') : value);
}

export function encodeBN(value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return hex ? value.toString(16) : value.toArrayLike(Buffer);
}

export function decodeBN(value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return hex ? new BN(value, 16) : new BN(value);
}

export function encodeBuffer(value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return value.toString('hex');
}

export function decodeBuffer(value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return new Buffer.from(value, 'hex');
}

export function encodeBigInteger(value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return hex ? value.toString(16) : encodeBN(toBN(value));
}

export function decodeBigInteger(value, hex) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return hex ? new BigInteger(value, 16) : toBigInteger(decodeBN(value));
}

export function toBN(value) {
  return new BN(value.toString(16), 16);
}

export function toBigInteger(value) {
  return new BigInteger(value.toString(16), 16);
}

export const Field = {};
Field[Field.Number = 0] = 'Number';
Field[Field.Boolean = 1] = 'Boolean';
Field[Field.String = 2] = 'String';
Field[Field.Buffer = 3] = 'Buffer';
Field[Field.BN = 4] = 'BN';
Field[Field.BigInteger = 5] = 'BigInteger';
Field[Field.Point = 6] = 'Point';
Field[Field.Custom = 7] = 'Custom';

export function generateMessage(name, abi, root) {
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

    for (let property in abi) {
      if (abi.hasOwnProperty(property)) {
        if (this.hasOwnProperty(property)) {
          const type = abi[property][0];
          const value = this[property];
          switch (type) {
            case Field.Number:
            case Field.String:
            case Field.Boolean:
              result[property] = value;
              break;
            case Field.Buffer:
              result[property] = hex ? encodeBuffer(value) : value;
              break;
            case Field.BN:
              result[property] = encodeBN(value, hex);
              break;
            case Field.BigInteger:
              result[property] = encodeBigInteger(value, hex);
              break;
            case Field.Point:
              result[property] = encodePoint(value, hex);
              break;
            case Field.Custom:
              result[property] = toJSON(value, hex);
              break;
          }
        }
      }
    }

    return result;
  };

  Class.prototype.fromJSON = function(json, hex) {
    this.curve = json.curve;
    this.crypto = matchCurve(this.curve);

    for (let property in abi) {
      if (abi.hasOwnProperty(property)) {
        if (json.hasOwnProperty(property)) {
          const type = abi[property][0];
          const subtype = abi[property][1];
          const value = json[property];
          switch (type) {
            case Field.Number:
            case Field.String:
            case Field.Boolean:
              this[property] = value;
              break;
            case Field.Buffer:
              this[property] = hex ? decodeBuffer(value) : value;
              break;
            case Field.BN:
              this[property] = decodeBN(value, hex);
              break;
            case Field.BigInteger:
              this[property] = decodeBigInteger(value, hex);
              break;
            case Field.Point:
              this[property] = decodePoint(this.crypto, value, hex);
              break;
            case Field.Custom:
              this[property] = fromJSON(subtype, value, hex);
              break;
          }
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
