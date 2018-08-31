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