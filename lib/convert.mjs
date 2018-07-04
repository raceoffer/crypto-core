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

export function toJSON(value) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  if (isFunction(get(value, 'toJSON'))) {
    return invoke(value, 'toJSON');
  }
}

export function fromJSON(type, value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  if (isFunction(get(type, 'fromJSON'))) {
    return invoke(type, 'fromJSON', value);
  }
}

export function encodePoint(value) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  return Buffer.from(value.encode(true)).toString('hex')
}

export function decodePoint(crypto, value) {
  if (isUndefined(value) || isNull(value)) {
      return value;
  }

  return crypto.curve.decodePoint(Buffer.from(value, 'hex'));
}

export function encodeBN(value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return value.toString(16);
}

export function decodeBN(value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return new BN(value, 16);
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

export function encodeBigInteger(value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return value.toString(16);
}

export function decodeBigInteger(value) {
  if (isUndefined(value) || isNull(value)) {
    return value;
  }

  return new BigInteger(value, 16);
}

export function toBN(value) {
  return new BN(value.toString(16), 16);
}

export function toBigInteger(value) {
  return new BigInteger(value.toString(16), 16);
}