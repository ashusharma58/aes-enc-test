"use strict";

import autoBind from "auto-bind";
import ResponseBody from "./ResponseBody.js";

const ERROR_NAME = "CryptoError";
const ERROR_CLASSIFICATION = "CRYTOGRAPHIC_ERROR";
const STATUS_CODE = 500;
const CAN_CAPTURE = typeof Error.captureStackTrace === "function";
const CAN_STACK = !!new Error().stack;

export default class CryptoError extends Error {
  constructor(error, source, message) {
    const {
      _isCryptoError,
      message: _message,
      msg,
      name,
      source: errSource,
      statusCode,
      error: err,
      stack,
    } = error || {};
    const _msg = msg || _message || message;

    super(_msg);

    this._isCryptoError = true;
    this.name = name || ERROR_NAME;
    this.classification = ERROR_CLASSIFICATION;
    this.source = (_isCryptoError && errSource) || source;

    this.message = _msg;
    this.msg = _msg;

    this.statusCode = (_isCryptoError && statusCode) || STATUS_CODE;

    this.error = (!_isCryptoError && error) || err || undefined;
    const thisErrorHasKeys = !!Object.keys(this.error || {}).length;
    if (!thisErrorHasKeys) {
      this.error = undefined;
    }

    this.stack =
      stack ||
      (CAN_CAPTURE && Error.captureStackTrace(this, CryptoError)) ||
      (CAN_STACK && new Error().stack) ||
      undefined;

    autoBind(this);
  }

  getResponseBody() {
    const { statusCode, message } = this;
    const error = this.toJSON();

    const { NODE_ENV } = process.env;
    error.stack = (NODE_ENV === "production" && undefined) || error.stack;

    return new ResponseBody(statusCode, message, undefined, error);
  }

  toJSON() {
    const { toJSON, ...rest } = this;
    return JSON.parse(JSON.stringify(rest));
  }
}
