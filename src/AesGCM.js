"use strict";

import crypto from "crypto";
import CryptoError from "./CryptoError.js";
import AES_CONSTANTS from "./AES_CONSTANTS.js";
import AesUtils from "./AesUtils.js";

const {
  AES_GCM_ALGORITHMS: ALGORITHMS,
  DEFAULT_AES_OPTIONS: DEFAULT_OPTIONS,
  KEY_LENGTH_MAP,
} = AES_CONSTANTS;

function encrypt(algorithm, params = {}, _options = {}) {
  const source = `${algorithm}::encrypt`;
  const { data = "" } = params;
  const options = { ...DEFAULT_OPTIONS, ..._options };
  const { cipherTextFormat, plainTextFormat, deriveKey } = options;

  validateEncryptOptions(source, params, options);

  try {
    const keyObj = getKey(algorithm, params, options);
    const ivObj = getEncryptIV(params, options);

    const { buffer: keyBuffer, saltObj } = keyObj;
    const { string: saltString } = saltObj || {};
    const { buffer: ivBuffer, string: ivString } = ivObj;

    const encryptor = crypto.createCipheriv(algorithm, keyBuffer, ivBuffer);

    const cipherTextBuffer = Buffer.concat([
      encryptor.update(data, plainTextFormat),
      encryptor.final(),
    ]);
    const cipherTextString = cipherTextBuffer.toString(cipherTextFormat);
    const cipherTextObj = {
      buffer: cipherTextBuffer,
      string: cipherTextString,
    };

    const authTagBuffer = encryptor.getAuthTag();
    const authTagString = authTagBuffer.toString(cipherTextFormat);
    const authTagObj = {
      buffer: authTagBuffer,
      string: authTagString,
    };

    const payloadFunc =
      (deriveKey && generateEncryptPayloadWithKDF) ||
      generateEncryptPayloadWithoutKDF;
    const payloadObj = payloadFunc(
      options,
      cipherTextObj,
      authTagObj,
      ivObj,
      saltObj
    );
    const { string: payloadString } = payloadObj;

    const encryptedData = {
      salt: saltString,
      iv: ivString,
      authTag: authTagString,
      cipherText: cipherTextString,
      payload: payloadString,
    };
    return encryptedData;
  } catch (e) {
    throw new CryptoError(e, source);
  }
}

function decrypt(algorithm, params = {}, _options = {}) {
  const source = `${algorithm}::decrypt`;
  const { iv = "", salt = "", authTag = "", cipherText = "" } = params;
  const options = { ...DEFAULT_OPTIONS, ..._options };
  const { ivFormat, saltFormat, cipherTextFormat, plainTextFormat, deriveKey } =
    options;

  validateDecryptOptions(source, params, options);

  try {
    const payloadPartsFunc =
      (deriveKey && getPayloadPartsWithKDF) || getPayloadPartsWithoutKDF;
    const payloadPartsObj = payloadPartsFunc(source, params, options);

    let { cipherTextBuffer, ivBuffer, saltBuffer, authTagBuffer } =
      payloadPartsObj;
    saltBuffer = saltBuffer || Buffer.from(salt, saltFormat);
    ivBuffer = ivBuffer || Buffer.from(iv, ivFormat);
    cipherTextBuffer =
      cipherTextBuffer || Buffer.from(cipherText, cipherTextFormat);
    authTagBuffer = authTagBuffer || Buffer.from(authTag, cipherTextFormat);

    const _params = { ...params, saltBuffer };
    const keyObj = getKey(algorithm, _params, options);
    const { buffer: keyBuffer } = keyObj;

    const decryptor = crypto.createDecipheriv(algorithm, keyBuffer, ivBuffer);
    decryptor.setAuthTag(authTagBuffer);

    const plainTextBuffer = Buffer.concat([
      decryptor.update(cipherTextBuffer),
      decryptor.final(),
    ]);
    const plainTextString = plainTextBuffer.toString(plainTextFormat);
    const decryptedData = { data: plainTextString };
    return decryptedData;
  } catch (e) {
    throw new CryptoError(e, source);
  }
}

function validateEncryptOptions(source, params, options) {
  const { key, data, masterKey } = params;
  const { deriveKey } = options;

  if (typeof data !== "string" || !data) {
    throw new CryptoError(
      null,
      source,
      "Provided 'data' must be a non-empty string"
    );
  }

  if (!deriveKey && (typeof key !== "string" || !key)) {
    throw new CryptoError(
      null,
      source,
      "Provided 'key' must be a non-empty string for non-derived keys"
    );
  }

  if (deriveKey && (typeof masterKey !== "string" || !masterKey)) {
    throw new CryptoError(
      null,
      source,
      "Provided 'masterKey' must be a non-empty string for derived keys"
    );
  }
}

function validateDecryptOptions(source, params, options) {
  const { key, payload, masterKey, cipherText, iv } = params;
  const { deriveKey } = options;

  if (
    (typeof payload !== "string" || !payload) &&
    (typeof cipherText !== "string" || !cipherText)
  ) {
    throw new CryptoError(
      null,
      source,
      "Provided 'payload' or 'cipherText' must be a non-empty string"
    );
  }

  if (!deriveKey && (typeof key !== "string" || !key)) {
    throw new CryptoError(
      null,
      source,
      "Provided 'key' must be a non-empty string for non-derived keys"
    );
  }

  if (deriveKey && (typeof masterKey !== "string" || !masterKey)) {
    throw new CryptoError(
      null,
      source,
      "Provided 'masterKey' must be a non-empty string for derived keys"
    );
  }

  if (
    typeof cipherText === "string" &&
    cipherText &&
    (typeof iv !== "string" || !iv)
  ) {
    throw new CryptoError(
      null,
      source,
      "Provided 'iv' must be a non-empty string"
    );
  }
}

function getEncryptIV(params, options) {
  const { iv } = params;
  const { ivFormat, ivLength } = options;

  const buffer =
    (iv && Buffer.from(iv, ivFormat)) || crypto.randomBytes(ivLength);
  const string = iv || buffer.toString(ivFormat);

  return { buffer, string };
}

function getSalt(params, options) {
  const { salt, saltBuffer } = params;
  const { saltFormat, saltLength } = options;

  const buffer =
    saltBuffer ||
    (salt && Buffer.from(salt, saltFormat)) ||
    crypto.randomBytes(saltLength);
  const string = salt || buffer.toString(saltFormat);

  return { buffer, string };
}

function getKey(algorithm, params, options) {
  const { key, masterKey } = params;
  const { deriveKey, keyFormat } = options;

  const saltObj = (deriveKey && getSalt(params, options)) || undefined;
  const { buffer: saltBuffer } = saltObj || {};

  const keyLength = KEY_LENGTH_MAP[algorithm];
  const buffer = deriveKey
    ? AesUtils.deriveKey(masterKey, saltBuffer, keyLength, options)
    : Buffer.from(key, keyFormat);

  return {
    buffer,
    string: (deriveKey && masterKey) || key,
    saltObj,
  };
}

function generateEncryptPayloadWithKDF(
  options,
  cipherTextObj,
  authTagObj,
  ivObj,
  saltObj
) {
  const { dataSeparator, cipherTextFormat } = options;
  const { buffer: cipherTextBuffer, string: cipherTextString } = cipherTextObj;
  const { buffer: authTagBuffer, string: authTagString } = authTagObj;
  const { buffer: ivBuffer, string: ivString } = ivObj;
  const { buffer: saltBuffer, string: saltString } = saltObj;

  const payloadBuffer = Buffer.concat([
    saltBuffer,
    ivBuffer,
    authTagBuffer,
    cipherTextBuffer,
  ]);
  const payloadString = dataSeparator
    ? [saltString, ivString, authTagString, cipherTextString].join(
        dataSeparator
      )
    : payloadBuffer.toString(cipherTextFormat);

  return {
    buffer: payloadBuffer,
    string: payloadString,
  };
}

function generateEncryptPayloadWithoutKDF(
  options,
  cipherTextObj,
  authTagObj,
  ivObj
) {
  const { dataSeparator, cipherTextFormat } = options;
  const { buffer: cipherTextBuffer, string: cipherTextString } = cipherTextObj;
  const { buffer: authTagBuffer, string: authTagString } = authTagObj;
  const { buffer: ivBuffer, string: ivString } = ivObj;

  const payloadBuffer = Buffer.concat([
    ivBuffer,
    authTagBuffer,
    cipherTextBuffer,
  ]);
  const payloadString = dataSeparator
    ? [ivString, authTagString, cipherTextString].join(dataSeparator)
    : payloadBuffer.toString(cipherTextFormat);

  return {
    buffer: payloadBuffer,
    string: payloadString,
  };
}

function getPayloadPartsWithKDF(source, params, options) {
  const { payload } = params;
  const {
    dataSeparator,
    saltFormat,
    ivFormat,
    cipherTextFormat,
    saltLength,
    ivLength,
    authTagLength,
  } = options;
  let saltBuffer;
  let ivBuffer;
  let authTagBuffer;
  let cipherTextBuffer;

  if (dataSeparator) {
    const [saltString, ivString, authTagString, cipherTextString] =
      payload.split(dataSeparator);

    if (!saltString || !ivString || !authTagString || !cipherTextString) {
      throw new CryptoError(null, source, "Invalid 'payload' for decrpytion");
    }

    saltBuffer = Buffer.from(saltString, saltFormat);
    ivBuffer = Buffer.from(ivString, ivFormat);
    authTagBuffer = Buffer.from(authTagString, cipherTextFormat);
    cipherTextBuffer = Buffer.from(cipherTextString, cipherTextFormat);
  } else {
    const payloadBuffer = Buffer.from(payload, cipherTextFormat);

    const saltBufferLimit = saltLength;
    const ivBufferLimit = saltLength + ivLength;
    const authTagBufferLimit = saltLength + ivLength + authTagLength;

    saltBuffer = payloadBuffer.slice(0, saltBufferLimit);
    ivBuffer = payloadBuffer.slice(saltBufferLimit, ivBufferLimit);
    authTagBuffer = payloadBuffer.slice(ivBufferLimit, authTagBufferLimit);
    cipherTextBuffer = payloadBuffer.slice(authTagBufferLimit);
  }

  return {
    saltBuffer,
    ivBuffer,
    authTagBuffer,
    cipherTextBuffer,
  };
}

function getPayloadPartsWithoutKDF(source, params, options) {
  const { payload } = params;
  const { dataSeparator, ivFormat, cipherTextFormat, ivLength, authTagLength } =
    options;
  let ivBuffer;
  let authTagBuffer;
  let cipherTextBuffer;

  if (dataSeparator) {
    const [ivString, authTagString, cipherTextString] =
      payload.split(dataSeparator);

    if (!ivString || !authTagString || !cipherTextString) {
      throw new CryptoError(null, source, "Invalid 'payload' for decrpytion");
    }

    ivBuffer = Buffer.from(ivString, ivFormat);
    authTagBuffer = Buffer.from(authTagString, cipherTextFormat);
    cipherTextBuffer = Buffer.from(cipherTextString, cipherTextFormat);
  } else {
    const payloadBuffer = Buffer.from(payload, cipherTextFormat);

    const ivBufferLimit = ivLength;
    const authTagBufferLimit = ivLength + authTagLength;

    ivBuffer = payloadBuffer.slice(0, ivBufferLimit);
    authTagBuffer = payloadBuffer.slice(ivBufferLimit, authTagBufferLimit);
    cipherTextBuffer = payloadBuffer.slice(authTagBufferLimit);
  }

  return {
    ivBuffer,
    authTagBuffer,
    cipherTextBuffer,
  };
}

const AesGCM = {
  ALGORITHMS,
  encrypt,
  decrypt,
};

export default AesGCM;
