"use strict";

import crypto from "crypto";
import randomstring from "randomstring";
import AES_CONSTANTS from "./AES_CONSTANTS.js";
import CryptoError from "./CryptoError.js";

const SOURCE = "Aes-Utils";

function generateKey(length = 16) {
  return randomstring.generate(length);
}

function deriveKey(masterKey, saltBuffer, keyLength, options) {
  const { KDF } = AES_CONSTANTS;
  const { kdf, kdfIterations, kdfDigest } = options;
  let derivedKeyBuffer;

  switch (kdf) {
    case KDF.PBKDF2:
      derivedKeyBuffer = crypto.pbkdf2Sync(
        masterKey,
        saltBuffer,
        kdfIterations,
        keyLength,
        kdfDigest
      );
      break;

    default:
      throw new CryptoError(
        null,
        SOURCE,
        `Cannot Derive Key with KDF '${kdf}'`
      );
  }

  return derivedKeyBuffer;
}

function extractKeyFromToken(token = "", keyLength = 32) {
  // const [,, checksum] = token.split('.')
  // const checksumLength = checksum.length
  // const eKey1 = checksum.substring(0, 16)
  // const eKey2 = checksum.substring(checksumLength-16)
  // const encryptionKey = [eKey1, eKey2].join('')
  // return encryptionKey

  const { DEFAULT_AES_OPTIONS } = AES_CONSTANTS;
  const { kdfIterations, kdfDigest, keyFormat } = DEFAULT_AES_OPTIONS;
  const [header, , checksum] = token.split(".");
  const saltBuffer = Buffer.from(header);
  const derivedKeyBuffer = crypto.pbkdf2Sync(
    checksum,
    saltBuffer,
    kdfIterations,
    keyLength,
    kdfDigest
  );
  const derivedKey = derivedKeyBuffer.toString(keyFormat);
  return derivedKey;
}
const AesUtils = {
  generateKey,
  deriveKey,
  extractKeyFromToken,
};

export default AesUtils;
