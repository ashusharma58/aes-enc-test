"use strict";

import crypto from "crypto";

const AES_CBC_ALGORITHMS = ["aes-128-cbc", "aes-256-cbc"];
const AES_GCM_ALGORITHMS = ["aes-128-gcm", "aes-256-gcm"];

const KEY_LENGTH_MAP = {
  "aes-128-cbc": 16,
  "aes-256-cbc": 32,
  "aes-128-gcm": 16,
  "aes-256-gcm": 32,
};

const KDF = {
  PBKDF2: "PBKDF2",
};

const KDF_MAP = {
  [KDF.PBKDF2]: crypto.pbkdf2Sync,
};

const DEFAULT_AES_OPTIONS = {
  keyFormat: "hex",
  ivFormat: "hex",
  saltFormat: "hex",
  cipherTextFormat: "hex",
  plainTextFormat: "utf8",
  dataSeparator: ".",

  deriveKey: false,
  appendSalt: false,
  kdf: KDF.PBKDF2,
  saltLength: 20,
  ivLength: 16,
  kdfIterations: 50,
  kdfDigest: "sha1",
  authTagLength: 16,
};

const AES_CONSTANTS = {
  AES_CBC_ALGORITHMS,
  AES_GCM_ALGORITHMS,
  KEY_LENGTH_MAP,
  KDF,
  KDF_MAP,
  DEFAULT_AES_OPTIONS,
};

export default AES_CONSTANTS;
