"use strict";

import { ALGORITHMS } from "./AES_MAP.js";
import CryptoError from "./CryptoError.js";

function encrypt(algorithom, params, options) {
  try {
    if (typeof algorithom !== "string" || !algorithom) {
      throw new TypeError('Provided "algorithom" must be a non-empty string');
    }

    const crypto = ALGORITHMS[algorithom];
    if (!crypto) {
      throw new TypeError(`Unprocessable AES Algorithm: ${algorithom}`);
    }
    return crypto.encrypt(algorithom, params, options);
  } catch (e) {
    throw new CryptoError(e);
  }
}

function decrypt(algorithom, params, options) {
  try {
    if (typeof algorithom !== "string" || !algorithom) {
      throw new TypeError('Provided "algorithom" must be a non-empty string');
    }

    const crypto = ALGORITHMS[algorithom];
    if (!crypto) {
      throw new TypeError(`Unprocessable AES Algorithm: ${algorithom}`);
    }
    return crypto.decrypt(algorithom, params, options);
  } catch (e) {
    throw new CryptoError(e);
  }
}

const Aes = {
  encrypt,
  decrypt,
};

export default Aes;
