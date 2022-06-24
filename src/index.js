import Aes from "./Aes.js";
import AesUtils from "./AesUtils.js";
import AES_CONSTANTS from "./AES_CONSTANTS.js";

const AES = { Aes, AesUtils, AES_CONSTANTS };
console.log("hey", AES);
let token =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjM2ZmNmOGEwLWRkODUtMTFlYy04ZDQ2LTNiODk2YTNlMjZiMiIsImlhdCI6MTY1MzYzMjQ3NzAwNn0.czhd-u0efk-3wHU8byYhpqko2RoSDbGKJsduT-KCnGc";
let key = AES.AesUtils.extractKeyFromToken(token);
console.log("key", key);
export default AES;
module.exports = AES;
