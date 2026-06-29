// Hex utilities
export { hexToBytes, bytesToHex } from "./hex.js";
// AES-CMAC (RFC 4493)
export { computeAesCmac, _computeKs, _computeCm, _computeAesCmacForVerification } from "./aes-cmac.js";
// NTAG424 p= decryption
export { decryptP } from "./decrypt.js";
// NTAG424 c= CMAC verification
export { verifyCmac, buildVerificationData } from "./verify.js";
// Deterministic key derivation (K0-K4)
export { deriveKeysFromHex } from "./keys.js";
// High-level convenience
export { extractUIDAndCounter, validateCmac, decodeAndValidate } from "./helpers.js";
// Version scanning
export { cmacScanVersions } from "./scan.js";
