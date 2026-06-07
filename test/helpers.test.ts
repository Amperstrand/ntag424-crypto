import { describe, it, expect } from "vitest";
import { extractUIDAndCounter, validateCmac, decodeAndValidate, hexToBytes, deriveKeysFromHex } from "../src/index.js";
import { virtualTap, TEST_UID, TEST_ISSUER_KEY } from "./helpers.js";

describe("extractUIDAndCounter", () => {
  const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
  const k1Keys = [hexToBytes(keys.k1)];

  it("extracts UID and counter from a valid tap", () => {
    const counter = 42;
    const { pHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const result = extractUIDAndCounter(pHex, k1Keys);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.uidHex).toBe(TEST_UID);
      // Counter 42 → ctr bytes [0, 0, 42] → hex "00002a"
      expect(result.ctr).toBe("00002a");
    }
  });

  it("returns failure for wrong K1 key", () => {
    const { pHex } = virtualTap(TEST_UID, 1, keys.k1, keys.k2);
    const wrongKey = [hexToBytes("00000000000000000000000000000002")];
    const result = extractUIDAndCounter(pHex, wrongKey);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBeDefined();
    }
  });
});

describe("validateCmac", () => {
  const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
  const counter = 7;

  it("validates a correct CMAC", () => {
    const { cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([(counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff]);
    const result = validateCmac(uid, ctr, cHex, hexToBytes(keys.k2));
    expect(result.cmac_validated).toBe(true);
    expect(result.cmac_error).toBeNull();
  });

  it("returns false for null cHex", () => {
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([0, 0, 1]);
    const result = validateCmac(uid, ctr, null, hexToBytes(keys.k2));
    expect(result.cmac_validated).toBe(false);
  });

  it("returns false for undefined k2Bytes", () => {
    const { cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([0, 0, counter]);
    const result = validateCmac(uid, ctr, cHex, undefined);
    expect(result.cmac_validated).toBe(false);
    expect(result.cmac_error).toBe("K2 key not available");
  });
});

describe("decodeAndValidate", () => {
  const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
  const k1Keys = [hexToBytes(keys.k1)];
  const k2Bytes = hexToBytes(keys.k2);

  it("full pipeline: decrypt + verify with valid tap", () => {
    const counter = 3;
    const { pHex, cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const result = decodeAndValidate(pHex, cHex, k1Keys, k2Bytes);
    expect(result.success).toBe(true);
    expect(result.uidHex).toBe(TEST_UID);
    expect(result.cmac_validated).toBe(true);
    expect(result.cmac_error).toBeNull();
  });

  it("fails decryption with wrong K1", () => {
    const { pHex, cHex } = virtualTap(TEST_UID, 1, keys.k1, keys.k2);
    const wrongK1 = [hexToBytes("00000000000000000000000000000002")];
    const result = decodeAndValidate(pHex, cHex, wrongK1, k2Bytes);
    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });

  it("decrypts but CMAC fails with wrong K2", () => {
    const { pHex, cHex } = virtualTap(TEST_UID, 1, keys.k1, keys.k2);
    const wrongK2 = hexToBytes("00000000000000000000000000000002");
    const result = decodeAndValidate(pHex, cHex, k1Keys, wrongK2);
    expect(result.success).toBe(true);
    expect(result.uidHex).toBe(TEST_UID);
    expect(result.cmac_validated).toBe(false);
  });
});
