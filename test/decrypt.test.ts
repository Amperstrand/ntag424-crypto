import { describe, it, expect } from "vitest";
import { decryptP, hexToBytes, deriveKeysFromHex } from "../src/index.js";
import { virtualTap, TEST_UID, TEST_ISSUER_KEY } from "./helpers.js";

describe("decryptP", () => {
  const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
  const k1 = hexToBytes(keys.k1);
  const counter = 5;

  it("decrypts a valid p= parameter and returns uidHex + ctr", () => {
    const { pHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const result = decryptP(pHex, [k1]);
    expect(result.success).toBe(true);
    if (result.success) {
      const uidHex = Array.from(result.uidBytes).map(b => b.toString(16).padStart(2, "0")).join("");
      expect(uidHex).toBe(TEST_UID);
      // ctr is big-endian: [counter>>16, counter>>8, counter&0xff]
      expect(result.ctr[0]).toBe(0);
      expect(result.ctr[1]).toBe(0);
      expect(result.ctr[2]).toBe(counter);
    }
  });

  it("returns { success: false } with wrong K1 key", () => {
    const { pHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const wrongKey = hexToBytes("00000000000000000000000000000002");
    const result = decryptP(pHex, [wrongKey]);
    expect(result.success).toBe(false);
  });

  it("returns { success: false } with empty k1Keys array", () => {
    const { pHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const result = decryptP(pHex, []);
    expect(result.success).toBe(false);
  });

  it("throws with invalid hex", () => {
    expect(() => decryptP("zzzz", [k1])).toThrow();
  });

  it("throws with wrong length p=", () => {
    expect(() => decryptP("0102", [k1])).toThrow("Invalid p length");
  });
});
