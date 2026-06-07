import { describe, it, expect } from "vitest";
import { verifyCmac, buildVerificationData, hexToBytes, deriveKeysFromHex } from "../src/index.js";
import { virtualTap, TEST_UID, TEST_ISSUER_KEY } from "./helpers.js";

describe("verifyCmac", () => {
  const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
  const k2 = hexToBytes(keys.k2);
  const counter = 10;

  it("validates a correct CMAC", () => {
    const { cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([(counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff]);
    const result = verifyCmac(uid, ctr, cHex, k2);
    expect(result.cmac_validated).toBe(true);
    expect(result.cmac_error).toBeNull();
  });

  it("rejects wrong K2", () => {
    const { cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([(counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff]);
    const wrongK2 = hexToBytes("00000000000000000000000000000002");
    const result = verifyCmac(uid, ctr, cHex, wrongK2);
    expect(result.cmac_validated).toBe(false);
    expect(result.cmac_error).toBe("CMAC validation failed");
  });

  it("rejects modified c=", () => {
    const { cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([(counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff]);
    // Flip a byte in cHex
    const modifiedC = "ff" + cHex.slice(2);
    const result = verifyCmac(uid, ctr, modifiedC, k2);
    expect(result.cmac_validated).toBe(false);
  });

  it("rejects empty c=", () => {
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([0, 0, 1]);
    const result = verifyCmac(uid, ctr, "", k2);
    expect(result.cmac_validated).toBe(false);
  });

  it("rejects wrong-length c= (not 16 hex chars)", () => {
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([0, 0, 1]);
    const result = verifyCmac(uid, ctr, "aabb", k2);
    expect(result.cmac_validated).toBe(false);
  });
});

describe("buildVerificationData", () => {
  it("returns all four components", () => {
    const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([0, 0, 1]);
    const k2 = hexToBytes(keys.k2);
    const vd = buildVerificationData(uid, ctr, k2);
    expect(vd.sv2).toBeInstanceOf(Uint8Array);
    expect(vd.ks).toBeInstanceOf(Uint8Array);
    expect(vd.cm).toBeInstanceOf(Uint8Array);
    expect(vd.ct).toBeInstanceOf(Uint8Array);
    expect(vd.sv2.length).toBe(16);
    expect(vd.ks.length).toBe(16);
    expect(vd.cm.length).toBe(16);
    expect(vd.ct.length).toBe(8);
  });

  it("produces deterministic results", () => {
    const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([0, 0, 1]);
    const k2 = hexToBytes(keys.k2);
    const a = buildVerificationData(uid, ctr, k2);
    const b = buildVerificationData(uid, ctr, k2);
    expect(a.ct).toEqual(b.ct);
  });
});
