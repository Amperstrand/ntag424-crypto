import { describe, it, expect } from "vitest";
import { verifyCmac, buildVerificationData, hexToBytes, bytesToHex, deriveKeysFromHex } from "../src/index.js";
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

describe("MAC window (windowData)", () => {
  const uid = hexToBytes("04a39493cc868080");
  const ctr = hexToBytes("000011");
  const k2 = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
  const enc = new TextEncoder();
  const shortWindow = enc.encode("boltcard.example.com/lnurlw?p=AB");
  const longWindow = enc.encode("boltcard.example.com/lnurlw?p=A1B2C3D4E5F60718&c=");

  it("byte-exact: no window (pinned, matches v1.0.0 production dist)", () => {
    expect(bytesToHex(buildVerificationData(uid, ctr, k2).ct)).toBe("55378618a2d0ce94");
  });

  it("byte-exact: short window < 16 bytes", () => {
    expect(bytesToHex(buildVerificationData(uid, ctr, k2, shortWindow).ct)).toBe("341ee269a983aef5");
  });

  it("byte-exact: window > 16 bytes exercises multi-block chaining", () => {
    expect(bytesToHex(buildVerificationData(uid, ctr, k2, longWindow).ct)).toBe("beec854f49523858");
  });

  it("window changes the tag; omitting it cannot validate a window tap", () => {
    const withWindow = buildVerificationData(uid, ctr, k2, shortWindow);
    expect(withWindow.ct).not.toEqual(buildVerificationData(uid, ctr, k2).ct);
    const cHex = bytesToHex(withWindow.ct);
    expect(verifyCmac(uid, ctr, cHex, k2, shortWindow).cmac_validated).toBe(true);
    expect(verifyCmac(uid, ctr, cHex, k2).cmac_validated).toBe(false);
    expect(verifyCmac(uid, ctr, cHex, k2, longWindow).cmac_validated).toBe(false);
  });
});
