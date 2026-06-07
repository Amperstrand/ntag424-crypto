import { describe, it, expect } from "vitest";
import { cmacScanVersions, hexToBytes, deriveKeysFromHex } from "../src/index.js";
import { virtualTap, TEST_UID, TEST_ISSUER_KEY } from "./helpers.js";

describe("cmacScanVersions", () => {
  const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
  const counter = 15;

  it("finds matching version", async () => {
    const { cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([(counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff]);

    const result = await cmacScanVersions(uid, ctr, cHex, {
      k2ForVersion: async (v: number) => {
        const vKeys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY, v);
        return hexToBytes(vKeys.k2);
      },
      highVersion: 5,
      lowVersion: 1,
      stopOnFirst: true,
    });

    expect(result.matchedVersion).toBe(1);
    expect(result.attempts.length).toBeGreaterThanOrEqual(1);
    expect(result.attempts.some(a => a.cmac_validated)).toBe(true);
  });

  it("returns null when no version matches", async () => {
    const { cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([(counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff]);

    const result = await cmacScanVersions(uid, ctr, cHex, {
      k2ForVersion: async () => hexToBytes("00000000000000000000000000000002"),
      highVersion: 3,
      lowVersion: 1,
      stopOnFirst: true,
    });

    expect(result.matchedVersion).toBeNull();
    expect(result.attempts.length).toBe(3);
    expect(result.attempts.every(a => !a.cmac_validated)).toBe(true);
  });

  it("scans all versions when stopOnFirst is false", async () => {
    const { cHex } = virtualTap(TEST_UID, counter, keys.k1, keys.k2);
    const uid = hexToBytes(TEST_UID);
    const ctr = new Uint8Array([(counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff]);

    const result = await cmacScanVersions(uid, ctr, cHex, {
      k2ForVersion: async (v: number) => {
        const vKeys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY, v);
        return hexToBytes(vKeys.k2);
      },
      highVersion: 5,
      lowVersion: 1,
      stopOnFirst: false,
    });

    expect(result.matchedVersion).toBe(1); // only version 1 matches with default issuer key
    expect(result.attempts.length).toBe(5);
  });
});
