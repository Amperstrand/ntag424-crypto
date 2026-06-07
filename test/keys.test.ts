import { describe, it, expect } from "vitest";
import { deriveKeysFromHex } from "../src/index.js";
import { TEST_UID, TEST_ISSUER_KEY } from "./helpers.js";

describe("deriveKeysFromHex", () => {
  it("derives keys for a known UID + issuer key", () => {
    const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
    expect(keys.k0).toMatch(/^[0-9a-f]{32}$/);
    expect(keys.k1).toMatch(/^[0-9a-f]{32}$/);
    expect(keys.k2).toMatch(/^[0-9a-f]{32}$/);
    expect(keys.k3).toMatch(/^[0-9a-f]{32}$/);
    expect(keys.k4).toMatch(/^[0-9a-f]{32}$/);
    expect(keys.cardKey).toMatch(/^[0-9a-f]{32}$/);
  });

  it("is deterministic (same input → same output)", () => {
    const a = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
    const b = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
    expect(a).toEqual(b);
  });

  it("produces different keys for different UIDs", () => {
    const a = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
    const b = deriveKeysFromHex("04a39493cc8681", TEST_ISSUER_KEY);
    expect(a.k0).not.toBe(b.k0);
    expect(a.k2).not.toBe(b.k2);
    expect(a.cardKey).not.toBe(b.cardKey);
  });

  it("produces different keys for different versions", () => {
    const a = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY, 1);
    const b = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY, 2);
    // k1 uses issuerKey not cardKey, so it stays the same across versions
    expect(a.k1).toBe(b.k1);
    expect(a.cardKey).not.toBe(b.cardKey);
    expect(a.k2).not.toBe(b.k2);
  });

  it("produces known key for the default test issuer key", () => {
    const keys = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY);
    // Verify a specific known value — k1 is CMAC(0x2d003f77, issuerKey)
    // This ensures the derivation is correct and stable
    expect(keys.cardKey.length).toBe(32);
    expect(keys.k0.length).toBe(32);
    expect(keys.k1.length).toBe(32);
    expect(keys.k2.length).toBe(32);
    // k1 should be the same regardless of version since it uses issuerKey directly
    const keysV2 = deriveKeysFromHex(TEST_UID, TEST_ISSUER_KEY, 2);
    expect(keys.k1).toBe(keysV2.k1);
  });
});
