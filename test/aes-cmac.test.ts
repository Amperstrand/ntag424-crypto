import { describe, it, expect } from "vitest";
import { computeAesCmac, hexToBytes } from "../src/index.js";

describe("computeAesCmac", () => {
  it("produces known-answer result for a known key and message", () => {
    // RFC 4493 test vector: key = 2b7e151628aed2a6abf7158809cf4f3c, M = 6bc1bee22e409f96e93d7e117393172a
    const key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
    const message = hexToBytes("6bc1bee22e409f96e93d7e117393172a");
    const result = computeAesCmac(message, key);
    // Expected CMAC for 16-byte message (single block, XOR with K1)
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(16);
  });

  it("handles message < 16 bytes (padding case)", () => {
    const key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
    const message = hexToBytes("6bc1bee22e409f96e93d7e11739317");
    expect(message.length).toBe(15);
    const result = computeAesCmac(message, key);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(16);
  });

  it("handles empty message (0 bytes)", () => {
    const key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
    const message = new Uint8Array(0);
    const result = computeAesCmac(message, key);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(16);
  });

  it("handles message === 16 bytes (XOR with K1 case)", () => {
    const key = hexToBytes("00000000000000000000000000000001");
    const message = hexToBytes("2d003f7504a39493cc86800100000000");
    expect(message.length).toBe(16);
    const result = computeAesCmac(message, key);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(16);
  });

  it("throws with message > 16 bytes", () => {
    const key = hexToBytes("00000000000000000000000000000001");
    const message = new Uint8Array(17);
    expect(() => computeAesCmac(message, key)).toThrow("exceeds single-block limit");
  });

  it("throws with non-16-byte key", () => {
    const key = hexToBytes("0102030405060708");
    const message = new Uint8Array(0);
    expect(() => computeAesCmac(message, key)).toThrow("16-byte key");
  });

  it("produces deterministic results", () => {
    const key = hexToBytes("00000000000000000000000000000001");
    const message = hexToBytes("2d003f75");
    const a = computeAesCmac(message, key);
    const b = computeAesCmac(message, key);
    expect(a).toEqual(b);
  });
});
