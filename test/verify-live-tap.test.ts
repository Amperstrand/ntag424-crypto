import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { decryptP, verifyCmac, hexToBytes, bytesToHex } from "../src/index.js";
import { virtualTap } from "./helpers.js";

/**
 * Key-generation discriminator test.
 *
 * When several candidate key generations exist for a card (e.g. historical
 * provisionings), a single captured tap URL identifies the live generation:
 * decrypt p= under each candidate K1, check the UID, then CMAC-verify c=
 * under that generation's K2. This suite proves the discrimination logic
 * with two SYNTHETIC random generations — it must identify the right one,
 * reject the wrong one, and reject tampering.
 *
 * Real-tap mode: run with LIVE_* env vars to judge an actual card tap
 * offline (zero card contact):
 *   LIVE_UID=04... LIVE_K1=<hex> LIVE_K2=<hex> LIVE_P=<32hex> LIVE_C=<16hex> \
 *   npx vitest run test/verify-live-tap.test.ts
 */

const TEST_UID = "04a39493cc8680"; // arbitrary fixed test UID

function makeGen(): { k1: string; k2: string } {
  return {
    k1: randomBytes(16).toString("hex"),
    k2: randomBytes(16).toString("hex"),
  };
}

function verifyTap(
  uid: string,
  pHex: string,
  cHex: string,
  candidates: { name: string; k1: string; k2: string }[]
): string[] {
  const verdicts: string[] = [];
  for (const g of candidates) {
    const r = decryptP(pHex, [hexToBytes(g.k1)]);
    if (!r.success) {
      verdicts.push(`${g.name}: p does not decrypt under K1 (wrong generation)`);
      continue;
    }
    const uidHex = bytesToHex(r.uidBytes);
    if (uidHex !== uid) {
      verdicts.push(`${g.name}: K1 decrypts p but UID=${uidHex} != ${uid}`);
      continue;
    }
    const v = verifyCmac(r.uidBytes, r.ctr, cHex, hexToBytes(g.k2));
    verdicts.push(
      `${g.name}: uid=${uidHex} ctr=${bytesToHex(r.ctr)} cmac_validated=${v.cmac_validated}` +
        (v.cmac_error ? ` (error: ${v.cmac_error})` : "  <== MATCH")
    );
  }
  return verdicts;
}

describe("verify-live-tap discriminator", () => {
  const genA = { name: "genA", ...makeGen() };
  const genB = { name: "genB", ...makeGen() };
  const candidates = [genA, genB];

  it("identifies a genA tap and rejects it under genB", () => {
    const { pHex, cHex } = virtualTap(TEST_UID, 4711, genA.k1, genA.k2);
    const v = verifyTap(TEST_UID, pHex, cHex, candidates);
    expect(v[0]).toContain("cmac_validated=true");
    expect(v[1]).toContain("does not decrypt");
  });

  it("identifies a genB tap and rejects it under genA", () => {
    const { pHex, cHex } = virtualTap(TEST_UID, 999999, genB.k1, genB.k2);
    const v = verifyTap(TEST_UID, pHex, cHex, candidates);
    expect(v[0]).toContain("does not decrypt");
    expect(v[1]).toContain("cmac_validated=true");
  });

  it("rejects a tampered c= for the right generation", () => {
    const { pHex } = virtualTap(TEST_UID, 5, genA.k1, genA.k2);
    const v = verifyTap(TEST_UID, pHex, "deadbeefdeadbeef", candidates);
    expect(v[0]).toContain("cmac_validated=false");
  });

  it("rejects a tap from a different UID even with the right keys", () => {
    const other = "04996c6a926980";
    const { pHex, cHex } = virtualTap(other, 7, genA.k1, genA.k2);
    const v = verifyTap(TEST_UID, pHex, cHex, candidates);
    expect(v.every((line) => !line.includes("MATCH"))).toBe(true);
  });

  it.runIf(
    process.env.LIVE_P && process.env.LIVE_C && process.env.LIVE_K1 && process.env.LIVE_K2 && process.env.LIVE_UID
  )("LIVE tap verdict (LIVE_* env vars)", () => {
    const { LIVE_P, LIVE_C, LIVE_UID, LIVE_K1, LIVE_K2 } = process.env;
    const v = verifyTap(LIVE_UID!, LIVE_P!, LIVE_C!, [
      { name: "live", k1: LIVE_K1!, k2: LIVE_K2! },
    ]);
    console.log("\n=== LIVE TAP VERDICT ===\n" + v.join("\n") + "\n=======================");
    expect(v.some((line) => line.includes("cmac_validated=true"))).toBe(true);
  });
});
