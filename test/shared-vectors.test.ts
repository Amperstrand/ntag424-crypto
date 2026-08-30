import { describe, it, expect } from "vitest";
import vectors from "./vectors.json";
import {
  computeAesCmac,
  decryptP,
  verifyCmac,
  buildVerificationData,
  deriveKeysFromHex,
  hexToBytes,
  bytesToHex,
} from "../src/index.js";

interface VectorInput {
  op: string;
  key?: string;
  message?: string;
  picc_enc_data?: string;
  uid?: string;
  counter_bytes?: string;
  issuer_key?: string;
  version?: number;
  k1?: string;
  k2?: string;
  p?: string;
  c?: string;
}

interface VectorExpected {
  cmac?: string;
  decrypted?: string;
  uid?: string;
  counter_bytes?: string;
  sv2?: string;
  cmac_truncated?: string;
  card_key?: string;
  k0?: string;
  k1?: string;
  k2?: string;
  k3?: string;
  k4?: string;
  card_id?: string;
  decrypted_p?: string;
  derived_mac_key?: string;
  full_cmac?: string;
}

interface Vector {
  id: string;
  category: "an12196" | "sdm" | "derivation";
  input: VectorInput;
  expected: VectorExpected;
  origin: string;
}

const suite = (vectors as { vectors: Vector[] }).vectors;

// decryptP and buildVerificationData exchange the counter as
// [b2, b1, b0] (MSB-first); vectors pin the verbatim PICCData bytes
// [b0, b1, b2] (LSB-first), so reverse at the boundary.
function ctrMsbFirst(counterBytes: string): Uint8Array {
  return hexToBytes(counterBytes).reverse();
}

function byOp(op: string): Vector[] {
  return suite.filter((v) => v.input.op === op);
}

describe("shared cross-language vector suite (Amperstrand/ntag424-vectors)", () => {
  it("has the expected suite size and categories", () => {
    expect(suite.length).toBe(16);
    const categories = new Set(suite.map((v) => v.category));
    expect([...categories].sort()).toEqual(["an12196", "derivation", "sdm"]);
  });

  describe("aes_cmac", () => {
    it("matches every AES-CMAC known-answer vector", () => {
      const vs = byOp("aes_cmac");
      expect(vs.length).toBe(5);
      for (const v of vs) {
        const cmac = computeAesCmac(
          hexToBytes(v.input.message!),
          hexToBytes(v.input.key!),
        );
        expect(bytesToHex(cmac), v.id).toBe(v.expected.cmac);
      }
    });
  });

  describe("picc_decrypt", () => {
    it("recovers UID and read counter from PICCENCData", () => {
      const vs = byOp("picc_decrypt");
      expect(vs.length).toBe(1);
      for (const v of vs) {
        const result = decryptP(v.input.picc_enc_data!, [hexToBytes(v.input.key!)]);
        expect(result.success, v.id).toBe(true);
        if (!result.success) continue;
        expect(bytesToHex(result.uidBytes), v.id).toBe(v.expected.uid);
        expect(bytesToHex(result.ctr), v.id).toBe(
          bytesToHex(hexToBytes(v.expected.counter_bytes!).reverse()),
        );
      }
    });
  });

  describe("sv2_build", () => {
    it("constructs SV2 byte-for-byte", () => {
      const vs = byOp("sv2_build");
      expect(vs.length).toBe(2);
      for (const v of vs) {
        const { sv2 } = buildVerificationData(
          hexToBytes(v.input.uid!),
          ctrMsbFirst(v.input.counter_bytes!),
          new Uint8Array(16),
        );
        expect(bytesToHex(sv2), v.id).toBe(v.expected.sv2);
      }
    });
  });

  describe("sun_mac", () => {
    it("derives the AN12196 §3.4.4.2.1 SUN MACt", () => {
      const vs = byOp("sun_mac");
      expect(vs.length).toBe(1);
      for (const v of vs) {
        const key = hexToBytes(v.input.key!);
        const uid = hexToBytes(v.input.uid!);
        const ctr = ctrMsbFirst(v.input.counter_bytes!);
        const { ct, ks } = buildVerificationData(uid, ctr, key);
        // Cross-check against the sibling table4-session-key vector.
        const sessionKeyVector = suite.find(
          (x) => x.id === "an12196-table4-session-key",
        );
        expect(bytesToHex(ks), `${v.id} session key`).toBe(
          sessionKeyVector!.expected.cmac,
        );
        expect(bytesToHex(ct), v.id).toBe(v.expected.cmac_truncated);
        const verified = verifyCmac(uid, ctr, v.expected.cmac_truncated!, key);
        expect(verified.cmac_validated, v.id).toBe(true);
      }
    });
  });

  describe("derive_keys", () => {
    it("derives the boltcard deterministic key set", () => {
      const vs = byOp("derive_keys");
      expect(vs.length).toBe(5);
      // card_id (CMAC(card_key, 2D003F7B)) is not exposed by
      // deriveKeysFromHex; it is skipped in the 3 vectors that carry it.
      for (const v of vs) {
        const keys = deriveKeysFromHex(
          v.input.uid!,
          v.input.issuer_key!,
          v.input.version!,
        );
        // Sources published subsets (e.g. the AGENTS.md v0 example carries
        // only k0); verify exactly the fields the vector pins.
        if (v.expected.card_key !== undefined)
          expect(keys.cardKey, v.id).toBe(v.expected.card_key);
        if (v.expected.k0 !== undefined) expect(keys.k0, v.id).toBe(v.expected.k0);
        if (v.expected.k1 !== undefined) expect(keys.k1, v.id).toBe(v.expected.k1);
        if (v.expected.k2 !== undefined) expect(keys.k2, v.id).toBe(v.expected.k2);
        if (v.expected.k3 !== undefined) expect(keys.k3, v.id).toBe(v.expected.k3);
        if (v.expected.k4 !== undefined) expect(keys.k4, v.id).toBe(v.expected.k4);
      }
    });
  });

  describe("sdm_full", () => {
    it("runs the full SDM decrypt + MAC chain", () => {
      const vs = byOp("sdm_full");
      expect(vs.length).toBe(2);
      for (const v of vs) {
        const k1 = hexToBytes(v.input.k1!);
        const k2 = hexToBytes(v.input.k2!);

        const result = decryptP(v.input.p!, [k1]);
        expect(result.success, `${v.id} decrypt`).toBe(true);
        if (!result.success) continue;
        expect(bytesToHex(result.uidBytes), `${v.id} uid`).toBe(v.expected.uid);
        expect(bytesToHex(result.ctr), `${v.id} counter`).toBe(
          bytesToHex(hexToBytes(v.expected.counter_bytes!).reverse()),
        );

        const { sv2, ks, cm, ct } = buildVerificationData(
          hexToBytes(v.expected.uid!),
          hexToBytes(v.expected.counter_bytes!).reverse(),
          k2,
        );
        expect(bytesToHex(sv2), `${v.id} sv2`).toBe(v.expected.sv2);
        expect(bytesToHex(ks), `${v.id} derived_mac_key`).toBe(
          v.expected.derived_mac_key,
        );
        expect(bytesToHex(cm), `${v.id} full_cmac`).toBe(v.expected.full_cmac);
        expect(bytesToHex(ct), `${v.id} truncated c`).toBe(v.input.c);

        const verified = verifyCmac(
          hexToBytes(v.expected.uid!),
          hexToBytes(v.expected.counter_bytes!).reverse(),
          v.input.c!,
          k2,
        );
        expect(verified.cmac_validated, v.id).toBe(true);
      }
    });
  });
});
