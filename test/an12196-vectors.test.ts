import { describe, it, expect } from "vitest";
import {
  computeAesCmac,
  decryptP,
  verifyCmac,
  buildVerificationData,
  hexToBytes,
  bytesToHex,
} from "../src/index.js";

const toHex = (bytes: Uint8Array): string => bytesToHex(bytes);

// ---------------------------------------------------------------------------
// AN12196 §3.3 Table 1 — SDM Session Key Generation
// ---------------------------------------------------------------------------
describe("AN12196 §3.3 Table 1 — SDM Session Key Generation", () => {
  const key = hexToBytes("5ACE7E50AB65D5D51FD5BF5A16B8205B");

  // SV1 = C33C || 0001 || 0080 || UID(7B) || SDMReadCtr(3B)
  // UID = 04C767F2066180, SDMReadCtr = 00100007h
  // Counter bytes in SV are upper 3 bytes of 4-byte big-endian SDMReadCtr
  const sv1 = hexToBytes("C33C0001008004C767F2066180010000");

  // SV2 = 3CC3 || 0001 || 0080 || UID(7B) || (SDMReadCtr+1)(3B)
  // SDMReadCtr+1 = 00100008h — upper 3 bytes unchanged (001000)
  const sv2 = hexToBytes("3CC30001008004C767F2066180010000");

  it("derives KSesSDMFileReadENC = CMAC(K_SDMFileRead, SV1)", () => {
    const ksEnc = computeAesCmac(sv1, key);
    expect(toHex(ksEnc)).toBe("66da61797e23deca5d8eca13bbadf7a9");
  });

  it("derives KSesSDMFileReadMAC = CMAC(K_SDMFileRead, SV2)", () => {
    const ksMac = computeAesCmac(sv2, key);
    expect(toHex(ksMac)).toBe("3a3e8110e05311f7a3fcf0d969bf2b48");
  });
});

// ---------------------------------------------------------------------------
// AN12196 §3.4.2.1 Table 2 — PICCData Decryption
// ---------------------------------------------------------------------------
describe("AN12196 §3.4.2.1 Table 2 — PICCData Decryption", () => {
  it("decrypts PICCENCData with K_SDMMetaRead via AES-ECB", () => {
    // Table 2 uses K_SDMMetaRead directly as the AES-ECB decryption key
    const kMetaRead = hexToBytes("00000000000000000000000000000000");

    const result = decryptP("EF963FF7828658A599F3041510671E88", [kMetaRead]);

    expect(result.success).toBe(true);
    if (result.success) {
      // Expected decrypted: C704DE5F1EACC0403D0000DA5CF60941
      // PICCDataTag=C7, UID=04DE5F1EACC040, SDMReadCtr=3D0000
      expect(toHex(result.uidBytes)).toBe("04de5f1eacc040");
      // decryptP returns ctr as [decrypted[10], decrypted[9], decrypted[8]]
      // Decrypted[8..10] = 3D 00 00 → ctr = [00, 00, 3D]
      expect(result.ctr).toEqual(new Uint8Array([0x00, 0x00, 0x3d]));
    }
  });
});

// ---------------------------------------------------------------------------
// AN12196 §3.4.4.2.1 Table 4 — Full SUN MAC Verification
// ---------------------------------------------------------------------------
describe("AN12196 §3.4.4.2.1 Table 4 — Full SUN MAC Verification", () => {
  const kFileRead = hexToBytes("00000000000000000000000000000000");
  const uid = hexToBytes("04DE5F1EACC040");
  // ctr in decryptP return format: [decrypted[10], decrypted[9], decrypted[8]]
  // Decrypted bytes 8-10 = 3D 00 00 → ctr = [00, 00, 3D]
  const ctr = new Uint8Array([0x00, 0x00, 0x3d]);

  it("buildVerificationData constructs SV2 matching AN12196 spec", () => {
    const vd = buildVerificationData(uid, ctr, kFileRead);
    expect(toHex(vd.sv2)).toBe("3cc30001008004de5f1eacc0403d0000");
  });

  it("session key Ks = CMAC(K_SDMFileRead, SV2) matches spec", () => {
    const sv2 = hexToBytes("3CC30001008004DE5F1EACC0403D0000");
    const ks = computeAesCmac(sv2, kFileRead);
    expect(toHex(ks)).toBe("3fb5f6e3a807a03d5e3570ace393776f");
  });

  it("ct (truncated MAC) matches spec MACt", () => {
    const vd = buildVerificationData(uid, ctr, kFileRead);
    expect(toHex(vd.ct)).toBe("94eed9ee65337086");
  });

  it("verifyCmac validates spec MACt = 94EED9EE65337086", () => {
    const result = verifyCmac(uid, ctr, "94eed9ee65337086", kFileRead);
    expect(result.cmac_validated).toBe(true);
    expect(result.cmac_error).toBeNull();
  });
});
