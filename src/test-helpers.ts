import AES from "aes-js";
import { deriveKeysFromHex } from "./keys.js";
import { hexToBytes, bytesToHex } from "./hex.js";
import { buildVerificationData } from "./verify.js";
import type { DerivedKeys } from "./keys.js";

/**
 * Virtual NTAG424 card for testing bolt card flows.
 *
 * Generates valid encrypted `p=` and CMAC `c=` parameters that
 * are compatible with decryptP() and verifyCmac().
 *
 * Usage:
 *   const card = new TestCard("04a1b2c3d4e5f6", "issuer-key-hex");
 *   const tap = card.tap(1);
 *   // tap.p = encrypted PICC data
 *   // tap.c = CMAC
 *   // tap.uidHex = "04a1b2c3d4e5f6"
 *   // tap.counter = 1
 */
export class TestCard {
  public readonly uidHex: string;
  public readonly uidBytes: Uint8Array;
  public readonly issuerKeyHex: string;
  public readonly version: number;
  public readonly keys: DerivedKeys;

  constructor(uidHex: string, issuerKeyHex: string, version: number = 1) {
    if (!/^[0-9a-fA-F]{14}$/.test(uidHex)) {
      throw new Error("uidHex must be exactly 14 hex characters (7 bytes)");
    }
    this.uidHex = uidHex.toLowerCase();
    this.uidBytes = hexToBytes(this.uidHex);
    this.issuerKeyHex = issuerKeyHex.toLowerCase();
    this.version = version;
    this.keys = deriveKeysFromHex(this.uidHex, this.issuerKeyHex, this.version);
  }

  /**
   * Generate a valid tap with encrypted p= and CMAC c=.
   * @param counter - the PICC session counter (must be >= 0)
   */
  tap(counter: number): TapResult {
    if (counter < 0 || counter > 0xffffff) {
      throw new Error("Counter must be 0..16777215 (24-bit)");
    }

    // Build PICC plaintext (16 bytes):
    // byte 0: 0xC7 tag
    // bytes 1-7: UID
    // byte 8: counter LSB
    // byte 9: counter middle
    // byte 10: counter MSB
    // bytes 11-15: zero padding
    const picc = new Uint8Array(16);
    picc[0] = 0xc7;
    picc.set(this.uidBytes, 1);
    picc[8] = counter & 0xff;
    picc[9] = (counter >> 8) & 0xff;
    picc[10] = (counter >> 16) & 0xff;

    // AES-ECB encrypt with K1
    const k1Bytes = hexToBytes(this.keys.k1);
    const aesEcb = new AES.ModeOfOperation.ecb(k1Bytes);
    const encrypted = aesEcb.encrypt(picc);
    const p = bytesToHex(encrypted);

    // Counter bytes in decryptP format: [MSB, mid, LSB]
    const ctrBytes = new Uint8Array([
      (counter >> 16) & 0xff,
      (counter >> 8) & 0xff,
      counter & 0xff,
    ]);

    // Compute CMAC with K2
    const k2Bytes = hexToBytes(this.keys.k2);
    const { ct } = buildVerificationData(this.uidBytes, ctrBytes, k2Bytes);
    const c = bytesToHex(ct);

    return { p, c, uidHex: this.uidHex, counter };
  }

  /** Get K1 as Uint8Array (for passing to decryptP) */
  get k1Bytes(): Uint8Array {
    return hexToBytes(this.keys.k1);
  }

  /** Get K2 as Uint8Array (for passing to verifyCmac) */
  get k2Bytes(): Uint8Array {
    return hexToBytes(this.keys.k2);
  }
}

export interface TapResult {
  /** Encrypted PICC data (p= parameter, 32 hex chars) */
  p: string;
  /** CMAC tag (c= parameter, 16 hex chars) */
  c: string;
  /** Card UID in hex (14 chars) */
  uidHex: string;
  /** Session counter value */
  counter: number;
}
