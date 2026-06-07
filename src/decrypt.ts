import AES from "aes-js";
import { hexToBytes } from "./hex.js";

const BLOCK_SIZE = 16;
const EXPECTED_PICC_DATA_TAG = 0xc7;

export interface DecryptSuccess {
  success: true;
  uidBytes: Uint8Array;
  ctr: Uint8Array;
  usedK1: Uint8Array;
}

export interface DecryptFailure {
  success: false;
}

export type DecryptResult = DecryptSuccess | DecryptFailure;

/**
 * AES-ECB decrypt the p= parameter from an NTAG424 tap.
 * Tries each K1 candidate and returns the first valid match.
 */
export function decryptP(pHex: string, k1Keys: Uint8Array[]): DecryptResult {
  const pBytes = hexToBytes(pHex);
  if (pBytes.length !== BLOCK_SIZE) {
    throw new Error("Invalid p length. Expected 16 bytes.");
  }

  let bestMatch: DecryptSuccess | null = null;

  for (let i = 0; i < k1Keys.length; i++) {
    const k1Bytes = k1Keys[i]!;
    const aesEcbK1 = new AES.ModeOfOperation.ecb(k1Bytes);
    const decrypted = aesEcbK1.decrypt(pBytes);

    if (decrypted[0] === EXPECTED_PICC_DATA_TAG) {
      const uidBytes = decrypted.slice(1, 8);
      const ctrLo = decrypted[8]! | decrypted[9]! | decrypted[10]!;
      if (uidBytes.every(b => b === 0) && ctrLo === 0) continue;

      if (bestMatch === null) {
        const ctr = new Uint8Array([decrypted[10]!, decrypted[9]!, decrypted[8]!]);
        bestMatch = { success: true, uidBytes, ctr, usedK1: k1Bytes };
      }
    }
  }

  return bestMatch !== null ? bestMatch : { success: false };
}
