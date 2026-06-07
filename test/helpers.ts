import AES from "aes-js";
import { hexToBytes, bytesToHex, buildVerificationData } from "../src/index.js";

export function virtualTap(uidHex: string, counter: number, k1Hex: string, k2Hex: string): { pHex: string; cHex: string } {
  const k1 = hexToBytes(k1Hex);
  const uid = hexToBytes(uidHex);
  const plaintext = new Uint8Array(16);
  plaintext[0] = 0xc7;
  plaintext.set(uid, 1);
  plaintext[8] = counter & 0xff;
  plaintext[9] = (counter >> 8) & 0xff;
  plaintext[10] = (counter >> 16) & 0xff;
  const aes = new AES.ModeOfOperation.ecb(k1);
  const encrypted = aes.encrypt(plaintext);
  const pHex = bytesToHex(new Uint8Array(encrypted));
  const ctrHex = bytesToHex(
    new Uint8Array([(counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff])
  );
  const vd = buildVerificationData(uid, hexToBytes(ctrHex), hexToBytes(k2Hex));
  const cHex = bytesToHex(vd.ct);
  return { pHex, cHex };
}

// Test constants from boltcard-cloudflareworker
export const TEST_UID = "04a39493cc8680";
export const TEST_ISSUER_KEY = "00000000000000000000000000000001";
