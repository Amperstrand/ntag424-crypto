import { hexToBytes } from "./hex.js";
import { _computeKs, _computeCm } from "./aes-cmac.js";

const BLOCK_SIZE = 16;

export interface VerificationResult {
  sv2: Uint8Array;
  ks: Uint8Array;
  cm: Uint8Array;
  ct: Uint8Array;
}

/**
 * Construct sv2, compute session key ks, Cm, and CMAC tag ct.
 */
export function buildVerificationData(uidBytes: Uint8Array, ctr: Uint8Array, k2Bytes: Uint8Array): VerificationResult {
  const sv2 = new Uint8Array(BLOCK_SIZE);
  sv2.set([0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80]);
  sv2.set(uidBytes, 6);
  sv2[13] = ctr[2]!;
  sv2[14] = ctr[1]!;
  sv2[15] = ctr[0]!;

  const ks = _computeKs(sv2, k2Bytes);
  const cm = _computeCm(ks);

  const ct = new Uint8Array([
    cm[1]!,
    cm[3]!,
    cm[5]!,
    cm[7]!,
    cm[9]!,
    cm[11]!,
    cm[13]!,
    cm[15]!,
  ]);

  return { sv2, ks, cm, ct };
}

interface CmacResult {
  cmac_validated: boolean;
  cmac_error: string | null;
}

/**
 * Verify the c= CMAC parameter from an NTAG424 tap.
 * Uses constant-time comparison (XOR accumulation).
 */
export function verifyCmac(uidBytes: Uint8Array, ctr: Uint8Array, cHex: string, k2Bytes: Uint8Array): CmacResult {
  if (!cHex || cHex.length !== 16) {
    return { cmac_validated: false, cmac_error: 'CMAC validation failed' };
  }

  const { ct } = buildVerificationData(uidBytes, ctr, k2Bytes);

  const providedBytes = hexToBytes(cHex);
  let diff = 0;
  for (let i = 0; i < ct.length; i++) {
    diff |= ct[i]! ^ providedBytes[i]!;
  }
  const cmac_validated = diff === 0;

  return {
    cmac_validated,
    cmac_error: cmac_validated
      ? null
      : 'CMAC validation failed'
  };
}
