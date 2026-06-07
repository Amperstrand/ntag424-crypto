import { validateCmac } from "./helpers.js";

export interface CmacScanOptions {
  k2ForVersion: (v: number) => Promise<Uint8Array>;
  highVersion: number;
  lowVersion: number;
  stopOnFirst?: boolean;
}

export interface CmacScanAttempt {
  version: number;
  cmac_validated: boolean;
}

export interface CmacScanResult {
  matchedVersion: number | null;
  attempts: CmacScanAttempt[];
}

/**
 * Scan a version range for CMAC match.
 * Tries each version from highVersion down to lowVersion,
 * calling k2ForVersion to get the K2 key for each version.
 */
export async function cmacScanVersions(
  uidBytes: Uint8Array,
  ctrBytes: Uint8Array,
  cHex: string,
  opts: CmacScanOptions
): Promise<CmacScanResult> {
  const { k2ForVersion, highVersion, lowVersion, stopOnFirst = true } = opts;
  const attempts: CmacScanAttempt[] = [];
  let matchedVersion: number | null = null;

  const step = highVersion >= lowVersion ? -1 : 1;
  for (let v = highVersion; step > 0 ? v <= lowVersion : v >= lowVersion; v += step) {
    const k2Bytes = await k2ForVersion(v);
    const { cmac_validated } = validateCmac(uidBytes, ctrBytes, cHex, k2Bytes);
    attempts.push({ version: v, cmac_validated });
    if (cmac_validated && stopOnFirst) {
      matchedVersion = v;
      break;
    }
    if (cmac_validated && !stopOnFirst && matchedVersion === null) {
      matchedVersion = v;
    }
  }

  return { matchedVersion, attempts };
}
