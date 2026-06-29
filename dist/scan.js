import { validateCmac } from "./helpers.js";
/**
 * Scan a version range for CMAC match.
 * Tries each version from highVersion down to lowVersion,
 * calling k2ForVersion to get the K2 key for each version.
 */
export async function cmacScanVersions(uidBytes, ctrBytes, cHex, opts) {
    const { k2ForVersion, highVersion, lowVersion, stopOnFirst = true } = opts;
    const attempts = [];
    let matchedVersion = null;
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
