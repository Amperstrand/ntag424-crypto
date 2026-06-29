import { hexToBytes, bytesToHex } from "./hex.js";
import { decryptP } from "./decrypt.js";
import { verifyCmac } from "./verify.js";
/**
 * Decrypt p= parameter and extract UID hex + counter hex.
 */
export function extractUIDAndCounter(pHex, k1Keys) {
    let result;
    try {
        result = decryptP(pHex, k1Keys);
    }
    catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, error: msg };
    }
    if (!result.success) {
        return { success: false, error: "Unable to decode UID from provided p parameter." };
    }
    const uidBytes = new Uint8Array(result.uidBytes);
    const ctrBytes = new Uint8Array(result.ctr);
    return {
        success: true,
        uidHex: bytesToHex(uidBytes),
        ctr: bytesToHex(ctrBytes)
    };
}
/**
 * Validate CMAC with null-safety for inputs.
 */
export function validateCmac(uidBytes, ctr, cHex, k2Bytes) {
    if (!cHex) {
        return { cmac_validated: false, cmac_error: null };
    }
    if (!ctr || ctr.length === 0) {
        return { cmac_validated: false, cmac_error: 'Invalid counter value' };
    }
    if (k2Bytes) {
        return verifyCmac(uidBytes, ctr, cHex, k2Bytes);
    }
    return { cmac_validated: false, cmac_error: "K2 key not available" };
}
/**
 * Full pipeline: decrypt p= + verify c= CMAC.
 */
export function decodeAndValidate(pHex, cHex, k1Keys, k2Bytes) {
    const decryption = extractUIDAndCounter(pHex, k1Keys);
    if (!decryption.success) {
        return { success: false, cmac_validated: false, cmac_error: null, error: decryption.error };
    }
    const { uidHex, ctr } = decryption;
    const uidBytes = hexToBytes(uidHex);
    const ctrBytes = hexToBytes(ctr);
    const validation = validateCmac(uidBytes, ctrBytes, cHex, k2Bytes);
    return {
        success: true,
        uidHex,
        ctr,
        cmac_validated: validation.cmac_validated,
        cmac_error: validation.cmac_error
    };
}
