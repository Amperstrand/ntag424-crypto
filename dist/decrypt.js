import { ecb } from "@noble/ciphers/aes.js";
import { hexToBytes } from "./hex.js";
const BLOCK_SIZE = 16;
const EXPECTED_PICC_DATA_TAG = 0xc7;
/**
 * AES-ECB decrypt the p= parameter from an NTAG424 tap.
 * Tries each K1 candidate and returns the first valid match.
 */
export function decryptP(pHex, k1Keys) {
    const pBytes = hexToBytes(pHex);
    if (pBytes.length !== BLOCK_SIZE) {
        throw new Error("Invalid p length. Expected 16 bytes.");
    }
    let bestMatch = null;
    for (let i = 0; i < k1Keys.length; i++) {
        const k1Bytes = k1Keys[i];
        // NXP AN12196 §3.4.2.1 specifies AES-128-CBC with IV=0 for PICCENCData decryption.
        // For a single 16-byte block, AES-CBC(IV=0) is mathematically identical to AES-ECB.
        // We use ECB because it avoids constructing a zero IV and is the primitive operation.
        // The Go boltcard reference (crypto.go) uses cipher.NewCBCDecrypter with iv = make([]byte, 16)
        // — functionally equivalent.
        const cipher = ecb(k1Bytes, { disablePadding: true });
        const decrypted = cipher.decrypt(pBytes);
        if (decrypted[0] === EXPECTED_PICC_DATA_TAG) {
            const uidBytes = decrypted.slice(1, 8);
            const ctrLo = decrypted[8] | decrypted[9] | decrypted[10];
            if (uidBytes.every(b => b === 0) && ctrLo === 0)
                continue;
            if (bestMatch === null) {
                const ctr = new Uint8Array([decrypted[10], decrypted[9], decrypted[8]]);
                bestMatch = { success: true, uidBytes, ctr, usedK1: k1Bytes };
            }
        }
    }
    return bestMatch !== null ? bestMatch : { success: false };
}
