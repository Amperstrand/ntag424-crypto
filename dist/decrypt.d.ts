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
export declare function decryptP(pHex: string, k1Keys: Uint8Array[]): DecryptResult;
