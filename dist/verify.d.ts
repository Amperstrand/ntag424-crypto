export interface VerificationResult {
    sv2: Uint8Array;
    ks: Uint8Array;
    cm: Uint8Array;
    ct: Uint8Array;
}
/**
 * Construct sv2, compute session key ks, Cm, and CMAC tag ct.
 */
export declare function buildVerificationData(uidBytes: Uint8Array, ctr: Uint8Array, k2Bytes: Uint8Array, windowData?: Uint8Array): VerificationResult;
interface CmacResult {
    cmac_validated: boolean;
    cmac_error: string | null;
}
/**
 * Verify the c= CMAC parameter from an NTAG424 tap.
 * Uses constant-time comparison (XOR accumulation).
 */
export declare function verifyCmac(uidBytes: Uint8Array, ctr: Uint8Array, cHex: string, k2Bytes: Uint8Array, windowData?: Uint8Array): CmacResult;
export {};
