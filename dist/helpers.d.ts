export interface ExtractSuccess {
    success: true;
    uidHex: string;
    ctr: string;
}
export interface ExtractFailure {
    success: false;
    error: string;
}
export type ExtractResult = ExtractSuccess | ExtractFailure;
/**
 * Decrypt p= parameter and extract UID hex + counter hex.
 */
export declare function extractUIDAndCounter(pHex: string, k1Keys: Uint8Array[]): ExtractResult;
/**
 * Validate CMAC with null-safety for inputs.
 */
export declare function validateCmac(uidBytes: Uint8Array, ctr: Uint8Array, cHex: string | null | undefined, k2Bytes: Uint8Array | undefined): {
    cmac_validated: boolean;
    cmac_error: string | null;
};
/**
 * Full pipeline: decrypt p= + verify c= CMAC.
 */
export declare function decodeAndValidate(pHex: string, cHex: string | null | undefined, k1Keys: Uint8Array[], k2Bytes?: Uint8Array): {
    success: boolean;
    uidHex?: string;
    ctr?: string;
    cmac_validated: boolean;
    cmac_error: string | null;
    error?: string;
};
