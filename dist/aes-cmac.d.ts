/**
 * RFC 4493 single-block AES-CMAC.
 * Throws if message > 16 bytes (multi-block CBC-MAC not implemented).
 */
export declare function computeAesCmac(message: Uint8Array, key: Uint8Array): Uint8Array;
/** Compute session key Ks from sv2 */
export declare function _computeKs(sv2: Uint8Array, cmacKeyBytes: Uint8Array): Uint8Array;
/** Compute Cm from Ks (double subkey derivation) */
export declare function _computeCm(ks: Uint8Array): Uint8Array;
/** Full verification CMAC computation */
export declare function _computeAesCmacForVerification(sv2: Uint8Array, cmacKeyBytes: Uint8Array): Uint8Array;
