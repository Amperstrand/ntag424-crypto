/**
 * RFC 4493 AES-CMAC with full multi-block CBC-MAC chaining (§2.3).
 * Handles empty messages, partial blocks, and multi-block messages.
 */
export declare function computeAesCmac(message: Uint8Array, key: Uint8Array): Uint8Array;
/** Compute session key Ks from sv2 */
export declare function _computeKs(sv2: Uint8Array, cmacKeyBytes: Uint8Array): Uint8Array;
/** Compute Cm from Ks (double subkey derivation) */
export declare function _computeCm(ks: Uint8Array): Uint8Array;
/** Full verification CMAC computation */
export declare function _computeAesCmacForVerification(sv2: Uint8Array, cmacKeyBytes: Uint8Array): Uint8Array;
