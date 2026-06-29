import type { DerivedKeys } from "./keys.js";
/**
 * Virtual NTAG424 card for testing bolt card flows.
 *
 * Generates valid encrypted `p=` and CMAC `c=` parameters that
 * are compatible with decryptP() and verifyCmac().
 *
 * Usage:
 *   const card = new TestCard("04a1b2c3d4e5f6", "issuer-key-hex");
 *   const tap = card.tap(1);
 *   // tap.p = encrypted PICC data
 *   // tap.c = CMAC
 *   // tap.uidHex = "04a1b2c3d4e5f6"
 *   // tap.counter = 1
 */
export declare class TestCard {
    readonly uidHex: string;
    readonly uidBytes: Uint8Array;
    readonly issuerKeyHex: string;
    readonly version: number;
    readonly keys: DerivedKeys;
    constructor(uidHex: string, issuerKeyHex: string, version?: number);
    /**
     * Generate a valid tap with encrypted p= and CMAC c=.
     * @param counter - the PICC session counter (must be >= 0)
     */
    tap(counter: number): TapResult;
    /** Get K1 as Uint8Array (for passing to decryptP) */
    get k1Bytes(): Uint8Array;
    /** Get K2 as Uint8Array (for passing to verifyCmac) */
    get k2Bytes(): Uint8Array;
}
export interface TapResult {
    /** Encrypted PICC data (p= parameter, 32 hex chars) */
    p: string;
    /** CMAC tag (c= parameter, 16 hex chars) */
    c: string;
    /** Card UID in hex (14 chars) */
    uidHex: string;
    /** Session counter value */
    counter: number;
}
