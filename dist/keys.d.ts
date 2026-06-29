export interface DerivedKeys {
    k0: string;
    k1: string;
    k2: string;
    k3: string;
    k4: string;
    cardKey: string;
}
/**
 * Deterministic key derivation for NTAG424 DNA cards.
 * Derives K0-K4 and cardKey from UID + issuer key.
 */
export declare function deriveKeysFromHex(uidHex: string, issuerKeyHex: string, version?: number): DerivedKeys;
