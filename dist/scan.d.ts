export interface CmacScanOptions {
    k2ForVersion: (v: number) => Promise<Uint8Array>;
    highVersion: number;
    lowVersion: number;
    stopOnFirst?: boolean;
}
export interface CmacScanAttempt {
    version: number;
    cmac_validated: boolean;
}
export interface CmacScanResult {
    matchedVersion: number | null;
    attempts: CmacScanAttempt[];
}
/**
 * Scan a version range for CMAC match.
 * Tries each version from highVersion down to lowVersion,
 * calling k2ForVersion to get the K2 key for each version.
 */
export declare function cmacScanVersions(uidBytes: Uint8Array, ctrBytes: Uint8Array, cHex: string, opts: CmacScanOptions): Promise<CmacScanResult>;
