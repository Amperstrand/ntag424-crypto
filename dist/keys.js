import { computeAesCmac } from "./aes-cmac.js";
import { hexToBytes, bytesToHex } from "./hex.js";
/**
 * Deterministic key derivation for NTAG424 DNA cards.
 * Derives K0-K4 and cardKey from UID + issuer key.
 */
export function deriveKeysFromHex(uidHex, issuerKeyHex, version = 1) {
    const issuerKey = hexToBytes(issuerKeyHex);
    const uid = hexToBytes(uidHex);
    const versionBytes = new Uint8Array(4);
    new DataView(versionBytes.buffer).setUint32(0, version, true);
    const cardKey = computeAesCmac(new Uint8Array([...hexToBytes("2d003f75"), ...uid, ...versionBytes]), issuerKey);
    return {
        k0: bytesToHex(computeAesCmac(hexToBytes("2d003f76"), cardKey)),
        k1: bytesToHex(computeAesCmac(hexToBytes("2d003f77"), issuerKey)),
        k2: bytesToHex(computeAesCmac(hexToBytes("2d003f78"), cardKey)),
        k3: bytesToHex(computeAesCmac(hexToBytes("2d003f79"), cardKey)),
        k4: bytesToHex(computeAesCmac(hexToBytes("2d003f7a"), cardKey)),
        cardKey: bytesToHex(cardKey),
    };
}
