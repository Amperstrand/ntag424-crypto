import { ecb } from "@noble/ciphers/aes.js";
const BLOCK_SIZE = 16;
/** Single-block AES-ECB encrypt (no padding). */
function aesEcbEncrypt(key, block) {
    return ecb(key, { disablePadding: true }).encrypt(block);
}
function _xorArrays(a, b) {
    if (a.length !== b.length) {
        throw new Error("_xorArrays: Input arrays must have the same length");
    }
    const result = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}
function _shiftGo(src) {
    const shifted = new Uint8Array(src.length);
    let carry = 0;
    for (let i = src.length - 1; i >= 0; i--) {
        const msb = src[i] >> 7;
        shifted[i] = ((src[i] << 1) & 0xff) | carry;
        carry = msb;
    }
    return { shifted, carry };
}
function _generateSubkeyGo(input) {
    const { shifted, carry } = _shiftGo(input);
    const subkey = new Uint8Array(shifted);
    if (carry) {
        subkey[subkey.length - 1] ^= 0x87;
    }
    return subkey;
}
/**
 * RFC 4493 AES-CMAC with full multi-block CBC-MAC chaining.
 * Handles empty messages, partial blocks, and multi-block messages.
 */
export function computeAesCmac(message, key) {
    if (!(key instanceof Uint8Array) || key.length !== 16) {
        throw new Error("AES-CMAC requires a 16-byte key (AES-128), per RFC 4493 §2.3");
    }
    const zeroBlock = new Uint8Array(BLOCK_SIZE);
    const L = aesEcbEncrypt(key, zeroBlock);
    const K1 = _generateSubkeyGo(L);
    const K2 = _generateSubkeyGo(K1);
    const n = Math.max(1, Math.ceil(message.length / BLOCK_SIZE));
    let M_last;
    if (message.length === 0) {
        const padded = new Uint8Array(BLOCK_SIZE);
        padded[0] = 0x80;
        M_last = _xorArrays(padded, K2);
    }
    else if (message.length % BLOCK_SIZE === 0) {
        const lastBlock = message.slice(message.length - BLOCK_SIZE);
        M_last = _xorArrays(lastBlock, K1);
    }
    else {
        const remainder = message.length % BLOCK_SIZE;
        const padded = new Uint8Array(BLOCK_SIZE);
        padded.set(message.slice(message.length - remainder));
        padded[remainder] = 0x80;
        M_last = _xorArrays(padded, K2);
    }
    let X = new Uint8Array(BLOCK_SIZE);
    for (let i = 0; i < n - 1; i++) {
        const block = message.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
        X = _xorArrays(X, block);
        X = aesEcbEncrypt(key, X);
    }
    X = _xorArrays(X, M_last);
    return aesEcbEncrypt(key, X);
}
/** Compute session key Ks from sv2 */
export function _computeKs(sv2, cmacKeyBytes) {
    return computeAesCmac(sv2, cmacKeyBytes);
}
/** Compute Cm from Ks, optionally including MAC window data (RFC 4493 AES-CMAC) */
export function _computeCm(ks, data) {
    return computeAesCmac(data ?? new Uint8Array(0), ks);
}
/** Extract bytes at odd indices (1,3,5,...) */
function _extractOddBytes(cm) {
    return new Uint8Array([
        cm[1],
        cm[3],
        cm[5],
        cm[7],
        cm[9],
        cm[11],
        cm[13],
        cm[15],
    ]);
}
/** Full verification CMAC computation */
export function _computeAesCmacForVerification(sv2, cmacKeyBytes) {
    const ks = _computeKs(sv2, cmacKeyBytes);
    const cm = _computeCm(ks);
    return _extractOddBytes(cm);
}
