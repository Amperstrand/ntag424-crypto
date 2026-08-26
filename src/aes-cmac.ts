import { ecb } from "@noble/ciphers/aes.js";
import { hexToBytes } from "./hex.js";

const BLOCK_SIZE = 16;

/** Single-block AES-ECB encrypt (no padding). */
function aesEcbEncrypt(key: Uint8Array, block: Uint8Array): Uint8Array {
  return ecb(key, { disablePadding: true }).encrypt(block);
}

function _xorArrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) {
    throw new Error("_xorArrays: Input arrays must have the same length");
  }
  return new Uint8Array(a.map((val, i) => val ^ b[i]!));
}

function _shiftGo(src: Uint8Array): { shifted: Uint8Array; carry: number } {
  const shifted = new Uint8Array(src.length);
  let carry = 0;
  for (let i = src.length - 1; i >= 0; i--) {
    const msb = src[i]! >> 7;
    shifted[i] = ((src[i]! << 1) & 0xff) | carry;
    carry = msb;
  }
  return { shifted, carry };
}

function _generateSubkeyGo(input: Uint8Array): Uint8Array {
  const { shifted, carry } = _shiftGo(input);
  const subkey = new Uint8Array(shifted);
  if (carry) {
    subkey[subkey.length - 1]! ^= 0x87;
  }
  return subkey;
}

/**
 * RFC 4493 AES-CMAC with full multi-block CBC-MAC chaining (§2.3).
 * Handles empty messages, partial blocks, and multi-block messages.
 */
export function computeAesCmac(message: Uint8Array, key: Uint8Array): Uint8Array {
  if (!(key instanceof Uint8Array) || key.length !== 16) {
    throw new Error("AES-CMAC requires a 16-byte key (AES-128), per RFC 4493 §2.3");
  }

  const n = Math.ceil(message.length / BLOCK_SIZE);
  const complete = message.length > 0 && message.length % BLOCK_SIZE === 0;

  const zeroBlock = new Uint8Array(BLOCK_SIZE);

  const L = aesEcbEncrypt(key, zeroBlock);

  const K1 = _generateSubkeyGo(L);
  const K2 = _generateSubkeyGo(K1);

  let M_last: Uint8Array;
  if (complete) {
    M_last = _xorArrays(message.subarray((n - 1) * BLOCK_SIZE), K1);
  } else {
    const padded = new Uint8Array(BLOCK_SIZE);
    const tail = message.subarray(n === 0 ? 0 : (n - 1) * BLOCK_SIZE);
    padded.set(tail);
    padded[tail.length] = 0x80;
    M_last = _xorArrays(padded, K2);
  }

  let c: Uint8Array = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < n - 1; i++) {
    c = aesEcbEncrypt(key, _xorArrays(c, message.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)));
  }

  return aesEcbEncrypt(key, _xorArrays(c, M_last));
}

/** Compute session key Ks from sv2 */
export function _computeKs(sv2: Uint8Array, cmacKeyBytes: Uint8Array): Uint8Array {
  return computeAesCmac(sv2, cmacKeyBytes);
}

/** Compute Cm from Ks (double subkey derivation) */
export function _computeCm(ks: Uint8Array): Uint8Array {
  const zeroBlock = new Uint8Array(BLOCK_SIZE);

  const Lprime = aesEcbEncrypt(ks, zeroBlock);

  const K1prime = _generateSubkeyGo(Lprime);

  const hk1 = _generateSubkeyGo(K1prime);

  const hashVal = new Uint8Array(hk1);
  hashVal[0]! ^= 0x80;

  return aesEcbEncrypt(ks, hashVal);
}

/** Extract bytes at odd indices (1,3,5,...) */
function _extractOddBytes(cm: Uint8Array): Uint8Array {
  return new Uint8Array([
    cm[1]!,
    cm[3]!,
    cm[5]!,
    cm[7]!,
    cm[9]!,
    cm[11]!,
    cm[13]!,
    cm[15]!,
  ]);
}

/** Full verification CMAC computation */
export function _computeAesCmacForVerification(sv2: Uint8Array, cmacKeyBytes: Uint8Array): Uint8Array {
  const ks = _computeKs(sv2, cmacKeyBytes);
  const cm = _computeCm(ks);
  return _extractOddBytes(cm);
}
