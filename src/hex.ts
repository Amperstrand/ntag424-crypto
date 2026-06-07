import { hex as scureHex } from "@scure/base";

export function hexToBytes(hex: string): Uint8Array {
  if (!hex || hex.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("Invalid hex string: contains non-hex characters");
  }
  return scureHex.decode(hex.toLowerCase());
}

export function bytesToHex(bytes: Uint8Array | Iterable<number>): string {
  return scureHex.encode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}
