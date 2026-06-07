# @ntag424/crypto

NTAG424 DNA cryptographic primitives for boltcard authentication. Extracted from the [boltcard-cloudflareworker](https://github.com/nicobailon/boltcard-cloudflareworker) project.

Designed for Cloudflare Workers, browsers, and Node.js. Zero native dependencies.

## Install

```bash
npm install @ntag424/crypto
```

## Quick Example

```typescript
import { deriveKeysFromHex, hexToBytes, verifyCmac, decodeAndValidate } from "@ntag424/crypto";

// Derive card keys from UID + issuer key
const keys = deriveKeysFromHex("04a39493cc8680", "00000000000000000000000000000001");

// Validate a bolt card tap (p= encrypted payload, c= CMAC)
const k1Keys = [hexToBytes(keys.k1)];
const k2Bytes = hexToBytes(keys.k2);
const result = decodeAndValidate(pHex, cHex, k1Keys, k2Bytes);

if (result.success && result.cmac_validated) {
  console.log("Valid tap from card:", result.uidHex);
}
```

## API Reference

### Hex Utilities

- **`hexToBytes(hex)`** — Convert hex string to `Uint8Array`. Throws on invalid input.
- **`bytesToHex(bytes)`** — Convert `Uint8Array` or iterable to lowercase hex string.

### AES-CMAC (RFC 4493)

- **`computeAesCmac(message, key)`** — Single-block AES-CMAC. Key must be 16 bytes. Message must be ≤ 16 bytes. Returns 16-byte `Uint8Array`.

### Key Derivation

- **`deriveKeysFromHex(uidHex, issuerKeyHex, version?)`** — Deterministic key derivation for NTAG424 DNA cards. Returns `{ k0, k1, k2, k3, k4, cardKey }` (all hex strings). Default version is 1.

### Decryption

- **`decryptP(pHex, k1Keys)`** — AES-ECB decrypt the `p=` parameter from an NTAG424 tap. Tries each K1 candidate. Returns `{ success: true, uidBytes, ctr, usedK1 }` or `{ success: false }`.

### CMAC Verification

- **`verifyCmac(uidBytes, ctr, cHex, k2Bytes)`** — Verify the `c=` CMAC parameter using constant-time comparison. Returns `{ cmac_validated, cmac_error }`.
- **`buildVerificationData(uidBytes, ctr, k2Bytes)`** — Build sv2, ks, cm, ct for verification. Returns `{ sv2, ks, cm, ct }`.

### High-Level Convenience

- **`extractUIDAndCounter(pHex, k1Keys)`** — Decrypt `p=` and return `{ uidHex, ctr }` as hex strings.
- **`validateCmac(uidBytes, ctr, cHex, k2Bytes)`** — Validate CMAC with null-safety for inputs.
- **`decodeAndValidate(pHex, cHex, k1Keys, k2Bytes?)`** — Full pipeline: decrypt `p=` + verify `c=` CMAC.

### Version Scanning

- **`cmacScanVersions(uidBytes, ctrBytes, cHex, opts)`** — Scan a version range for CMAC match. Useful for detecting which key version a card was programmed with.

## License

MIT
