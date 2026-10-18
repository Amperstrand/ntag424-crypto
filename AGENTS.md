# AGENTS.md — ntag424-crypto

**Line canon**: this repo is one node of the boltcard line. The canonical
doctrine — repo map, SUN read-path architecture, the vectors-as-oracle
conformance rule, bench touchpoints — lives in
[ntag424-vectors/AGENTS.md](https://github.com/Amperstrand/ntag424-vectors/blob/main/AGENTS.md).
The oracle rule in one line: **every implementation passes every
`vectors.json` vector its API can express, skips are counted aloud,
vendored copies must not drift** (enforced by that repo's CI, issue #1).

## Purpose

NTAG424 DNA cryptographic primitives for boltcard authentication, pure
TypeScript with zero native dependencies — extracted from
boltcard-cloudflareworker so the worker, the browser, Node.js, and the
test rig all share one implementation of: deterministic key derivation
(`deriveKeysFromHex`), SDM PICC decrypt + SUN CMAC verify
(`decodeAndValidate`, `verifyCmac`), and the AES-CMAC core (RFC 4493).

Position in the read path: the worker's `GET /?p=..&c=..` handler calls
this package to turn `p`/`c` into a verdict. The package is deliberately
narrow — no routes, no KV, no payments; keep it that way.

## Build / test

```bash
npm install
npm run build     # tsc
npm test          # vitest run
```

- The test suite includes the AN12196 and RFC 4493 tables **and** a
  vendored copy of the canonical `vectors.json` — the vendored copy is a
  conformance artifact: it must move only in lockstep with
  Amperstrand/ntag424-vectors (drift = CI failure there, issue #1).
- The consumer-side wiring now exists end-to-end: the worker runs the
  full 46-vector suite against this package + its keygenerator
  composition (boltcard-cloudflareworker#68 — `npm run vectors:check`,
  reference-locked copy + sha256 assert). A change here that would break
  a vector is visible in the worker's CI, not just this repo's.
- CI gate (issue #3): test + typecheck + publish dry-run. Package
  graduation (license, security policy, dependency policy, releases) is
  issue #5 — check its state before changing packaging metadata.

## Rules for agents

- Crypto changes are conformance changes: run the vectors, count skips,
  and if a category becomes newly expressible, wire it in — a silent
  skip regression is a failure.
- Never add native dependencies; the Cloudflare-Workers/browser/Node
  portability contract is the point of the extraction.
- No secrets in tests or examples: the `0000…0001` issuer key is the
  documented public dev fallback; production keys have no business here
  (worker issue #59 pins the same rule for docs).
- Key-derivation semantics must stay byte-identical to the worker's
  `keygenerator.ts` and to the `derivation` vectors — three-way
  agreement, oracles decided by provenance (see the canon).
