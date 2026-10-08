# proof-primitives

SHA-256, canonical JSON, Merkle tree (build, inclusion proof, verification) and RFC 3161 timestamp request and token handling.
**Open source (MIT), no internal dependency**: the verifier and the sealing code both build on it.

> Status: not published to a registry yet.

## Contents

| Module           | Role                                                                                                                  |
| ---------------- | --------------------------------------------------------------------------------------------------------------------- |
| `hash`           | `sha256Hex`, `isSha256Hex`, `hexToBytes`, `bytesToHex`                                                                |
| `canonical-json` | `canonicalJson`: sorted keys, `toJSON` honoured                                                                       |
| `merkle`         | `buildTree`, `inclusionProof`, `verifyInclusion` (an odd leaf is duplicated at each level)                            |
| `rfc3161`        | `buildTimeStampReq`, `parseTimeStampResp`, `verifyTimeStampToken`, `CERTIGNA_QUALIFIED_PROFILE`                       |
| `imprint`        | the two imprint conventions: `hash-of-data` (hash of the data) and `digest` (the value itself, used by `direct` mode) |

Design rules: configuration is injected (no `process.env`, no `console`, no disk access), and **`trusted` is true only when the trust
chain you provide validates the authority's certificate, at the token's time**. A foreign chain never produces trust.

## Fixtures

`fixtures/vectors/*.json` are shared test vectors (SHA-256, canonical JSON, Merkle trees). `fixtures/tsa/` holds a throwaway test
authority and real FreeTSA tokens, one of them in `digest` convention, checked with OpenSSL.

## Runtime

Node 22 or later (CommonJS build with TypeScript types). The only Node-specific call is the synchronous SHA-256 from `node:crypto`; in
a browser, alias it to a synchronous SHA-256 implementation.

## License

MIT.
