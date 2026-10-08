# TryVidimusVerify

Open-source verifier for **tryVidimus proofs**. A proof is a signed, timestamped set of photos or videos; this code checks one
**without trusting the server that gave it to you**: every value that matters is recomputed here, never read from the bundle.

| Package | What it is |
| --- | --- |
| [`verifier`](packages/verifier) | Checks a proof bundle and returns a verdict (`valid`, `test_mode`, `chain_unverified`, `incomplete`, `invalid`). |
| [`proof-primitives`](packages/proof-primitives) | SHA-256, canonical JSON, Merkle trees, and RFC 3161 timestamp handling. |

> Status: not published to npm yet. The packages are used from this repository.

## Check a proof

1. Get the public bundle of a proof (no API key needed): `GET https://api.tryvidimus.com/v1/public/proofs/{id}/bundle`.
2. Run it through the verifier (see [the verifier README](packages/verifier/README.md)).

The same code runs in the browser on <https://verify.tryvidimus.com>. For a proof in `direct` mode you can also check the timestamp
with OpenSSL alone: `openssl ts -verify -digest <manifest_sha256> -in token.tsr -CAfile chain.pem`.

## Develop

```
pnpm install
pnpm typecheck && pnpm lint && pnpm test
pnpm build:npm
```

Node 22 or later. The `fixtures/golden` proofs are sealed proofs generated once and frozen, including real RFC 3161 tokens from FreeTSA:
every future version must keep validating them.

## Security

Please report vulnerabilities **privately** through GitHub (Security tab, "Report a vulnerability"), not in a public issue. See
[SECURITY.md](SECURITY.md).

## License

MIT, Copyright (c) 2026 Fyher.
