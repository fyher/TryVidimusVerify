# verifier

Open-source verifier for **tryVidimus proof bundles** (MIT). It checks a proof **without trusting the server that gave it to you**:
every value that matters is recomputed here, never read from the bundle.

It depends only on `proof-primitives`; the two are published together.

> Status: not published to a registry yet. The package names below are the ones used inside the tryVidimus repository.

## What it checks

1. **The manifest** is rebuilt from the declared fingerprints and its SHA-256 recomputed.
2. **The timestamp token (RFC 3161)** carries the right value, is correctly signed, and, when you give a trust chain, was issued by an
   authority that chain validates:
   - **`direct` mode** (default): one token per proof; the token's message imprint is the manifest hash itself, so you can also check it
     with OpenSSL: `openssl ts -verify -digest <manifest_sha256> -in token.tsr -CAfile chain.pem`;
   - **`merkle_batch` mode** (legacy): one token for a batch of proofs; the proof's leaf is recomputed and must belong to the
     Merkle tree whose root the token certifies.
3. **Files** you provide (optional) must match the fingerprints in the bundle.
4. **The external reference commitment** is checked when you provide the salt and the reference.

```ts
import { verifyBundle } from '@repo/verifier';

const bundle = await (
  await fetch(`https://api.tryvidimus.com/v1/public/proofs/${id}/bundle`)
).json();
const result = await verifyBundle(bundle, { trustChainPem, qualifiedProfile, files });
// result.status: 'valid' | 'test_mode' | 'chain_unverified' | 'incomplete' | 'invalid'
```

| Verdict            | Meaning                                                                                       |
| ------------------ | --------------------------------------------------------------------------------------------- |
| `valid`            | Everything matches, the trust chain you provided validates the authority, real authority      |
| `test_mode`        | Everything matches but the timestamp is **simulated**: it has no legal value                  |
| `chain_unverified` | Everything matches but no trust chain validated the authority (none given, or not recognised) |
| `incomplete`       | The proof is not timestamped yet                                                              |
| `invalid`          | A check failed: never present the proof as valid                                              |

"Qualified" (eIDAS) and "trusted" are **recomputed** from the token and the profile you pass; the fields of the bundle are never believed.
Without a trust chain, a token is never reported as trusted or qualified.

## What is declared, never "verified"

`result.claims` reports what the proof announces, to be displayed with the right wording:

- `declaredByPlatform` (`party`, `stage`): declared by the platform that created the proof (`verified: false`);
- `media[].capturedAt`: the time **observed by the service**, not by the phone, and **not qualified** (`capturedAtQualified: false`).
  Only the timestamp (`timestamp.genTime`) proves that the proof existed "at the latest at this time";
- `mode`, `capture`, `generator`, `organizationId`.

The external reference of the dossier is never in the public bundle, only a commitment to it.

## Runtime

Node 22 or later, CommonJS build with TypeScript types (`import` works from ESM too). The one Node-specific call is a synchronous
SHA-256 (`node:crypto`) in `proof-primitives`; to run in a browser, alias `node:crypto` to a synchronous SHA-256 implementation
(the tryVidimus verification page does exactly that, and tests it against Node's for every length around the block boundaries).
Signature checks use the Web Crypto API.

## Golden proofs

`fixtures/golden/` holds sealed proofs **generated once** and then frozen, including real RFC 3161 tokens from FreeTSA that you can
verify with OpenSSL. Every future version of the verifier must keep validating them; they are never regenerated to make a test pass.

| Folder                    | Content                                                                      |
| ------------------------- | ---------------------------------------------------------------------------- |
| `direct-simulated-photo`  | `direct` mode, token from the **simulated** authority (test identity)        |
| `direct-freetsa-photo`    | `direct` mode, **real** FreeTSA token                                        |
| `direct-upload-simulated` | `direct` mode, direct upload, simulated authority                            |
| `simulated-photo-video`   | `merkle_batch` mode, photo and video, batch of 5 leaves, simulated authority |
| `freetsa-photo`           | `merkle_batch` mode, **real** FreeTSA token                                  |

Each folder: `bundle.json`, `dossier.json` (external reference and salt, given with the dossier), `trust-chain.pem`, `c2pa-anchors.pem`
and `media/`. The test identities ("Proof Test") are throwaway and carry no secret.

## License

MIT.
