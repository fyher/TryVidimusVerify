import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  buildProofManifest,
  canonicalJson,
  commitExternalReference,
  PROOF_MANIFEST_VERSION,
  proofManifestSha256,
  sha256Hex,
  type ProofManifestInput,
  type ProofManifestMedia,
} from '../src/index';

const media = (n: number): ProofManifestMedia => ({
  media_type: n % 2 === 0 ? 'photo' : 'video',
  mime_type: n % 2 === 0 ? 'image/jpeg' : 'video/mp4',
  byte_size: 1000 + n,
  captured_at: '2026-09-30T12:00:00.000Z',
  original_sha256: sha256Hex(`original-${n}`),
  signed_sha256: sha256Hex(`signed-${n}`),
  manifest_id: `urn:uuid:${n}`,
  key_version: 'aws-kms-p256-v1',
});

const input = (overrides: Partial<ProofManifestInput> = {}): ProofManifestInput => ({
  proof_id: 'prf_vector',
  organization_id: 'org_vector',
  mode: 'test',
  external_reference_commitment: commitExternalReference('00'.repeat(32), 'booking-123'),
  declared_by_platform: { party: 'provider', stage: 'check_in' },
  capture: { method: 'hosted_live', session_id: 'cps_vector' },
  generator: { name: 'Proof Capture', version: '1.0.0' },
  media: [media(0), media(1)],
  ...overrides,
});

describe('buildProofManifest', () => {
  it('fixe la version et ne retient que les champs du format', () => {
    const extra = { ...media(0), status: 'sealed', uploaded_at: 'x' } as ProofManifestMedia;
    const manifest = buildProofManifest(input({ media: [extra] }));
    expect(manifest.version).toBe(PROOF_MANIFEST_VERSION);
    expect(Object.keys(manifest.media[0] as object).sort()).toEqual([
      'byte_size',
      'captured_at',
      'key_version',
      'manifest_id',
      'media_type',
      'mime_type',
      'original_sha256',
      'signed_sha256',
    ]);
    expect(Object.keys(manifest).sort()).toEqual([
      'capture',
      'declared_by_platform',
      'external_reference_commitment',
      'generator',
      'media',
      'mode',
      'organization_id',
      'proof_id',
      'version',
    ]);
  });

  it('direct_upload : session nulle acceptée, identifiant valide toléré (golden proofs historiques)', () => {
    expect(
      buildProofManifest(input({ capture: { method: 'direct_upload', session_id: 'cps_legacy' } }))
        .capture,
    ).toEqual({ method: 'direct_upload', session_id: 'cps_legacy' });
    const manifest = buildProofManifest(
      input({ capture: { method: 'direct_upload', session_id: null } }),
    );
    expect(manifest.capture).toEqual({ method: 'direct_upload', session_id: null });
  });

  it('accepte un stage nul', () => {
    const manifest = buildProofManifest(
      input({ declared_by_platform: { party: 'recipient', stage: null } }),
    );
    expect(manifest.declared_by_platform).toEqual({ party: 'recipient', stage: null });
  });

  it('refuse un manifeste sans fichier', () => {
    expect(() => buildProofManifest(input({ media: [] }))).toThrowError(
      expect.objectContaining({ code: 'EMPTY_MANIFEST' }),
    );
  });

  it.each([
    [
      'original_sha256 invalide',
      { media: [{ ...media(0), original_sha256: 'nope' }] },
      'INVALID_HEX',
    ],
    [
      'signed_sha256 en majuscules',
      { media: [{ ...media(0), signed_sha256: 'A'.repeat(64) }] },
      'INVALID_HEX',
    ],
    ['engagement invalide', { external_reference_commitment: 'zz' }, 'INVALID_HEX'],
    ['mode inconnu', { mode: 'prod' as never }, 'INVALID_MANIFEST'],
    [
      'party inconnue',
      { declared_by_platform: { party: 'tiers' as never, stage: null } },
      'INVALID_MANIFEST',
    ],
    [
      'stage libre (donnée personnelle possible)',
      { declared_by_platform: { party: 'provider' as const, stage: 'Jean Dupont' } },
      'INVALID_MANIFEST',
    ],
    [
      'méthode de capture inconnue',
      { capture: { method: 'email' as never, session_id: 's' } },
      'INVALID_MANIFEST',
    ],
    [
      'session_id vide',
      { capture: { method: 'hosted_live' as const, session_id: '' } },
      'INVALID_MANIFEST',
    ],
    ['organization_id avec espace', { organization_id: 'org 1' }, 'INVALID_MANIFEST'],
    [
      'générateur avec balise',
      { generator: { name: '<b>x</b>', version: '1' } },
      'INVALID_MANIFEST',
    ],
    ['mime_type sans slash', { media: [{ ...media(0), mime_type: 'jpeg' }] }, 'INVALID_MANIFEST'],
    ['byte_size nul', { media: [{ ...media(0), byte_size: 0 }] }, 'INVALID_MANIFEST'],
    ['byte_size fractionnaire', { media: [{ ...media(0), byte_size: 1.5 }] }, 'INVALID_MANIFEST'],
    [
      'captured_at sans millisecondes',
      { media: [{ ...media(0), captured_at: '2026-09-30T12:00:00Z' }] },
      'INVALID_MANIFEST',
    ],
    [
      'captured_at avec fuseau',
      { media: [{ ...media(0), captured_at: '2026-09-30T14:00:00.000+02:00' }] },
      'INVALID_MANIFEST',
    ],
    [
      'captured_at illisible',
      { media: [{ ...media(0), captured_at: 'hier' }] },
      'INVALID_MANIFEST',
    ],
    [
      'media_type inconnu',
      { media: [{ ...media(0), media_type: 'audio' as never }] },
      'INVALID_MANIFEST',
    ],
  ])('refuse %s', (_label, overrides, code) => {
    expect(() => buildProofManifest(input(overrides as Partial<ProofManifestInput>))).toThrowError(
      expect.objectContaining({ code }),
    );
  });
});

describe('proofManifestSha256', () => {
  it('vecteur figé : ne doit jamais changer (les feuilles Merkle existantes en dépendent)', () => {
    const manifest = buildProofManifest(input());
    const canonical = canonicalJson(manifest);
    expect(canonical).toBe(
      '{"capture":{"method":"hosted_live","session_id":"cps_vector"},' +
        '"declared_by_platform":{"party":"provider","stage":"check_in"},' +
        `"external_reference_commitment":"${commitExternalReference('00'.repeat(32), 'booking-123')}",` +
        '"generator":{"name":"Proof Capture","version":"1.0.0"},' +
        '"media":[' +
        `{"byte_size":1000,"captured_at":"2026-09-30T12:00:00.000Z","key_version":"aws-kms-p256-v1","manifest_id":"urn:uuid:0","media_type":"photo","mime_type":"image/jpeg","original_sha256":"${sha256Hex('original-0')}","signed_sha256":"${sha256Hex('signed-0')}"},` +
        `{"byte_size":1001,"captured_at":"2026-09-30T12:00:00.000Z","key_version":"aws-kms-p256-v1","manifest_id":"urn:uuid:1","media_type":"video","mime_type":"video/mp4","original_sha256":"${sha256Hex('original-1')}","signed_sha256":"${sha256Hex('signed-1')}"}],` +
        '"mode":"test","organization_id":"org_vector","proof_id":"prf_vector","version":1}',
    );
    expect(proofManifestSha256(manifest)).toBe(sha256Hex(canonical));
  });

  it('dépend de chaque champ engagé', () => {
    const hash = proofManifestSha256(buildProofManifest(input()));
    const variants: Partial<ProofManifestInput>[] = [
      { proof_id: 'prf_autre' },
      { organization_id: 'org_autre' },
      { mode: 'live' },
      { external_reference_commitment: sha256Hex('autre') },
      { declared_by_platform: { party: 'recipient', stage: 'check_in' } },
      { declared_by_platform: { party: 'provider', stage: 'check_out' } },
      { declared_by_platform: { party: 'provider', stage: null } },
      { capture: { method: 'direct_upload', session_id: null } },
      { capture: { method: 'hosted_live', session_id: 'cps_autre' } },
      { generator: { name: 'Proof Capture', version: '1.0.1' } },
      { media: [media(1), media(0)] },
      { media: [{ ...media(0), captured_at: '2026-09-30T12:00:00.001Z' }, media(1)] },
      { media: [{ ...media(0), byte_size: 1 }, media(1)] },
      { media: [{ ...media(0), mime_type: 'image/png' }, media(1)] },
      { media: [{ ...media(0), signed_sha256: sha256Hex('autre') }, media(1)] },
    ];
    for (const overrides of variants) {
      expect(proofManifestSha256(buildProofManifest(input(overrides)))).not.toBe(hash);
    }
  });

  it('est déterministe quel que soit l’ordre d’insertion des clés', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 5 }), (count) => {
        const files = Array.from({ length: count }, (_, i) => media(i));
        const a = buildProofManifest(input({ media: files }));
        const b = buildProofManifest(input({ media: files.map((m) => ({ ...m })) }));
        expect(proofManifestSha256(a)).toBe(proofManifestSha256(b));
      }),
    );
  });
});
