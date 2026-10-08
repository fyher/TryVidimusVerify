import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { leafOf, verifyBundle, type ProofBundle } from '../src/index';
import { clone, loadGolden } from './golden';

const golden = loadGolden('simulated-photo-video');
const freetsa = loadGolden('freetsa-photo');
const options = { trustChainPem: golden.trustChainPem, files: golden.files };

async function statusOf(bundle: unknown, extra = {}): Promise<string> {
  return (await verifyBundle(bundle, { ...options, ...extra })).status;
}

describe('altération du paquet', () => {
  it.each([
    ['une empreinte de fichier', (b: any) => (b.media[0].original_sha256 = 'a'.repeat(64))],
    ['l’identifiant de preuve', (b: any) => (b.proof_id = 'prf_autre')],
    ['manifest_sha256', (b: any) => (b.manifest_sha256 = 'b'.repeat(64))],
    ['la version de clé', (b: any) => (b.media[0].key_version = 'autre')],
    ['l’ordre des fichiers', (b: any) => b.media.reverse()],
    ['la position dans l’arbre', (b: any) => (b.batch.leaf_index = 0)],
    ['un pas du chemin', (b: any) => (b.batch.merkle_path[0].hash = 'c'.repeat(64))],
    [
      'un côté du chemin',
      (b: any) =>
        (b.batch.merkle_path[0].position =
          b.batch.merkle_path[0].position === 'left' ? 'right' : 'left'),
    ],
    ['la racine', (b: any) => (b.batch.merkle_root = 'd'.repeat(64))],
    ['l’heure', (b: any) => (b.batch.gen_time = '2026-01-01T00:00:00.000Z')],
    ['le numéro de série', (b: any) => (b.batch.serial = 'ffff')],
    [
      'le jeton (octets)',
      (b: any) =>
        (b.batch.tsr_base64 = b.batch.tsr_base64.replace(/.$/, 'A').slice(0, -8) + 'AAAAAAAA'),
    ],
    ['le jeton (illisible)', (b: any) => (b.batch.tsr_base64 = 'AAAA')],
  ])('%s ⇒ invalide', async (_label, mutate) => {
    const bundle = clone(golden.bundle);
    mutate(bundle);
    expect(await statusOf(bundle)).toBe('invalid');
  });

  it('un jeton d’une autre preuve ne valide pas celle-ci', async () => {
    const bundle = clone(golden.bundle);
    bundle['batch'].tsr_base64 = freetsa.bundle['batch'].tsr_base64;
    expect(await statusOf(bundle)).toBe('invalid');
  });

  it('une chaîne de confiance étrangère ⇒ invalide', async () => {
    expect(await statusOf(golden.bundle, { trustChainPem: freetsa.trustChainPem })).toBe('invalid');
  });

  it('toute modification d’un octet d’empreinte est détectée', () => {
    const fields = [
      'manifest_sha256',
      'media.0.original_sha256',
      'media.0.signed_sha256',
      'batch.merkle_root',
    ];
    return fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...fields),
        fc.integer({ min: 0, max: 63 }),
        async (field, position) => {
          const bundle = clone(golden.bundle);
          const holder = field
            .split('.')
            .slice(0, -1)
            .reduce((node: any, key) => node[key === 'batch' ? 'batch' : key], bundle);
          const key = field.split('.').at(-1) as string;
          const current: string = holder[key];
          holder[key] =
            current.slice(0, position) +
            (current[position] === '0' ? '1' : '0') +
            current.slice(position + 1);
          expect(['invalid']).toContain(await statusOf(bundle));
        },
      ),
      { numRuns: 40 },
    );
  });
});

describe('fichiers', () => {
  it('un original modifié ⇒ invalide', async () => {
    const files = clone(
      golden.files.map((f) => ({
        original: Array.from(f.original ?? []),
        signed: Array.from(f.signed ?? []),
      })),
    );
    files[0]!.original[10] = (files[0]!.original[10] as number) ^ 1;
    const modified = files.map((f) => ({
      original: new Uint8Array(f.original),
      signed: new Uint8Array(f.signed),
    }));
    const result = await verifyBundle(golden.bundle, {
      trustChainPem: golden.trustChainPem,
      files: modified,
    });
    expect(result.status).toBe('invalid');
    expect(result.checks.media[0]?.original?.ok).toBe(false);
  });

  it('une copie signée échangée ⇒ invalide', async () => {
    const files = [{ ...golden.files[0], signed: golden.files[1]?.signed }, golden.files[1]];
    const result = await verifyBundle(golden.bundle, {
      trustChainPem: golden.trustChainPem,
      files,
    });
    expect(result.checks.media[0]?.signed?.ok).toBe(false);
    expect(result.status).toBe('invalid');
  });

  it('les fichiers sont facultatifs', async () => {
    const result = await verifyBundle(golden.bundle, { trustChainPem: golden.trustChainPem });
    expect(result.checks.media.every((m) => m.original === null && m.signed === null)).toBe(true);
    expect(result.status).toBe('test_mode');
  });

  it('applique la vérification de signature C2PA injectée', async () => {
    const seen: string[] = [];
    const ok = await verifyBundle(golden.bundle, {
      ...options,
      verifyMedia: (_bytes, type) => {
        seen.push(type);
        return Promise.resolve({ ok: true });
      },
    });
    expect(seen).toEqual(['photo', 'video']);
    expect(ok.status).toBe('test_mode');
    const ko = await verifyBundle(golden.bundle, {
      ...options,
      verifyMedia: () => Promise.resolve({ ok: false, detail: 'manifeste invalide' }),
    });
    expect(ko.status).toBe('invalid');
  });
});

describe('forme du paquet', () => {
  it.each([
    ['null', null],
    ['une chaîne', 'x'],
    ['un objet vide', {}],
  ])('%s ⇒ invalide, avec une erreur lisible', async (_label, input) => {
    const result = await verifyBundle(input);
    expect(result.status).toBe('invalid');
    expect(result.checks.schema.ok).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('refuse une empreinte mal formée et un paquet sans fichier', async () => {
    const bad = clone(golden.bundle);
    bad['media'][0].signed_sha256 = 'XYZ';
    expect((await verifyBundle(bad)).errors.join(' ')).toContain('media.0.signed_sha256');
    const none = clone(golden.bundle);
    none['media'] = [];
    expect((await verifyBundle(none)).status).toBe('invalid');
  });

  it('ignore les champs inconnus (un paquet plus récent reste lisible)', async () => {
    const bundle = clone(golden.bundle);
    bundle['nouveau_champ'] = { a: 1 };
    bundle['batch'].autre = true;
    expect(await statusOf(bundle)).toBe('test_mode');
  });

  it('sans lot horodaté : incomplet, mais toujours contrôlé', async () => {
    const pending = clone(golden.bundle);
    pending['batch'] = null;
    expect((await verifyBundle(pending)).status).toBe('incomplete');
    pending['media'][0].original_sha256 = 'a'.repeat(64);
    expect((await verifyBundle(pending)).status).toBe('invalid');
  });

  it('expose la feuille recalculée', () => {
    expect(leafOf(golden.bundle as ProofBundle)).toBe(golden.bundle['manifest_sha256']);
  });
});

describe('cohérence de leaf_index', () => {
  it('accepte l’index d’origine de chaque golden', async () => {
    for (const g of [golden, freetsa]) {
      const result = await verifyBundle(g.bundle, { trustChainPem: g.trustChainPem });
      expect(result.checks.inclusion).toEqual({ ok: true });
    }
  });

  it('un index qui contredit le chemin est signalé, même si le chemin mène à la racine', async () => {
    const bundle = clone(golden.bundle);
    bundle['batch'].leaf_index = 3;
    const result = await verifyBundle(bundle, options);
    expect(result.checks.inclusion?.detail).toContain('leaf_index');
    expect(result.status).toBe('invalid');
  });
});

describe('champs engagés par le manifeste', () => {
  it.each([
    ['organization_id', (b: any) => (b.organization_id = 'org_autre')],
    ['mode', (b: any) => (b.mode = 'live')],
    [
      'external_reference_commitment',
      (b: any) => (b.external_reference_commitment = 'e'.repeat(64)),
    ],
    ['party', (b: any) => (b.declared_by_platform.party = 'recipient')],
    ['stage', (b: any) => (b.declared_by_platform.stage = 'check_out')],
    ['capture.method', (b: any) => (b.capture = { method: 'direct_upload', session_id: null })],
    ['capture.session_id', (b: any) => (b.capture.session_id = 'cps_autre')],
    ['generator.name', (b: any) => (b.generator.name = 'Autre')],
    ['generator.version', (b: any) => (b.generator.version = '9')],
    ['media[0].captured_at', (b: any) => (b.media[0].captured_at = '2026-01-01T00:00:00.000Z')],
    ['media[0].mime_type', (b: any) => (b.media[0].mime_type = 'image/png')],
    ['media[0].byte_size', (b: any) => (b.media[0].byte_size += 1)],
  ])('modifier %s invalide la preuve (la feuille recalculée change)', async (_field, mutate) => {
    const bundle = clone(golden.bundle);
    mutate(bundle);
    const result = await verifyBundle(bundle, options);
    expect(result.status).toBe('invalid');
    expect(result.checks.manifestHash?.ok).toBe(false);
  });

  it.each([
    ['version inconnue', (b: any) => (b.version = 2)],
    ['stage libre', (b: any) => (b.declared_by_platform.stage = 'Jean Dupont')],
    ['party inconnue', (b: any) => (b.declared_by_platform.party = 'tiers')],
    ['mode inconnu', (b: any) => (b.mode = 'prod')],
    ['méthode inconnue', (b: any) => (b.capture.method = 'email')],
    ['captured_at non canonique', (b: any) => (b.media[0].captured_at = '2026-09-30T12:00:00Z')],
    ['byte_size nul', (b: any) => (b.media[0].byte_size = 0)],
    ['champ obligatoire absent', (b: any) => delete b.organization_id],
  ])('refuse %s sans lever d’exception', async (_label, mutate) => {
    const bundle = clone(golden.bundle);
    mutate(bundle);
    const result = await verifyBundle(bundle, options);
    expect(result.status).toBe('invalid');
    expect(result.checks.schema.ok).toBe(false);
  });
});
