import { describe, expect, it } from 'vitest';

import { verifyBundle } from '../src/index';
import { GOLDEN_NAMES, loadGolden } from './golden';

// Golden proofs (docs/testing.md) : chaque version future du vérificateur doit continuer à les valider.
// Leurs fichiers ne sont jamais régénérés ni modifiés pour faire passer ce test.
const EXPECTED = {
  'simulated-photo-video': { status: 'test_mode', simulated: true },
  'freetsa-photo': { status: 'valid', simulated: false },
  // envoi direct : pas de session de capture (session_id nul)
  'direct-upload-simulated': { status: 'test_mode', simulated: true },
} as const;

describe.each(GOLDEN_NAMES)('golden proof %s', (name) => {
  const golden = loadGolden(name);
  const expected = EXPECTED[name];

  it('est vérifiée de bout en bout, fichiers compris', async () => {
    const result = await verifyBundle(golden.bundle, {
      trustChainPem: golden.trustChainPem,
      files: golden.files,
    });
    expect(result.errors).toEqual([]);
    expect(result.status).toBe(expected.status);
    expect(result.checks).toMatchObject({
      schema: { ok: true },
      manifestHash: { ok: true },
      inclusion: { ok: true },
      timestamp: { ok: true },
    });
    expect(result.timestamp).toMatchObject({
      trusted: true,
      simulated: expected.simulated,
      qualified: false,
    });
    for (const media of result.checks.media) {
      expect(media.original).toEqual({ ok: true });
      expect(media.signed).toEqual({ ok: true });
    }
  });

  it('sans chaîne de confiance, la confiance n’est jamais présumée', async () => {
    const result = await verifyBundle(golden.bundle);
    expect(result.status).toBe(expected.simulated ? 'test_mode' : 'chain_unverified');
    expect(result.timestamp?.trusted).toBeNull();
  });

  it('recalcule « qualifié » lui-même : le champ du paquet est ignoré', async () => {
    const forged = structuredClone(golden.bundle);
    forged['batch'].qualified = true;
    const result = await verifyBundle(forged, { trustChainPem: golden.trustChainPem });
    expect(result.timestamp?.qualified).toBe(false);
  });
});

describe('formats', () => {
  it('conserve la version 1 du manifeste : la feuille de la golden simulée est celle figée', async () => {
    const { bundle } = loadGolden('simulated-photo-video');
    expect(bundle['manifest_sha256']).toBe(
      '354a2e2c773daadfd159ca12bba4d45ca7d3bc0bd29cf3921fd4295ca3b47009',
    );
  });
});

describe.each(GOLDEN_NAMES)('golden proof %s : déclarations et confidentialité', (name) => {
  const golden = loadGolden(name);

  it('l’engagement de la référence externe se vérifie avec le sel du dossier', async () => {
    const result = await verifyBundle(golden.bundle, {
      trustChainPem: golden.trustChainPem,
      externalReference: {
        salt: golden.dossier.salt_hex,
        reference: golden.dossier.external_reference,
      },
    });
    expect(result.checks.externalReference).toEqual({ ok: true });
    expect(result.status).not.toBe('invalid');
  });

  it('une autre référence, ou un autre sel, est refusé', async () => {
    const wrongReference = await verifyBundle(golden.bundle, {
      externalReference: { salt: golden.dossier.salt_hex, reference: 'booking-autre' },
    });
    expect(wrongReference.status).toBe('invalid');
    expect(wrongReference.checks.externalReference?.ok).toBe(false);
    const wrongSalt = await verifyBundle(golden.bundle, {
      externalReference: { salt: '00'.repeat(32), reference: golden.dossier.external_reference },
    });
    expect(wrongSalt.status).toBe('invalid');
  });

  it('sans le dossier, l’engagement n’est pas contrôlé (jamais présumé)', async () => {
    const result = await verifyBundle(golden.bundle, { trustChainPem: golden.trustChainPem });
    expect(result.checks.externalReference).toBeNull();
  });

  it('le paquet public ne contient ni la référence externe ni le sel', () => {
    const text = JSON.stringify(golden.bundle);
    expect(text).not.toContain(golden.dossier.external_reference);
    expect(text).not.toContain(golden.dossier.salt_hex);
  });

  it('restitue les déclarations sans jamais les présenter comme vérifiées', async () => {
    const { claims } = await verifyBundle(golden.bundle, { trustChainPem: golden.trustChainPem });
    expect(claims?.declaredByPlatform.verified).toBe(false);
    expect(claims?.declaredByPlatform.party).toBe(golden.bundle['declared_by_platform'].party);
    expect(claims?.organizationId).toBe('org_golden');
    expect(claims?.mode).toBe('test');
    expect(claims?.capture.method).toBe(golden.bundle['capture'].method);
    expect(claims?.generator).toEqual({ name: 'Proof Capture', version: 'golden-1' });
    for (const media of claims?.media ?? []) {
      expect(media.capturedAt).toBe('2026-09-30T11:59:58.000Z');
      // heure observée par le service : jamais qualifiée, contrairement à gen_time du jeton
      expect(media.capturedAtQualified).toBe(false);
    }
  });
});

describe('golden proof historique : direct_upload avec un identifiant de session', () => {
  // Les premières golden proofs portent un identifiant de session pour direct_upload : le format le tolère et elles
  // doivent rester valides pour toujours.
  it('freetsa-photo reste valide', async () => {
    const golden = loadGolden('freetsa-photo');
    expect(golden.bundle['capture']).toEqual({
      method: 'direct_upload',
      session_id: 'cps_freetsa_photo',
    });
    expect(
      (await verifyBundle(golden.bundle, { trustChainPem: golden.trustChainPem })).status,
    ).toBe('valid');
  });

  it('direct-upload-simulated n’a pas de session', () => {
    expect(loadGolden('direct-upload-simulated').bundle['capture']).toEqual({
      method: 'direct_upload',
      session_id: null,
    });
  });
});
