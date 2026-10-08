import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { verifyBundle } from '../src/index';
import { clone, loadGolden } from './golden';
import {
  DIRECT_GOLDEN_NAMES,
  goldenTokenPath,
  loadDirectGolden,
  type DirectGoldenName,
} from './golden-direct';

// Golden proofs du mode `direct` (ADR-0026) : un jeton par preuve, dont l'empreinte est le condensat du manifeste. Elles doivent
// rester valides à chaque version du vérificateur, comme celles du mode par lot.
const EXPECTED = {
  'direct-freetsa-photo': { status: 'valid', simulated: false },
  'direct-simulated-photo': { status: 'test_mode', simulated: true },
} as const;

describe.each(DIRECT_GOLDEN_NAMES)('golden proof %s (mode direct)', (name) => {
  const golden = loadDirectGolden(name);
  const expected = EXPECTED[name];

  it('est vérifiée de bout en bout, fichiers compris, sans arbre de Merkle', async () => {
    const result = await verifyBundle(golden.bundle, {
      trustChainPem: golden.trustChainPem,
      files: golden.files,
    });
    expect(result.errors).toEqual([]);
    expect(result.status).toBe(expected.status);
    expect(result.checks).toMatchObject({
      schema: { ok: true },
      manifestHash: { ok: true },
      inclusion: null,
      timestamp: { ok: true },
    });
    expect(result.timestamp).toMatchObject({
      mode: 'direct',
      trusted: true,
      simulated: expected.simulated,
      qualified: false,
    });
    for (const media of result.checks.media) {
      expect(media.original).toEqual({ ok: true });
      expect(media.signed).toEqual({ ok: true });
    }
  });

  it('le paquet direct ne porte ni chemin ni index', () => {
    expect(golden.bundle['timestamp']).not.toHaveProperty('merkle_path');
    expect(golden.bundle['timestamp']).not.toHaveProperty('leaf_index');
    expect(golden.bundle['timestamp'].mode).toBe('direct');
    expect(golden.bundle['batch']).toBeUndefined();
  });

  it('sans chaîne de confiance, la confiance n’est jamais présumée', async () => {
    const result = await verifyBundle(golden.bundle);
    expect(result.status).toBe(expected.simulated ? 'test_mode' : 'chain_unverified');
    expect(result.timestamp?.trusted).toBeNull();
  });

  it('recalcule « qualifié » lui-même : le champ du paquet est ignoré', async () => {
    const forged = clone(golden.bundle);
    forged['timestamp'].qualified = true;
    const result = await verifyBundle(forged, { trustChainPem: golden.trustChainPem });
    expect(result.timestamp?.qualified).toBe(false);
  });

  it('un champ déclaré modifié change le condensat recalculé : preuve invalide', async () => {
    const forged = clone(golden.bundle);
    forged['generator'].version = 'falsifie-9';
    const result = await verifyBundle(forged, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('invalid');
    expect(result.checks.manifestHash).toMatchObject({ ok: false });
  });

  it('un manifest_sha256 falsifié (le jeton ne porte plus le condensat recalculé) : invalide', async () => {
    const forged = clone(golden.bundle);
    forged['manifest_sha256'] = 'a'.repeat(64);
    const result = await verifyBundle(forged, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('invalid');
  });

  it('un jeton rejoué venant d’une autre preuve est rejeté (empreinte différente)', async () => {
    const other = loadDirectGolden(
      name === 'direct-freetsa-photo' ? 'direct-simulated-photo' : 'direct-freetsa-photo',
    );
    const forged = clone(golden.bundle);
    forged['timestamp'].tsr_base64 = other.bundle['timestamp'].tsr_base64;
    const result = await verifyBundle(forged, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('invalid');
    expect(result.checks.timestamp).toMatchObject({ ok: false });
  });

  it('une chaîne étrangère ne donne jamais la confiance', async () => {
    const foreign = loadDirectGolden(
      name === 'direct-freetsa-photo' ? 'direct-simulated-photo' : 'direct-freetsa-photo',
    ).trustChainPem;
    const result = await verifyBundle(golden.bundle, { trustChainPem: foreign });
    expect(result.status).toBe('invalid');
  });

  it('un mode annoncé qui ne correspond pas au contenu est refusé : `merkle_batch` sans arbre', async () => {
    const lying = clone(golden.bundle);
    lying['timestamp'].mode = 'merkle_batch';
    const result = await verifyBundle(lying, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('invalid');
    expect(result.checks.schema.ok).toBe(false);
  });

  it('timestamp et batch ensemble : paquet ambigu, refusé', async () => {
    const both = clone(golden.bundle);
    both['batch'] = clone(loadGolden('freetsa-photo').bundle['batch']);
    const result = await verifyBundle(both, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('invalid');
    expect(result.checks.schema.ok).toBe(false);
  });

  it('pas d’horodatage encore : « incomplete », avec ou sans le champ', async () => {
    for (const mutate of [
      (bundle: Record<string, any>) => ((bundle['timestamp'] = null), bundle),
      (bundle: Record<string, any>) => (delete bundle['timestamp'], bundle),
    ]) {
      const pending = mutate(clone(golden.bundle));
      const result = await verifyBundle(pending);
      expect(result.status).toBe('incomplete');
    }
  });

  it('l’heure ou le numéro de série du paquet qui diffèrent de ceux du jeton sont signalés', async () => {
    const forged = clone(golden.bundle);
    forged['timestamp'].gen_time = '2020-01-01T00:00:00.000Z';
    const result = await verifyBundle(forged, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('invalid');
  });
});

describe('les deux modes se côtoient', () => {
  it('une golden proof au format antérieur (`batch`) est lue comme `merkle_batch`, avec son arbre', async () => {
    const golden = loadGolden('freetsa-photo');
    const result = await verifyBundle(golden.bundle, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('valid');
    expect(result.timestamp?.mode).toBe('merkle_batch');
    expect(result.checks.inclusion).toEqual({ ok: true });
  });

  it('le même paquet au format `timestamp` en mode `merkle_batch` donne le même verdict', async () => {
    const golden = loadGolden('freetsa-photo');
    const converted = clone(golden.bundle);
    converted['timestamp'] = { mode: 'merkle_batch', ...converted['batch'] };
    delete converted['batch'];
    const result = await verifyBundle(converted, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('valid');
    expect(result.timestamp?.mode).toBe('merkle_batch');
  });

  it('un jeton de lot ne passe pas pour un jeton direct (conventions d’empreinte distinctes)', async () => {
    const golden = loadGolden('freetsa-photo');
    const forged = clone(golden.bundle);
    forged['timestamp'] = {
      mode: 'direct',
      tsr_base64: forged['batch'].tsr_base64,
      authority: forged['batch'].authority,
      gen_time: forged['batch'].gen_time,
      serial: forged['batch'].serial,
      policy_oid: forged['batch'].policy_oid,
    };
    delete forged['batch'];
    const result = await verifyBundle(forged, { trustChainPem: golden.trustChainPem });
    expect(result.status).toBe('invalid');
  });
});

const hasOpenssl = spawnSync('openssl', ['version']).status === 0;

describe.skipIf(!hasOpenssl).each(DIRECT_GOLDEN_NAMES)(
  'interopérabilité OpenSSL : le jeton de %s',
  (name: DirectGoldenName) => {
    it('`openssl ts -verify -digest <manifest_sha256>` l’accepte, sans connaître notre format', () => {
      const golden = loadDirectGolden(name);
      const dir = mkdtempSync(join(tmpdir(), 'golden-'));
      try {
        writeFileSync(
          join(dir, 'token.tsr'),
          Buffer.from(golden.bundle['timestamp'].tsr_base64, 'base64'),
        );
        const out = execFileSync(
          'openssl',
          [
            'ts',
            '-verify',
            '-digest',
            golden.bundle['manifest_sha256'],
            '-in',
            join(dir, 'token.tsr'),
            '-CAfile',
            goldenTokenPath(name),
          ],
          { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
        );
        expect(out).toContain('Verification: OK');
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  },
);
