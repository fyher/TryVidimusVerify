import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { loadGolden, type Golden } from './golden';

// Les preuves de référence du mode `direct` (ADR-0026). Chargées comme les autres ; leurs fichiers ne sont jamais régénérés.
export const DIRECT_GOLDEN_NAMES = ['direct-freetsa-photo', 'direct-simulated-photo'] as const;
export type DirectGoldenName = (typeof DIRECT_GOLDEN_NAMES)[number];

export const loadDirectGolden = (name: DirectGoldenName): Golden =>
  loadGolden(name as unknown as Parameters<typeof loadGolden>[0]);

export const goldenTokenPath = (name: DirectGoldenName): string =>
  join(import.meta.dirname, '../fixtures/golden', name, 'trust-chain.pem');

export const readTrustChain = (name: DirectGoldenName): string =>
  readFileSync(goldenTokenPath(name), 'utf8');
