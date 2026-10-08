import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { MediaFiles } from '../src/index';

const goldenDir = join(import.meta.dirname, '../fixtures/golden');

export type Golden = {
  bundle: Record<string, any>;
  trustChainPem: string;
  files: MediaFiles[];
  /** Ce que le dossier révèle : jamais dans le paquet public. */
  dossier: { external_reference: string; salt_hex: string };
};

const read = (dir: string, ...path: string[]): Buffer =>
  readFileSync(join(goldenDir, dir, ...path));

export function loadGolden(name: (typeof GOLDEN_NAMES)[number]): Golden {
  const bundle = JSON.parse(read(name, 'bundle.json').toString('utf8')) as Golden['bundle'];
  const file = (kind: 'photo' | 'video', role: 'original' | 'signed'): Uint8Array => {
    const extension = kind === 'photo' ? 'jpg' : 'mp4';
    return new Uint8Array(read(name, 'media', `${kind}.${role}.${extension}`));
  };
  const files: MediaFiles[] = (bundle['media'] as { media_type: 'photo' | 'video' }[]).map((m) => ({
    original: file(m.media_type, 'original'),
    signed: file(m.media_type, 'signed'),
  }));
  const dossier = JSON.parse(read(name, 'dossier.json').toString('utf8')) as Golden['dossier'];
  return { bundle, trustChainPem: read(name, 'trust-chain.pem').toString('utf8'), files, dossier };
}

export const GOLDEN_NAMES = [
  'simulated-photo-video',
  'freetsa-photo',
  'direct-upload-simulated',
] as const;

/** Copie profonde modifiable d'un paquet. */
export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
