import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = join(import.meta.dirname, '../fixtures');

export function loadJson<T>(name: string): T {
  return JSON.parse(readFileSync(join(dir, 'vectors', name), 'utf8')) as T;
}

export function loadTsa(name: string): Uint8Array {
  return new Uint8Array(readFileSync(join(dir, 'tsa', name)));
}

export function loadTsaText(name: string): string {
  return readFileSync(join(dir, 'tsa', name), 'utf8').trim();
}
