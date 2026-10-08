import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { canonicalJson } from '../src/index';
import { loadJson } from './vectors';

describe('canonicalJson', () => {
  it.each(loadJson<{ input: unknown; expected: string }[]>('canonical-json.json'))(
    'reproduit le vecteur de référence $expected',
    ({ input, expected }) => {
      expect(canonicalJson(input)).toBe(expected);
    },
  );

  it('ne dépend pas de l’ordre d’insertion des clés', () => {
    expect(canonicalJson({ a: 1, b: { d: 1, c: 2 } })).toBe(
      canonicalJson({ b: { c: 2, d: 1 }, a: 1 }),
    );
  });

  it('respecte toJSON (les dates sont sérialisées en ISO)', () => {
    const date = new Date('2026-09-30T10:00:00.000Z');
    expect(canonicalJson({ at: date })).toBe('{"at":"2026-09-30T10:00:00.000Z"}');
  });

  it('produit un JSON valide qui relit la même valeur', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(JSON.parse(canonicalJson(value))).toEqual(JSON.parse(JSON.stringify(value)));
      }),
    );
  });

  it('est stable : deux appels donnent la même sortie', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => canonicalJson(value) === canonicalJson(value)),
    );
  });
});
