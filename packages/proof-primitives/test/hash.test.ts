import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { bytesToHex, hexToBytes, isSha256Hex, PrimitiveError, sha256Hex } from '../src/index';
import { loadJson } from './vectors';

describe('sha256Hex', () => {
  it.each(loadJson<{ input: string; expected: string }[]>('sha256.json'))(
    'reproduit le vecteur de référence ($input.length caractères)',
    ({ input, expected }) => {
      expect(sha256Hex(input)).toBe(expected);
    },
  );

  it('donne le même résultat pour une chaîne UTF-8 et ses octets', () => {
    expect(sha256Hex(new TextEncoder().encode('é'))).toBe(sha256Hex('é'));
  });
});

describe('isSha256Hex', () => {
  it('accepte 64 caractères hexadécimaux minuscules', () => {
    expect(isSha256Hex(sha256Hex('x'))).toBe(true);
  });

  it.each(['', 'abc', 'A'.repeat(64), 'g'.repeat(64), 'a'.repeat(63), 'a'.repeat(65)])(
    'refuse %j',
    (value) => {
      expect(isSha256Hex(value)).toBe(false);
    },
  );
});

describe('hexToBytes / bytesToHex', () => {
  it('fait l’aller-retour pour tout tableau d’octets', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
      }),
    );
  });

  it.each(['abc', 'zz', 'g0'])('refuse l’hexadécimal invalide %j', (value) => {
    expect(() => hexToBytes(value)).toThrow(PrimitiveError);
    try {
      hexToBytes(value);
    } catch (error) {
      expect((error as PrimitiveError).code).toBe('INVALID_HEX');
    }
  });
});
