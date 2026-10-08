import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  COMMITMENT_SALT_BYTES,
  bytesToHex,
  commitExternalReference,
  newCommitmentSalt,
  sha256Hex,
  verifyExternalReference,
} from '../src/index';

const salt = new Uint8Array(32).map((_, i) => i);

describe('commitExternalReference', () => {
  it('vecteur figé : SHA-256(sel || référence en UTF-8)', () => {
    const expected = sha256Hex(
      new Uint8Array([...salt, ...new TextEncoder().encode('réservation-é1')]),
    );
    expect(commitExternalReference(salt, 'réservation-é1')).toBe(expected);
  });

  it('accepte le sel en octets ou en hexadécimal', () => {
    expect(commitExternalReference(bytesToHex(salt), 'ref')).toBe(
      commitExternalReference(salt, 'ref'),
    );
  });

  it('refuse un sel qui ne fait pas 32 octets', () => {
    expect(() => commitExternalReference(new Uint8Array(31), 'x')).toThrowError(
      expect.objectContaining({ code: 'INVALID_HEX' }),
    );
    expect(() => commitExternalReference('00', 'x')).toThrow();
  });

  it('newCommitmentSalt : 32 octets aléatoires, jamais deux fois le même', () => {
    const a = newCommitmentSalt();
    expect(a).toHaveLength(COMMITMENT_SALT_BYTES);
    expect(bytesToHex(a)).not.toBe(bytesToHex(newCommitmentSalt()));
  });

  it('un sel différent donne un engagement différent (une référence courante ne se devine pas par dictionnaire)', () => {
    expect(commitExternalReference(newCommitmentSalt(), 'booking-1')).not.toBe(
      commitExternalReference(newCommitmentSalt(), 'booking-1'),
    );
  });
});

describe('verifyExternalReference', () => {
  it('valide la bonne référence et refuse toute autre', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (reference, other) => {
        const commitment = commitExternalReference(salt, reference);
        expect(verifyExternalReference(commitment, salt, reference)).toBe(true);
        if (other !== reference)
          expect(verifyExternalReference(commitment, salt, other)).toBe(false);
      }),
    );
  });

  it('refuse un autre sel, et renvoie false (sans lever) sur des entrées malformées', () => {
    const commitment = commitExternalReference(salt, 'ref');
    expect(verifyExternalReference(commitment, new Uint8Array(32), 'ref')).toBe(false);
    expect(verifyExternalReference('nope', salt, 'ref')).toBe(false);
    expect(verifyExternalReference(commitment, 'zz', 'ref')).toBe(false);
    expect(verifyExternalReference(commitment, new Uint8Array(3), 'ref')).toBe(false);
  });
});
