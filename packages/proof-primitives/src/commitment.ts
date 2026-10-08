import { PrimitiveError } from './errors';
import { hexToBytes, isSha256Hex, sha256Hex } from './hash';

/** Taille du sel, en octets : fixe, ce qui évite toute ambiguïté de concaténation. */
export const COMMITMENT_SALT_BYTES = 32;

/** Sel aléatoire propre à une preuve (jamais réutilisé d'une preuve à l'autre). */
export function newCommitmentSalt(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(COMMITMENT_SALT_BYTES));
}

function toSaltBytes(salt: Uint8Array | string): Uint8Array {
  const bytes = typeof salt === 'string' ? hexToBytes(salt) : salt;
  if (bytes.length !== COMMITMENT_SALT_BYTES) {
    throw new PrimitiveError('INVALID_HEX', `le sel doit faire ${COMMITMENT_SALT_BYTES} octets`);
  }
  return bytes;
}

/**
 * Engagement sur la référence externe d'un dossier : SHA-256(sel || référence en UTF-8). Le paquet public ne porte
 * que l'engagement ; le sel et la référence sont remis avec le dossier, et n'importe qui peut alors vérifier.
 */
export function commitExternalReference(salt: Uint8Array | string, reference: string): string {
  const saltBytes = toSaltBytes(salt);
  const referenceBytes = new TextEncoder().encode(reference);
  const input = new Uint8Array(saltBytes.length + referenceBytes.length);
  input.set(saltBytes, 0);
  input.set(referenceBytes, saltBytes.length);
  return sha256Hex(input);
}

/** Vrai si `commitment` correspond au sel et à la référence. Faux (sans lever) si l'entrée est malformée. */
export function verifyExternalReference(
  commitment: string,
  salt: Uint8Array | string,
  reference: string,
): boolean {
  if (!isSha256Hex(commitment)) return false;
  try {
    return commitExternalReference(salt, reference) === commitment;
  } catch {
    return false;
  }
}
