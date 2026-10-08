import { createHash } from 'node:crypto';

import { PrimitiveError } from './errors';

export type HashInput = Uint8Array | string;

const SHA256_HEX = /^[0-9a-f]{64}$/;

/** SHA-256 en hexadécimal minuscule. Une chaîne est hachée en UTF-8. */
export function sha256Hex(input: HashInput): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Vrai pour une empreinte SHA-256 en hexadécimal minuscule (64 caractères). */
export function isSha256Hex(value: string): boolean {
  return SHA256_HEX.test(value);
}

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new PrimitiveError('INVALID_HEX', 'chaîne hexadécimale invalide');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
