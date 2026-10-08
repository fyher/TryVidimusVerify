import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

/** Copie d'un tableau d'octets dans un ArrayBuffer autonome (les Buffer Node partagent un pool mémoire). */
const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer as ArrayBuffer;

/**
 * Ce que le `messageImprint` du jeton contient (ADR-0026).
 * - `hash-of-data` (défaut, mode `merkle_batch`) : SHA-256 de l'octet-chaîne de 32 octets (la racine est traitée comme une donnée).
 * - `digest` (mode `direct`) : le condensat SHA-256 LUI-MÊME. Se vérifie avec OpenSSL sans connaître notre format :
 *   `openssl ts -verify -digest <condensat hex> -in preuve.tsr -CAfile chaine.pem`.
 */
export type ImprintConvention = 'hash-of-data' | 'digest';

export const SHA256_OID = '2.16.840.1.101.3.4.2.1';

export async function messageImprintFor(
  bytes: Uint8Array,
  convention: ImprintConvention,
): Promise<pkijs.MessageImprint> {
  if (convention === 'hash-of-data') {
    return pkijs.MessageImprint.create('SHA-256', toArrayBuffer(bytes));
  }
  return new pkijs.MessageImprint({
    hashAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: SHA256_OID,
      algorithmParams: new asn1js.Null(),
    }),
    hashedMessage: new asn1js.OctetString({ valueHex: toArrayBuffer(bytes) }),
  });
}

/** Le jeton porte-t-il exactement ce condensat (convention `digest`) ? Algorithme SHA-256 exigé. */
export function digestImprintMatches(tstInfo: pkijs.TSTInfo, digest: Uint8Array): boolean {
  const { hashAlgorithm, hashedMessage } = tstInfo.messageImprint;
  const actual = new Uint8Array(hashedMessage.valueBlock.valueHexView);
  return (
    hashAlgorithm.algorithmId === SHA256_OID &&
    actual.length === digest.length &&
    actual.every((byte, index) => byte === digest[index])
  );
}
