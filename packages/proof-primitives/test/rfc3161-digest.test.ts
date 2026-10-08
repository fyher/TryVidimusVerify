import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';

import { buildTimeStampReq, sha256Hex, verifyTimeStampToken } from '../src/index';
import { loadTsa, loadTsaText } from './vectors';

// ADR-0026 : en mode direct, le messageImprint du jeton est le condensat LUI-MÊME (et non SHA-256 du condensat).
const digest = loadTsaText('freetsa-digest.digest');
const nonce = loadTsaText('freetsa-digest.nonce');
const token = loadTsa('freetsa-digest.tsr'); // jeton RÉEL de FreeTSA, vérifié aussi avec `openssl ts -verify -digest`
const freetsaCa = loadTsaText('freetsa-ca.pem');

const requestOf = (bytes: Uint8Array): pkijs.TimeStampReq =>
  new pkijs.TimeStampReq({ schema: asn1js.fromBER(bytes.slice().buffer as ArrayBuffer).result });

describe('buildTimeStampReq — convention `digest`', () => {
  it('le messageImprint est le condensat lui-même, algorithme SHA-256', async () => {
    const { reqBytes } = await buildTimeStampReq(digest, { imprint: 'digest' });
    const imprint = requestOf(reqBytes).messageImprint;
    expect(imprint.hashAlgorithm.algorithmId).toBe('2.16.840.1.101.3.4.2.1');
    expect(Buffer.from(imprint.hashedMessage.valueBlock.valueHexView).toString('hex')).toBe(digest);
  });

  it('la convention par défaut (lot) reste SHA-256 du condensat : les preuves Merkle ne changent pas', async () => {
    const { reqBytes } = await buildTimeStampReq(digest);
    const imprint = requestOf(reqBytes).messageImprint;
    expect(Buffer.from(imprint.hashedMessage.valueBlock.valueHexView).toString('hex')).toBe(
      sha256Hex(Buffer.from(digest, 'hex')),
    );
  });

  it('un nonce imposé est repris, une empreinte invalide refusée', async () => {
    const built = await buildTimeStampReq(digest, { imprint: 'digest', nonceHex: nonce });
    expect(built.nonceHex).toBe(nonce);
    await expect(buildTimeStampReq('zz', { imprint: 'digest' })).rejects.toThrow(/racine invalide/);
  });
});

describe('verifyTimeStampToken — convention `digest`, jeton réel FreeTSA', () => {
  it('le jeton porte le condensat : empreinte, nonce, signature et chaîne vérifiés', async () => {
    const result = await verifyTimeStampToken(token, digest, {
      imprint: 'digest',
      expectedNonceHex: nonce,
      trustChainPem: freetsaCa,
    });
    expect(result).toMatchObject({
      statusOk: true,
      messageImprintMatch: true,
      nonceMatch: true,
      signatureValid: true,
      trusted: true,
      errors: [],
    });
    expect(result.genTime).toBeInstanceOf(Date);
  });

  it('un autre condensat est rejeté (empreinte fausse)', async () => {
    const other = sha256Hex('un autre manifeste');
    const result = await verifyTimeStampToken(token, other, {
      imprint: 'digest',
      trustChainPem: freetsaCa,
    });
    expect(result.messageImprintMatch).toBe(false);
  });

  it('un jeton rejoué avec un autre nonce est détecté', async () => {
    const result = await verifyTimeStampToken(token, digest, {
      imprint: 'digest',
      expectedNonceHex: '0000000000000001',
    });
    expect(result.nonceMatch).toBe(false);
  });

  it('une chaîne étrangère ne donne jamais la confiance', async () => {
    const foreign = loadTsaText('ca.pem');
    const result = await verifyTimeStampToken(token, digest, {
      imprint: 'digest',
      trustChainPem: foreign,
    });
    expect(result.trusted).not.toBe(true);
  });

  it('les deux conventions ne se confondent pas : ce jeton direct n’est pas valable comme jeton de lot', async () => {
    const asBatch = await verifyTimeStampToken(token, digest, { trustChainPem: freetsaCa });
    expect(asBatch.messageImprintMatch).toBe(false);
  });

  it('un jeton dont l’empreinte a été falsifiée échoue aussi à la signature (le contrôle de pkijs n’est pas la seule garde)', async () => {
    const forged = token.slice();
    const at = Buffer.from(forged).indexOf(Buffer.from(digest, 'hex'));
    expect(at).toBeGreaterThan(0);
    forged[at + 3] = (forged[at + 3] as number) ^ 0xff;
    const result = await verifyTimeStampToken(forged, digest, {
      imprint: 'digest',
      trustChainPem: freetsaCa,
    });
    expect(result.messageImprintMatch).toBe(false);
    expect(result.signatureValid).toBe(false);
  });

  it('une empreinte qui n’est pas un SHA-256 hexadécimal est refusée', async () => {
    await expect(verifyTimeStampToken(token, 'abc', { imprint: 'digest' })).rejects.toThrow();
  });
});
