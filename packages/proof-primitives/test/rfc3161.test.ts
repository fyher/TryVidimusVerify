import * as asn1js from 'asn1js';
import { describe, expect, it } from 'vitest';

import {
  buildTimeStampReq,
  CERTIGNA_QUALIFIED_PROFILE,
  parseTimeStampResp,
  sha256Hex,
  verifyTimeStampToken,
  type QualifiedProfile,
} from '../src/index';
import { loadTsa, loadTsaText } from './vectors';

const root = loadTsaText('root.hex');
const nonce = loadTsaText('synthetic.nonce');
const syntheticTsr = loadTsa('synthetic.tsr');
const caPem = loadTsaText('ca.pem');
const freetsaTsr = loadTsa('freetsa.tsr');
const freetsaCa = loadTsaText('freetsa-ca.pem');

const testProfile: QualifiedProfile = {
  policyOid: '1.2.3.4.5',
  country: 'FR',
  organization: 'Test Timestamp Authority',
  commonNamePrefix: 'Test TSA',
  qcStatementsOid: '1.3.6.1.5.5.7.1.3',
};

describe('buildTimeStampReq', () => {
  it('produit la requête attendue avec un nonce imposé (vecteur)', async () => {
    const { reqBytes, nonceHex, rootBytes } = await buildTimeStampReq(root, { nonceHex: nonce });
    expect(nonceHex).toBe(nonce);
    expect(rootBytes).toHaveLength(32);
    expect(reqBytes).toEqual(loadTsa('synthetic.tsq'));
  });

  it('génère un nonce aléatoire positif de 8 octets', async () => {
    const a = await buildTimeStampReq(root);
    const b = await buildTimeStampReq(root);
    expect(a.nonceHex).toMatch(/^[0-7][0-9a-f]{15}$/);
    expect(a.nonceHex).not.toBe(b.nonceHex);
  });

  it('refuse une racine invalide et un nonce invalide', async () => {
    await expect(buildTimeStampReq('nope')).rejects.toMatchObject({ code: 'INVALID_ROOT' });
    await expect(buildTimeStampReq(root, { nonceHex: 'ff'.repeat(8) })).rejects.toMatchObject({
      code: 'INVALID_HEX',
    });
    await expect(buildTimeStampReq(root, { nonceHex: '11' })).rejects.toMatchObject({
      code: 'INVALID_HEX',
    });
  });
});

describe('parseTimeStampResp', () => {
  it('lit un jeton et refuse du bruit', () => {
    expect(parseTimeStampResp(syntheticTsr).status.status).toBe(0);
    expect(() => parseTimeStampResp(new Uint8Array([1, 2, 3]))).toThrowError(
      expect.objectContaining({ code: 'TIMESTAMP_UNREADABLE' }),
    );
  });
});

describe('verifyTimeStampToken — autorité de test', () => {
  it('sans chaîne : signature auto-cohérente, trusted reste null, jamais qualifié', async () => {
    const r = await verifyTimeStampToken(syntheticTsr, root, { expectedNonceHex: nonce });
    expect(r).toMatchObject({
      statusOk: true,
      messageImprintMatch: true,
      nonceMatch: true,
      signatureValid: true,
      trusted: null,
      qualifiedClaimVerified: false,
      policyOid: '1.2.3.4.5',
      tsaName: 'Test TSA Unit',
      errors: [],
    });
    expect(r.genTime).toBeInstanceOf(Date);
    expect(r.serialHex).toBe('02');
  });

  it('avec la bonne chaîne : trusted = true', async () => {
    const r = await verifyTimeStampToken(syntheticTsr, root, { trustChainPem: caPem });
    expect(r.trusted).toBe(true);
    expect(r.signatureValid).toBe(true);
  });

  it('avec une chaîne étrangère : jamais de confiance (régression)', async () => {
    const r = await verifyTimeStampToken(syntheticTsr, root, { trustChainPem: freetsaCa });
    expect(r.trusted).toBe(false);
    expect(r.errors.length).toBeGreaterThan(0);
  });

  it('une autre racine ne correspond pas au messageImprint', async () => {
    const r = await verifyTimeStampToken(syntheticTsr, sha256Hex('autre'), {
      trustChainPem: caPem,
    });
    expect(r.messageImprintMatch).toBe(false);
  });

  it('un autre nonce est détecté comme rejeu', async () => {
    expect(
      (await verifyTimeStampToken(syntheticTsr, root, { expectedNonceHex: '0'.repeat(16) }))
        .nonceMatch,
    ).toBe(false);
  });

  it('refuse une racine mal formée', async () => {
    await expect(verifyTimeStampToken(syntheticTsr, 'zz')).rejects.toMatchObject({
      code: 'INVALID_ROOT',
    });
  });

  it('un jeton altéré ne passe pas la signature', async () => {
    const tampered = new Uint8Array(syntheticTsr);
    tampered[tampered.length - 5] = (tampered[tampered.length - 5] as number) ^ 0xff;
    const r = await verifyTimeStampToken(tampered, root, { trustChainPem: caPem });
    expect(r.trusted).toBe(false);
  });

  describe('déclaration « qualifié »', () => {
    it('vraie seulement avec profil ET chaîne vérifiée', async () => {
      const r = await verifyTimeStampToken(syntheticTsr, root, {
        trustChainPem: caPem,
        qualifiedProfile: { ...testProfile, qcStatementsOid: '2.5.29.15' },
      });
      // le certificat porte keyUsage (2.5.29.15) : profil et chaîne concordent
      expect(r.qualifiedClaimVerified).toBe(true);
      expect(r.qualifiedClaimReasons).toEqual([]);
    });

    it('jamais sans chaîne, même si le certificat correspond au profil', async () => {
      const r = await verifyTimeStampToken(syntheticTsr, root, {
        qualifiedProfile: { ...testProfile, qcStatementsOid: '2.5.29.15' },
      });
      expect(r.qualifiedClaimVerified).toBe(false);
      expect(r.qualifiedClaimReasons.join(' ')).toContain('chaîne de confiance non vérifiée');
    });

    it('liste chaque écart au profil', async () => {
      const r = await verifyTimeStampToken(syntheticTsr, root, {
        trustChainPem: caPem,
        qualifiedProfile: CERTIGNA_QUALIFIED_PROFILE,
      });
      expect(r.qualifiedClaimVerified).toBe(false);
      const reasons = r.qualifiedClaimReasons.join('\n');
      for (const fragment of ['policyOid', 'O attendu', 'CN attendu', 'qcStatements']) {
        expect(reasons).toContain(fragment);
      }
    });

    it('sans profil, aucune déclaration', async () => {
      const r = await verifyTimeStampToken(syntheticTsr, root, { trustChainPem: caPem });
      expect(r.qualifiedClaimVerified).toBe(false);
    });
  });
});

describe('verifyTimeStampToken — réponse sans jeton ou refusée', () => {
  function tsrWithStatus(status: number): Uint8Array {
    const seq = new asn1js.Sequence({
      value: [new asn1js.Sequence({ value: [new asn1js.Integer({ value: status })] })],
    });
    return new Uint8Array(seq.toBER());
  }

  it('signale un statut refusé et l’absence de jeton', async () => {
    const r = await verifyTimeStampToken(tsrWithStatus(2), root);
    expect(r.statusOk).toBe(false);
    expect(r.signatureValid).toBe(false);
    expect(r.errors).toEqual(expect.arrayContaining(['PKIStatus=2', 'timeStampToken absent']));
  });
});

describe('verifyTimeStampToken — jeton réel FreeTSA', () => {
  it('vérifie signature, chaîne et messageImprint sur un vrai jeton', async () => {
    const r = await verifyTimeStampToken(freetsaTsr, root, { trustChainPem: freetsaCa });
    expect(r).toMatchObject({
      statusOk: true,
      messageImprintMatch: true,
      signatureValid: true,
      trusted: true,
      qualifiedClaimVerified: false,
    });
    expect(r.genTime?.getUTCFullYear()).toBeGreaterThanOrEqual(2026);
  });

  it('refuse le jeton pour une autre racine', async () => {
    const r = await verifyTimeStampToken(freetsaTsr, sha256Hex('autre'), {
      trustChainPem: freetsaCa,
    });
    expect(r.messageImprintMatch).toBe(false);
  });
});
