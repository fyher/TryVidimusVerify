// Horodatage RFC 3161 : construction de la requête et vérification du jeton (ASN.1 pur via pkijs / asn1js).
// Aucun appel réseau ici : envoyer la requête à l'autorité est le rôle du code de scellement, hors de ce paquet.
//
// Ce que l'on horodate : la racine Merkle est traitée comme une DONNÉE de 32 octets ; le messageImprint du
// jeton est donc SHA-256(racine). Un tiers peut vérifier avec OpenSSL :
//   printf '<racine hex>' | xxd -r -p > racine.bin
//   openssl ts -verify -data racine.bin -in lot.tsr -CAfile chaine.pem
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import { PrimitiveError } from './errors';
import { bytesToHex, hexToBytes, isSha256Hex } from './hash';
import { digestImprintMatches, messageImprintFor, type ImprintConvention } from './imprint';

export type { ImprintConvention };

let engineReady = false;
function ensureEngine(): void {
  if (engineReady) return;
  // Les typings de pkijs 3.4 exigent des méthodes de décapsulation que CryptoEngine n'expose pas encore.
  const engine = new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto });
  pkijs.setEngine('node-webcrypto', engine as unknown as Parameters<typeof pkijs.setEngine>[1]);
  engineReady = true;
}

/** Copie d'un tableau d'octets dans un ArrayBuffer autonome (les Buffer Node partagent un pool mémoire). */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

// ------------------------------------------------------------------------------------------------ Requête

export type BuiltTimeStampReq = {
  /** Requête RFC 3161 encodée en DER. */
  reqBytes: Uint8Array;
  nonceHex: string;
  rootBytes: Uint8Array;
};

export type BuildTimeStampReqOptions = {
  /** Convention du `messageImprint` (défaut : `hash-of-data`). */
  imprint?: ImprintConvention;
  /** Nonce imposé (16 caractères hexadécimaux, premier octet < 0x80). Réservé aux tests ; sinon aléatoire. */
  nonceHex?: string;
};

function makeNonce(nonceHex?: string): { nonce: asn1js.Integer; nonceHex: string } {
  let bytes: Uint8Array<ArrayBuffer>;
  if (nonceHex === undefined) {
    bytes = new Uint8Array(8);
    globalThis.crypto.getRandomValues(bytes);
    // Bit de poids fort à 0 : INTEGER ASN.1 positif, sans octet de bourrage.
    bytes[0] = (bytes[0] as number) & 0x7f;
  } else {
    bytes = hexToBytes(nonceHex);
    if (bytes.length !== 8 || (bytes[0] as number) >= 0x80) {
      throw new PrimitiveError('INVALID_HEX', 'nonce : 8 octets, premier octet < 0x80');
    }
  }
  return {
    nonce: new asn1js.Integer({ valueHex: toArrayBuffer(bytes) }),
    nonceHex: bytesToHex(bytes),
  };
}

/** Construit la requête RFC 3161 (DER) pour une racine Merkle (SHA-256 hexadécimal). */
export async function buildTimeStampReq(
  rootHex: string,
  options: BuildTimeStampReqOptions = {},
): Promise<BuiltTimeStampReq> {
  ensureEngine();
  if (!isSha256Hex(rootHex))
    throw new PrimitiveError('INVALID_ROOT', 'racine invalide (attendu SHA-256 hexadécimal)');
  const rootBytes = hexToBytes(rootHex);
  const { nonce, nonceHex } = makeNonce(options.nonceHex);
  const messageImprint = await messageImprintFor(rootBytes, options.imprint ?? 'hash-of-data');
  const request = new pkijs.TimeStampReq({ version: 1, messageImprint, certReq: true, nonce });
  return { reqBytes: new Uint8Array(request.toSchema().toBER()), nonceHex, rootBytes };
}

// ------------------------------------------------------------------------------------------------ Jeton

export function parseTimeStampResp(tsrBytes: Uint8Array): pkijs.TimeStampResp {
  ensureEngine();
  const asn1 = asn1js.fromBER(toArrayBuffer(tsrBytes));
  if (asn1.offset === -1)
    throw new PrimitiveError('TIMESTAMP_UNREADABLE', 'jeton .tsr : ASN.1 illisible');
  return new pkijs.TimeStampResp({ schema: asn1.result });
}

/**
 * Empreinte attendue d'une autorité d'horodatage qualifiée. Une autorité non décrite par un profil ne peut
 * PAS être déclarée qualifiée, quoi que dise la configuration.
 */
export type QualifiedProfile = {
  policyOid: string;
  country: string;
  organization: string;
  commonNamePrefix: string;
  /** Extension qcStatements du certificat de l'autorité (RFC 3739). */
  qcStatementsOid: string;
};

/**
 * Certigna : valeurs relevées sur la production (3 jetons réels, 2026-09-16). La documentation du fournisseur
 * annonçait un autre OID et O=DHIMYOTIS ; le certificat qui signe réellement porte O=CERTIGNA et
 * CN=CERTIGNA - TSUxx, et la politique 1.2.250.1.177.2.9.1.
 */
export const CERTIGNA_QUALIFIED_PROFILE: QualifiedProfile = {
  policyOid: '1.2.250.1.177.2.9.1',
  country: 'FR',
  organization: 'CERTIGNA',
  commonNamePrefix: 'CERTIGNA - TSU',
  qcStatementsOid: '1.3.6.1.5.5.7.1.3',
};

export type VerifyTimeStampOptions = {
  /** Convention du `messageImprint` attendue (défaut : `hash-of-data`). */
  imprint?: ImprintConvention;
  /** Chaîne de confiance (PEM, un ou plusieurs certificats). Sans elle, `trusted` reste `null`. */
  trustChainPem?: string;
  /** Nonce de la requête d'origine, pour détecter un rejeu. */
  expectedNonceHex?: string;
  /** Profil d'une autorité qualifiée à reconnaître. Sans lui, un jeton n'est jamais « qualifié ». */
  qualifiedProfile?: QualifiedProfile;
};

export type TimeStampVerification = {
  statusOk: boolean;
  messageImprintMatch: boolean;
  nonceMatch: boolean;
  signatureValid: boolean;
  /** true = chaîne vérifiée contre `trustChainPem` ; null = aucune chaîne fournie (jamais fabriqué). */
  trusted: boolean | null;
  genTime?: Date;
  serialHex?: string;
  policyOid?: string;
  tsaName?: string;
  /**
   * true seulement si le jeton porte la politique et le certificat du profil ET que sa chaîne est vérifiée
   * (`trusted === true`). Sans chaîne de confiance, un certificat qui « ressemble » à une autorité qualifiée
   * ne prouve rien : il pourrait être fabriqué.
   */
  qualifiedClaimVerified: boolean;
  qualifiedClaimReasons: string[];
  errors: string[];
};

function extractRdn(cert: pkijs.Certificate, oid: string): string | undefined {
  const entry = cert.subject.typesAndValues.find((t) => t.type === oid);
  return entry ? String(entry.value.valueBlock.value) : undefined;
}

function subjectMismatches(profile: QualifiedProfile, cert: pkijs.Certificate): string[] {
  const reasons: string[] = [];
  const country = extractRdn(cert, '2.5.4.6');
  const organization = extractRdn(cert, '2.5.4.10');
  const commonName = extractRdn(cert, '2.5.4.3');
  if (country !== profile.country)
    reasons.push(`C attendu ${profile.country}, reçu ${country ?? '∅'}`);
  if (organization !== profile.organization)
    reasons.push(`O attendu ${profile.organization}, reçu ${organization ?? '∅'}`);
  if (!commonName?.startsWith(profile.commonNamePrefix)) {
    reasons.push(`CN attendu préfixe "${profile.commonNamePrefix}", reçu ${commonName ?? '∅'}`);
  }
  if (!(cert.extensions ?? []).some((e) => e.extnID === profile.qcStatementsOid)) {
    reasons.push('extension qcStatements absente du certificat');
  }
  return reasons;
}

function checkQualifiedClaim(
  profile: QualifiedProfile,
  policyOid: string | undefined,
  cert: pkijs.Certificate | undefined,
  trusted: boolean | null,
): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (policyOid !== profile.policyOid)
    reasons.push(`policyOid attendu ${profile.policyOid}, reçu ${policyOid ?? '∅'}`);
  reasons.push(
    ...(cert ? subjectMismatches(profile, cert) : ["certificat de l'autorité absent du jeton"]),
  );
  if (trusted !== true)
    reasons.push('chaîne de confiance non vérifiée (aucune chaîne fournie, ou signature invalide)');
  return { ok: reasons.length === 0, reasons };
}

/**
 * Identifie le certificat qui a RÉELLEMENT signé le jeton parmi ceux embarqués, via signerInfo.sid : l'ordre
 * des certificats dans la réponse n'est pas garanti (les AC précèdent souvent la feuille).
 */
function findSignerCertificate(
  signedData: pkijs.SignedData,
  certs: pkijs.Certificate[],
): pkijs.Certificate | undefined {
  const sid = signedData.signerInfos?.[0]?.sid as { serialNumber?: asn1js.Integer } | undefined;
  if (!sid?.serialNumber) return certs[0];
  const wanted = bytesToHex(new Uint8Array(sid.serialNumber.valueBlock.valueHexView));
  return (
    certs.find(
      (c) => bytesToHex(new Uint8Array(c.serialNumber.valueBlock.valueHexView)) === wanted,
    ) ?? certs[0]
  );
}

function parseCertChainPem(pem: string): pkijs.Certificate[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((block) => {
    const der = Uint8Array.from(
      atob(block.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, '')),
      (c) => c.charCodeAt(0),
    );
    return new pkijs.Certificate({ schema: asn1js.fromBER(toArrayBuffer(der)).result });
  });
}

function nonceMatches(
  tstNonce: asn1js.Integer | undefined,
  expectedHex: string | undefined,
): boolean {
  if (expectedHex === undefined) return true;
  if (!tstNonce) return false;
  const actual = bytesToHex(new Uint8Array(tstNonce.valueBlock.valueHexView)).replace(/^0+/, '');
  return actual === expectedHex.replace(/^0+/, '');
}

type ParsedToken = {
  signedData: pkijs.SignedData;
  tstInfo: pkijs.TSTInfo;
  embeddedCerts: pkijs.Certificate[];
  /** Une copie indépendante de la structure signée (pour une vérification qui ne doit pas modifier l'original). */
  reparse: () => pkijs.SignedData;
};

const ID_DATA = '1.2.840.113549.1.7.1';

function parseToken(response: pkijs.TimeStampResp): ParsedToken | null {
  if (!response.timeStampToken) return null;
  const content = response.timeStampToken.content;
  const signedData = new pkijs.SignedData({ schema: content });
  const tstInfoBer = (signedData.encapContentInfo.eContent as asn1js.OctetString).getValue();
  const tstInfo = new pkijs.TSTInfo({ schema: asn1js.fromBER(tstInfoBer).result });
  const embeddedCerts = (signedData.certificates ?? []).filter(
    (c): c is pkijs.Certificate => c instanceof pkijs.Certificate,
  );
  return {
    signedData,
    tstInfo,
    embeddedCerts,
    reparse: () => new pkijs.SignedData({ schema: content }),
  };
}

/**
 * Sans chaîne fournie : signature contre le certificat embarqué (auto-cohérence). Avec chaîne : la signature
 * ET la chaîne du certificat de l'autorité jusqu'à `trustedCerts` sont vérifiées, à la date `genTime` du jeton.
 * (Une version antérieure ne demandait pas la chaîne à pkijs : `trusted` pouvait être vrai avec une chaîne étrangère.)
 */
async function checkSignature(
  token: ParsedToken,
  rootArrayBuffer: ArrayBuffer,
  trust: { certs: pkijs.Certificate[]; checkChain: boolean; imprint: ImprintConvention },
  errors: string[],
): Promise<{ signatureValid: boolean; trusted: boolean | null }> {
  try {
    // pkijs contrôle l'empreinte d'un TSTInfo en hachant `data` : cela ne convient qu'à la convention `hash-of-data`. Pour
    // `digest`, la vérification de la SIGNATURE et de la CHAÎNE se fait sur une copie dont le type de contenu n'est plus
    // « TSTInfo » (la signature couvre les mêmes octets), et l'empreinte est contrôlée séparément (`digestImprintMatches`).
    const signedData = trust.imprint === 'digest' ? token.reparse() : token.signedData;
    if (trust.imprint === 'digest') signedData.encapContentInfo.eContentType = ID_DATA;
    const result = await signedData.verify({
      signer: 0,
      data: rootArrayBuffer,
      trustedCerts: trust.certs,
      checkChain: trust.checkChain,
      checkDate: token.tstInfo.genTime,
      extendedMode: true,
    });
    const signatureValid = result.signatureVerified === true;
    const trusted = trust.checkChain
      ? signatureValid && result.signerCertificateVerified === true
      : null;
    if (!signatureValid || trusted === false) errors.push(`signature: ${result.message}`);
    return { signatureValid, trusted };
  } catch (error) {
    errors.push(`signature: ${String(error)}`);
    return { signatureValid: false, trusted: trust.checkChain ? false : null };
  }
}

/** L'empreinte du jeton est-elle celle attendue, selon la convention (ADR-0026) ? */
async function imprintMatches(
  tstInfo: pkijs.TSTInfo,
  rootHex: string,
  convention: ImprintConvention = 'hash-of-data',
): Promise<boolean> {
  return convention === 'digest'
    ? digestImprintMatches(tstInfo, hexToBytes(rootHex))
    : tstInfo.verify({ data: toArrayBuffer(hexToBytes(rootHex)) });
}

const MISSING_TOKEN: Omit<TimeStampVerification, 'statusOk' | 'errors'> = {
  messageImprintMatch: false,
  nonceMatch: false,
  signatureValid: false,
  trusted: null,
  qualifiedClaimVerified: false,
  qualifiedClaimReasons: ['timeStampToken absent'],
};

/**
 * Vérifie un jeton .tsr contre la racine attendue. Sans `trustChainPem`, la signature n'est vérifiée qu'en
 * auto-cohérence (contre le certificat embarqué) et `trusted` reste `null`.
 */
export async function verifyTimeStampToken(
  tsrBytes: Uint8Array,
  rootHex: string,
  options: VerifyTimeStampOptions = {},
): Promise<TimeStampVerification> {
  ensureEngine();
  if (!isSha256Hex(rootHex))
    throw new PrimitiveError('INVALID_ROOT', 'racine invalide (attendu SHA-256 hexadécimal)');
  const errors: string[] = [];
  const response = parseTimeStampResp(tsrBytes);
  const statusOk =
    response.status.status === pkijs.PKIStatus.granted ||
    response.status.status === pkijs.PKIStatus.grantedWithMods;
  if (!statusOk) errors.push(`PKIStatus=${response.status.status}`);

  const token = parseToken(response);
  if (!token) return { ...MISSING_TOKEN, statusOk, errors: [...errors, 'timeStampToken absent'] };
  const { signedData, tstInfo, embeddedCerts } = token;

  const rootArrayBuffer = toArrayBuffer(hexToBytes(rootHex));
  const messageImprintMatch = await imprintMatches(tstInfo, rootHex, options.imprint);
  const trust = {
    certs: options.trustChainPem ? parseCertChainPem(options.trustChainPem) : embeddedCerts,
    checkChain: Boolean(options.trustChainPem),
    imprint: options.imprint ?? 'hash-of-data',
  } as const;
  const { signatureValid, trusted } = await checkSignature(token, rootArrayBuffer, trust, errors);

  const signerCert = findSignerCertificate(signedData, embeddedCerts);
  const claim = options.qualifiedProfile
    ? checkQualifiedClaim(options.qualifiedProfile, tstInfo.policy, signerCert, trusted)
    : { ok: false, reasons: ["aucun profil d'autorité qualifiée fourni"] };

  return {
    statusOk,
    messageImprintMatch,
    nonceMatch: nonceMatches(tstInfo.nonce, options.expectedNonceHex),
    signatureValid,
    trusted,
    genTime: tstInfo.genTime,
    serialHex: bytesToHex(new Uint8Array(tstInfo.serialNumber.valueBlock.valueHexView)),
    policyOid: tstInfo.policy,
    ...(signerCert ? { tsaName: extractRdn(signerCert, '2.5.4.3') } : {}),
    qualifiedClaimVerified: claim.ok,
    qualifiedClaimReasons: claim.reasons,
    errors,
  };
}
