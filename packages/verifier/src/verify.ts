import {
  sha256Hex,
  verifyExternalReference,
  verifyInclusion,
  verifyTimeStampToken,
  type QualifiedProfile,
  type TimeStampVerification,
} from '@repo/proof-primitives';

import {
  indexMatchesPath,
  leafOf,
  proofBundleSchema,
  timestampOf,
  type BundleTimestamp,
  type ProofBundle,
} from './bundle';
import type {
  BundleVerification,
  Check,
  Claims,
  MediaCheck,
  TimestampSummary,
  VerificationStatus,
} from './result';

export type MediaFiles = { original?: Uint8Array; signed?: Uint8Array };

export type VerifyBundleOptions = {
  /** Chaîne de confiance (PEM) de l'autorité d'horodatage. Fournie, elle est exigée. */
  trustChainPem?: string;
  /** Profil d'une autorité qualifiée à reconnaître. Sans lui, un jeton n'est jamais « qualifié ». */
  qualifiedProfile?: QualifiedProfile;
  /**
   * Sel et référence externe, remis avec le dossier : permettent de contrôler l'engagement du manifeste. Sans eux,
   * l'engagement n'est pas contrôlé (`externalReference` reste `null`).
   */
  externalReference?: { salt: Uint8Array | string; reference: string };
  /** Fichiers à comparer aux empreintes du paquet, dans l'ordre de `media`. */
  files?: (MediaFiles | undefined)[];
  /**
   * Vérification de la signature C2PA d'une copie signée, injectée par l'appelant : le vérificateur ne dépend
   * pas de la bibliothèque native.
   */
  verifyMedia?: (signed: Uint8Array, mediaType: 'photo' | 'video') => Promise<Check>;
};

type Timestamp = BundleTimestamp;
type Batch = Extract<Timestamp, { mode: 'merkle_batch' }>;

function fromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function normalizeHex(value: string): string {
  return value.toLowerCase().replace(/^0+/, '');
}

const IMPRINT_PROBLEM = {
  direct: 'le jeton ne porte pas le condensat du manifeste',
  merkle_batch: 'le jeton ne porte pas la racine du lot',
} as const;

function explain(
  verification: TimeStampVerification,
  batch: Timestamp,
  trustRequired: boolean,
): string[] {
  const problems: string[] = [];
  if (!verification.statusOk) problems.push('statut de la réponse RFC 3161 refusé');
  if (!verification.messageImprintMatch) problems.push(IMPRINT_PROBLEM[batch.mode]);
  if (!verification.signatureValid) problems.push('signature du jeton invalide');
  if (trustRequired && verification.trusted !== true)
    problems.push('chaîne de confiance non validée');
  if (
    verification.genTime &&
    verification.genTime.getTime() !== new Date(batch.gen_time).getTime()
  ) {
    problems.push("l'heure du paquet diffère de celle du jeton");
  }
  if (
    verification.serialHex &&
    normalizeHex(verification.serialHex) !== normalizeHex(batch.serial)
  ) {
    problems.push('le numéro de série du paquet diffère de celui du jeton');
  }
  return problems;
}

/**
 * Ce que le jeton doit porter, recalculé par le vérificateur et jamais lu dans le paquet : en mode `direct`, le condensat du manifeste
 * (la feuille recalculée), avec la convention « empreinte = condensat » ; en mode `merkle_batch`, la racine déclarée du lot.
 */
const expectedImprint = (
  timestamp: Timestamp,
  leaf: string,
): { hex: string; imprint: 'digest' | 'hash-of-data' } =>
  timestamp.mode === 'direct'
    ? { hex: leaf, imprint: 'digest' }
    : { hex: timestamp.merkle_root, imprint: 'hash-of-data' };

async function checkTimestamp(
  batch: Timestamp,
  leaf: string,
  options: VerifyBundleOptions,
): Promise<{ check: Check; summary?: TimestampSummary }> {
  let verification: TimeStampVerification;
  const expected = expectedImprint(batch, leaf);
  try {
    verification = await verifyTimeStampToken(fromBase64(batch.tsr_base64), expected.hex, {
      imprint: expected.imprint,
      ...(options.trustChainPem ? { trustChainPem: options.trustChainPem } : {}),
      ...(options.qualifiedProfile ? { qualifiedProfile: options.qualifiedProfile } : {}),
    });
  } catch (error) {
    return { check: { ok: false, detail: `jeton illisible : ${String(error)}` } };
  }
  const problems = explain(verification, batch, Boolean(options.trustChainPem));
  const simulated = batch.authority === 'simulated';
  return {
    check: problems.length === 0 ? { ok: true } : { ok: false, detail: problems.join('; ') },
    summary: {
      mode: batch.mode,
      genTime: verification.genTime ?? new Date(batch.gen_time),
      serial: verification.serialHex ?? batch.serial,
      policyOid: verification.policyOid ?? '',
      authority: batch.authority,
      simulated,
      trusted: verification.trusted,
      qualified: !simulated && verification.qualifiedClaimVerified,
    },
  };
}

function compare(bytes: Uint8Array | undefined, expected: string): Check | null {
  if (!bytes) return null;
  return sha256Hex(bytes) === expected
    ? { ok: true }
    : { ok: false, detail: "l'empreinte du fichier diffère de celle du paquet" };
}

async function checkMedia(
  bundle: ProofBundle,
  options: VerifyBundleOptions,
): Promise<MediaCheck[]> {
  const results: MediaCheck[] = [];
  for (const [index, media] of bundle.media.entries()) {
    const files = options.files?.[index];
    results.push({
      index,
      original: compare(files?.original, media.original_sha256),
      signed: compare(files?.signed, media.signed_sha256),
      signature:
        files?.signed && options.verifyMedia
          ? await options.verifyMedia(files.signed, media.media_type)
          : null,
    });
  }
  return results;
}

function mediaFailed(results: MediaCheck[]): boolean {
  return results.some((r) =>
    [r.original, r.signed, r.signature].some((check) => check?.ok === false),
  );
}

function statusOf(input: {
  hard: boolean;
  batch: Timestamp | null;
  summary?: TimestampSummary;
}): VerificationStatus {
  if (input.hard) return 'invalid';
  if (!input.batch) return 'incomplete';
  if (input.summary?.simulated) return 'test_mode';
  return input.summary?.trusted === true ? 'valid' : 'chain_unverified';
}

function invalidSchema(error: {
  issues: { path: PropertyKey[]; message: string }[];
}): BundleVerification {
  const errors = error.issues.map(
    (issue) => `${issue.path.join('.') || '(racine)'} : ${issue.message}`,
  );
  return {
    status: 'invalid',
    checks: {
      schema: { ok: false, detail: errors.join('; ') },
      manifestHash: null,
      inclusion: null,
      timestamp: null,
      media: [],
      externalReference: null,
    },
    errors,
  };
}

function checkManifestHash(bundle: ProofBundle, leaf: string): Check {
  return leaf === bundle.manifest_sha256
    ? { ok: true }
    : { ok: false, detail: 'la feuille recalculée diffère de manifest_sha256' };
}

function checkInclusion(leaf: string, batch: Batch): Check {
  if (!indexMatchesPath(batch.leaf_index, batch.merkle_path)) {
    return { ok: false, detail: "leaf_index incohérent avec le chemin de l'arbre" };
  }
  const included = verifyInclusion(
    leaf,
    { leafIndex: batch.leaf_index, steps: batch.merkle_path },
    batch.merkle_root,
  );
  return included
    ? { ok: true }
    : { ok: false, detail: "la feuille n'appartient pas à l'arbre de la racine déclarée" };
}

function checkExternalReference(bundle: ProofBundle, options: VerifyBundleOptions): Check | null {
  const given = options.externalReference;
  if (!given) return null;
  return verifyExternalReference(bundle.external_reference_commitment, given.salt, given.reference)
    ? { ok: true }
    : {
        ok: false,
        detail: "la référence et le sel ne correspondent pas à l'engagement du manifeste",
      };
}

function claimsOf(bundle: ProofBundle): Claims {
  return {
    organizationId: bundle.organization_id,
    mode: bundle.mode,
    declaredByPlatform: { ...bundle.declared_by_platform, verified: false },
    capture: { method: bundle.capture.method, sessionId: bundle.capture.session_id },
    generator: bundle.generator,
    media: bundle.media.map((media) => ({
      mediaType: media.media_type,
      mimeType: media.mime_type,
      byteSize: media.byte_size,
      capturedAt: media.captured_at,
      capturedAtQualified: false as const,
    })),
  };
}

/** Feuille recalculée, ou le message de refus si un champ du paquet viole le format du manifeste. */
function tryLeaf(bundle: ProofBundle): { leaf: string } | { error: string } {
  try {
    return { leaf: leafOf(bundle) };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

type Prepared = {
  bundle: ProofBundle;
  leaf: string;
  manifestHash: Check;
  media: MediaCheck[];
  externalReference: Check | null;
  hard: boolean;
};

async function prepare(
  bundle: ProofBundle,
  leaf: string,
  options: VerifyBundleOptions,
): Promise<Prepared> {
  const manifestHash = checkManifestHash(bundle, leaf);
  const media = await checkMedia(bundle, options);
  const externalReference = checkExternalReference(bundle, options);
  const hard = !manifestHash.ok || mediaFailed(media) || externalReference?.ok === false;
  return { bundle, leaf, manifestHash, media, externalReference, hard };
}

function pending(p: Prepared): BundleVerification {
  return {
    status: statusOf({ hard: p.hard, batch: null }),
    proofId: p.bundle.proof_id,
    checks: {
      schema: { ok: true },
      manifestHash: p.manifestHash,
      inclusion: null,
      timestamp: null,
      media: p.media,
      externalReference: p.externalReference,
    },
    claims: claimsOf(p.bundle),
    errors: p.manifestHash.ok ? [] : [p.manifestHash.detail ?? ''],
  };
}

async function sealed(
  p: Prepared,
  batch: Timestamp,
  options: VerifyBundleOptions,
): Promise<BundleVerification> {
  // Pas d'arbre en mode `direct` : l'appartenance n'a pas de sens, le jeton porte directement le condensat du manifeste.
  const inclusion = batch.mode === 'merkle_batch' ? checkInclusion(p.leaf, batch) : null;
  const { check: timestamp, summary } = await checkTimestamp(batch, p.leaf, options);
  const checks = [p.manifestHash, ...(inclusion ? [inclusion] : []), timestamp];
  const failures = [...checks, ...(p.externalReference ? [p.externalReference] : [])];
  return {
    status: statusOf({ hard: p.hard || checks.some((c) => !c.ok), batch, summary }),
    proofId: p.bundle.proof_id,
    checks: {
      schema: { ok: true },
      manifestHash: p.manifestHash,
      inclusion,
      timestamp,
      media: p.media,
      externalReference: p.externalReference,
    },
    claims: claimsOf(p.bundle),
    ...(summary ? { timestamp: summary } : {}),
    errors: failures.flatMap((c) => (c.ok ? [] : [c.detail ?? ''])),
  };
}

/**
 * Vérifie un paquet de preuve de bout en bout, sans faire confiance au serveur qui l'a produit :
 * 1. la feuille est recalculée à partir des champs déclarés (jamais lue) ;
 * 2. en mode `merkle_batch`, la feuille appartient bien à l'arbre de racine `merkle_root` ;
 * 3. le jeton RFC 3161 porte le condensat du manifeste (mode `direct`) ou la racine du lot (mode `merkle_batch`), est signé, et
 *    (si une chaîne est fournie) émane d'une autorité de confiance ;
 * 4. les fichiers fournis correspondent aux empreintes, et la référence externe (si fournie) à son engagement.
 * Le caractère « qualifié » et la confiance sont recalculés ici, jamais recopiés du paquet. Les déclarations de la
 * plateforme, l'heure de capture et le générateur sont restitués dans `claims`, jamais comme des faits vérifiés.
 */
export async function verifyBundle(
  input: unknown,
  options: VerifyBundleOptions = {},
): Promise<BundleVerification> {
  const parsed = proofBundleSchema.safeParse(input);
  if (!parsed.success) return invalidSchema(parsed.error);
  const computed = tryLeaf(parsed.data);
  if ('error' in computed)
    return invalidSchema({ issues: [{ path: [], message: computed.error }] });
  const prepared = await prepare(parsed.data, computed.leaf, options);
  const timestamp = timestampOf(parsed.data);
  return timestamp ? sealed(prepared, timestamp, options) : pending(prepared);
}
