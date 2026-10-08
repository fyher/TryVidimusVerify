import { canonicalJson } from './canonical-json';
import { PrimitiveError } from './errors';
import { isSha256Hex, sha256Hex } from './hash';

/** Version du format du manifeste de preuve. Un changement de format ajoute une version, il ne modifie pas la précédente. */
export const PROOF_MANIFEST_VERSION = 1;

export type ProofMode = 'live' | 'test';
export type CaptureMethod = 'hosted_live' | 'direct_upload';
export type Party = 'provider' | 'recipient';

export type ProofManifestMedia = {
  media_type: 'photo' | 'video';
  mime_type: string;
  /** Taille de l'original, en octets. */
  byte_size: number;
  /**
   * Heure à laquelle NOTRE service a observé le fichier (ISO 8601, UTC, millisecondes), jamais celle du téléphone.
   * Ce n'est pas une heure qualifiée : seul l'horodatage du lot prouve « au plus tard à `gen_time` ».
   */
  captured_at: string;
  /** SHA-256 de l'original, octet pour octet (ADR-0003). */
  original_sha256: string;
  /** SHA-256 de la copie signée C2PA dérivée. */
  signed_sha256: string;
  manifest_id: string;
  key_version: string;
};

/**
 * Ce qu'une feuille Merkle engage. Le paquet est public et définitif : aucune donnée personnelle (ni nom, ni e-mail,
 * ni position), la référence externe n'y figure que sous forme d'engagement (`external_reference_commitment`), et
 * rien de mutable (statut, dates de traitement).
 */
export type ProofManifest = {
  version: typeof PROOF_MANIFEST_VERSION;
  proof_id: string;
  /** Identifiant public et stable de la plateforme cliente. */
  organization_id: string;
  mode: ProofMode;
  /** SHA-256(sel de 32 octets || référence externe) ; le sel est révélé avec le dossier, jamais la référence. */
  external_reference_commitment: string;
  /** Renseigné par la plateforme cliente : jamais présenté comme vérifié. */
  declared_by_platform: { party: Party; stage: string | null };
  /**
   * `hosted_live` : page de capture hébergée, avec sa session (`session_id` obligatoire) ; `direct_upload` : envoi
   * direct par l'API, sans session (`session_id` nul).
   */
  capture: { method: CaptureMethod; session_id: string | null };
  generator: { name: string; version: string };
  media: ProofManifestMedia[];
};

export type ProofManifestInput = Omit<ProofManifest, 'version'>;

const ID = /^[A-Za-z0-9_.:-]{1,100}$/;
const SLUG = /^[a-z0-9_.-]{1,64}$/;
const MIME = /^[a-z]+\/[a-z0-9.+-]{1,100}$/;
const LABEL = /^[A-Za-z0-9 ._+/-]{1,100}$/;

function invalid(message: string): never {
  throw new PrimitiveError('INVALID_MANIFEST', message);
}

function assertText(value: unknown, pattern: RegExp, field: string): void {
  if (typeof value !== 'string' || !pattern.test(value)) invalid(`champ invalide : ${field}`);
}

function assertMedia(media: ProofManifestMedia, index: number): void {
  const at = `media[${index}]`;
  if (!isSha256Hex(media.original_sha256) || !isSha256Hex(media.signed_sha256)) {
    throw new PrimitiveError(
      'INVALID_HEX',
      'les empreintes du manifeste doivent être des SHA-256 hexadécimaux',
    );
  }
  if (media.media_type !== 'photo' && media.media_type !== 'video') invalid(`${at}.media_type`);
  assertText(media.mime_type, MIME, `${at}.mime_type`);
  assertText(media.manifest_id, ID, `${at}.manifest_id`);
  assertText(media.key_version, ID, `${at}.key_version`);
  if (!Number.isSafeInteger(media.byte_size) || media.byte_size <= 0) invalid(`${at}.byte_size`);
  const canonicalDate =
    typeof media.captured_at === 'string' &&
    !Number.isNaN(Date.parse(media.captured_at)) &&
    new Date(media.captured_at).toISOString() === media.captured_at;
  if (!canonicalDate) invalid(`${at}.captured_at doit être un ISO 8601 UTC avec millisecondes`);
}

function assertCapture(capture: ProofManifest['capture']): void {
  if (capture.method !== 'hosted_live' && capture.method !== 'direct_upload')
    invalid('capture.method');
  // `hosted_live` a toujours une session. `direct_upload` n'en a pas (nul) ; un identifiant y reste toléré, car les
  // premières golden proofs en portent un et le vérificateur doit les valider pour toujours.
  if (capture.method === 'hosted_live' || capture.session_id !== null) {
    assertText(capture.session_id, ID, 'capture.session_id');
  }
}

function assertManifest(input: ProofManifestInput): void {
  if (input.media.length === 0) {
    throw new PrimitiveError(
      'EMPTY_MANIFEST',
      'un manifeste de preuve contient au moins un fichier',
    );
  }
  assertText(input.proof_id, ID, 'proof_id');
  assertText(input.organization_id, ID, 'organization_id');
  if (input.mode !== 'live' && input.mode !== 'test') invalid('mode');
  if (!isSha256Hex(input.external_reference_commitment)) {
    throw new PrimitiveError(
      'INVALID_HEX',
      "l'engagement de la référence externe doit être un SHA-256 hexadécimal",
    );
  }
  if (
    input.declared_by_platform.party !== 'provider' &&
    input.declared_by_platform.party !== 'recipient'
  ) {
    invalid('declared_by_platform.party');
  }
  if (input.declared_by_platform.stage !== null) {
    assertText(input.declared_by_platform.stage, SLUG, 'declared_by_platform.stage');
  }
  assertCapture(input.capture);
  assertText(input.generator.name, LABEL, 'generator.name');
  assertText(input.generator.version, LABEL, 'generator.version');
  input.media.forEach(assertMedia);
}

/** Construit le manifeste en validant chaque champ et en ne retenant que ceux du format courant. */
export function buildProofManifest(input: ProofManifestInput): ProofManifest {
  assertManifest(input);
  return {
    version: PROOF_MANIFEST_VERSION,
    proof_id: input.proof_id,
    organization_id: input.organization_id,
    mode: input.mode,
    external_reference_commitment: input.external_reference_commitment,
    declared_by_platform: {
      party: input.declared_by_platform.party,
      stage: input.declared_by_platform.stage,
    },
    capture: { method: input.capture.method, session_id: input.capture.session_id },
    generator: { name: input.generator.name, version: input.generator.version },
    media: input.media.map((media) => ({
      media_type: media.media_type,
      mime_type: media.mime_type,
      byte_size: media.byte_size,
      captured_at: media.captured_at,
      original_sha256: media.original_sha256,
      signed_sha256: media.signed_sha256,
      manifest_id: media.manifest_id,
      key_version: media.key_version,
    })),
  };
}

/** Feuille Merkle d'une preuve : SHA-256 du manifeste en JSON canonique. */
export function proofManifestSha256(manifest: ProofManifest): string {
  return sha256Hex(canonicalJson(manifest));
}
