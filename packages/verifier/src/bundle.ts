import {
  buildProofManifest,
  proofManifestSha256,
  type ProofManifest,
} from '@repo/proof-primitives';
import { z } from 'zod';

const sha256 = z.string().regex(/^[0-9a-f]{64}$/, 'SHA-256 hexadécimal minuscule attendu');
const id = z.string().regex(/^[A-Za-z0-9_.:-]{1,100}$/, 'identifiant invalide');

const mediaSchema = z.object({
  media_type: z.enum(['photo', 'video']),
  mime_type: z.string().regex(/^[a-z]+\/[a-z0-9.+-]{1,100}$/, 'type MIME invalide'),
  byte_size: z.number().int().positive(),
  /** Heure observée par le service, ISO 8601 UTC avec millisecondes : non qualifiée. */
  captured_at: z.string().min(1),
  original_sha256: sha256,
  signed_sha256: sha256,
  manifest_id: id,
  key_version: id,
});

const stepSchema = z.object({ hash: sha256, position: z.enum(['left', 'right']) });

/** Les champs du jeton, communs aux deux modes. */
const tokenFields = {
  /** Réponse RFC 3161 (.tsr) en base64. */
  tsr_base64: z.string().min(1),
  authority: z.string().min(1),
  gen_time: z.string().min(1),
  serial: z.string().min(1),
  policy_oid: z.string().nullable().optional(),
  qualified: z.boolean().optional(),
};

const merkleFields = {
  merkle_root: sha256,
  leaf_index: z.number().int().min(0),
  merkle_path: z.array(stepSchema),
};

/** Ancien format (avant l'ADR-0026) : toujours lu, comme un horodatage `merkle_batch`. */
const batchSchema = z.object({ ...merkleFields, ...tokenFields });

/**
 * Horodatage de la preuve (ADR-0026). `direct` : un jeton par preuve, dont l'empreinte est le condensat du manifeste ; ni chemin ni
 * index. `merkle_batch` : le jeton porte la racine d'un lot, le chemin mène de la feuille à la racine.
 */
const timestampSchema = z.discriminatedUnion('mode', [
  z.object({ mode: z.literal('direct'), ...tokenFields }),
  z.object({ mode: z.literal('merkle_batch'), ...merkleFields, ...tokenFields }),
]);

/**
 * Paquet de vérification d'une preuve (`GET /v1/public/proofs/{id}/bundle`) : les champs du manifeste (ADR-0018),
 * la feuille déclarée et le lot horodaté. Les champs inconnus sont ignorés : un paquet plus récent reste lisible par
 * un vérificateur plus ancien. Une `version` de manifeste inconnue est refusée.
 */
export const proofBundleSchema = z
  .object({
    version: z.literal(1),
    proof_id: id,
    organization_id: id,
    mode: z.enum(['live', 'test']),
    external_reference_commitment: sha256,
    declared_by_platform: z.object({
      party: z.enum(['provider', 'recipient']),
      stage: z
        .string()
        .regex(/^[a-z0-9_.-]{1,64}$/, 'stage invalide')
        .nullable(),
    }),
    capture: z.object({
      method: z.enum(['hosted_live', 'direct_upload']),
      /** Nul pour `direct_upload` (pas de session de capture). */
      session_id: id.nullable(),
    }),
    generator: z.object({
      name: z.string().regex(/^[A-Za-z0-9 ._+/-]{1,100}$/),
      version: z.string().regex(/^[A-Za-z0-9 ._+/-]{1,100}$/),
    }),
    media: z.array(mediaSchema).min(1),
    manifest_sha256: sha256,
    /** L'horodatage (ADR-0026) ; `null` ou absent tant que la preuve n'est pas horodatée. */
    timestamp: timestampSchema.nullable().optional(),
    /** Ancien format (avant l'ADR-0026) : un lot horodaté ; lu comme `timestamp` en mode `merkle_batch`. */
    batch: batchSchema.nullable().optional(),
  })
  .refine((bundle) => !(bundle.timestamp && bundle.batch), {
    message: 'timestamp et batch ne peuvent pas figurer ensemble',
    path: ['timestamp'],
  });

export type ProofBundle = z.infer<typeof proofBundleSchema>;

export type DirectTimestamp = Extract<z.infer<typeof timestampSchema>, { mode: 'direct' }>;
export type BatchTimestamp = Extract<z.infer<typeof timestampSchema>, { mode: 'merkle_batch' }>;
export type BundleTimestamp = DirectTimestamp | BatchTimestamp;

/** L'horodatage du paquet, quel que soit le format : `timestamp` d'abord, sinon l'ancien `batch` lu comme `merkle_batch`. */
export function timestampOf(bundle: ProofBundle): BundleTimestamp | null {
  if (bundle.timestamp) return bundle.timestamp;
  return bundle.batch ? { mode: 'merkle_batch', ...bundle.batch } : null;
}

/** Manifeste reconstruit à partir des seuls champs déclarés dans le paquet. */
export function manifestOf(bundle: ProofBundle): ProofManifest {
  return buildProofManifest({
    proof_id: bundle.proof_id,
    organization_id: bundle.organization_id,
    mode: bundle.mode,
    external_reference_commitment: bundle.external_reference_commitment,
    declared_by_platform: bundle.declared_by_platform,
    capture: bundle.capture,
    generator: bundle.generator,
    media: bundle.media,
  });
}

/** Feuille Merkle recalculée (jamais lue dans le paquet). */
export function leafOf(bundle: ProofBundle): string {
  return proofManifestSha256(manifestOf(bundle));
}

/**
 * À chaque niveau de l'arbre, le côté du frère est dicté par l'index de la feuille (impair : frère à gauche ; pair :
 * frère à droite, y compris le dernier nœud dupliqué). Un `leaf_index` qui ne correspond pas au chemin est un paquet
 * incohérent, même si le chemin mène à la racine.
 */
export function indexMatchesPath(
  leafIndex: number,
  steps: readonly { position: 'left' | 'right' }[],
): boolean {
  return steps.every(
    (step, level) =>
      step.position === (Math.floor(leafIndex / 2 ** level) % 2 === 1 ? 'left' : 'right'),
  );
}
