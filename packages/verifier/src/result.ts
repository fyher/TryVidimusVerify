/**
 * Verdict global, du plus grave au plus favorable :
 * - `invalid` : une vérification a échoué, la preuve ne doit pas être présentée comme valide ;
 * - `incomplete` : pas encore d'horodatage (preuve en cours de traitement) ;
 * - `test_mode` : tout concorde mais l'horodatage est simulé (ADR-0008), donc non opposable ;
 * - `chain_unverified` : tout concorde mais aucune chaîne de confiance n'a validé l'autorité d'horodatage ;
 * - `valid` : tout concorde, chaîne vérifiée, autorité réelle.
 */
export type VerificationStatus =
  'invalid' | 'incomplete' | 'test_mode' | 'chain_unverified' | 'valid';

export type Check = { ok: boolean; detail?: string };

export type MediaCheck = {
  index: number;
  original: Check | null;
  signed: Check | null;
  signature: Check | null;
};

export type TimestampSummary = {
  /** `direct` : un jeton par preuve ; `merkle_batch` : un jeton pour un lot (ADR-0026). */
  mode: 'direct' | 'merkle_batch';
  genTime: Date;
  serial: string;
  policyOid: string;
  authority: string;
  simulated: boolean;
  /** `true` : chaîne vérifiée ; `null` : aucune chaîne fournie (jamais présumé). */
  trusted: boolean | null;
  /** Recalculé par le vérificateur, jamais lu dans le paquet ; toujours faux pour une autorité simulée. */
  qualified: boolean;
};

/**
 * Ce que la preuve DÉCLARE, à afficher avec la mention qui convient. Rien ici n'est « vérifié » :
 * - `declaredByPlatform` est renseigné par la plateforme cliente (`verified` est toujours faux) ;
 * - `capturedAt` est l'heure observée par le service, pas celle du téléphone, et elle n'est pas qualifiée ;
 * - seul l'horodatage (`genTime`) prouve que la preuve existait « au plus tard à cette heure ».
 */
export type Claims = {
  organizationId: string;
  mode: 'live' | 'test';
  declaredByPlatform: { party: 'provider' | 'recipient'; stage: string | null; verified: false };
  capture: { method: 'hosted_live' | 'direct_upload'; sessionId: string | null };
  generator: { name: string; version: string };
  media: {
    mediaType: 'photo' | 'video';
    mimeType: string;
    byteSize: number;
    capturedAt: string;
    capturedAtQualified: false;
  }[];
};

export type BundleVerification = {
  status: VerificationStatus;
  proofId?: string;
  checks: {
    schema: Check;
    manifestHash: Check | null;
    /** Appartenance de la feuille à l'arbre : seulement en mode `merkle_batch` (`null` en mode `direct`, sans arbre). */
    inclusion: Check | null;
    timestamp: Check | null;
    media: MediaCheck[];
    /** Engagement sur la référence externe, contrôlé seulement si le sel et la référence sont fournis. */
    externalReference: Check | null;
  };
  claims?: Claims;
  timestamp?: TimestampSummary;
  errors: string[];
};
