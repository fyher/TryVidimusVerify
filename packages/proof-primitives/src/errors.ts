export type PrimitiveErrorCode =
  | 'INVALID_HEX'
  | 'EMPTY_TREE'
  | 'LEAF_INDEX_OUT_OF_RANGE'
  | 'INVALID_ROOT'
  | 'TIMESTAMP_UNREADABLE'
  | 'EMPTY_MANIFEST'
  | 'INVALID_MANIFEST';

/** Erreur typée des primitives : le `code` est fait pour être testé, le message pour l'humain. */
export class PrimitiveError extends Error {
  readonly code: PrimitiveErrorCode;

  constructor(code: PrimitiveErrorCode, message?: string) {
    super(message ?? code);
    this.name = 'PrimitiveError';
    this.code = code;
  }
}
