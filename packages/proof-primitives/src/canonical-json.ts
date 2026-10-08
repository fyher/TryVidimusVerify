/**
 * Sérialisation JSON déterministe : clés d'objet triées récursivement, sans espaces, tableaux dans leur
 * ordre. La feuille Merkle d'une preuve doit être reproductible à l'identique par n'importe qui.
 *
 * Comme `JSON.stringify`, une valeur portant `toJSON` (ex. `Date`) est d'abord convertie.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function hasToJson(value: object): value is { toJSON: () => unknown } {
  return typeof (value as { toJSON?: unknown }).toJSON === 'function';
}

function sortKeys(value: unknown): unknown {
  if (value !== null && typeof value === 'object' && hasToJson(value))
    return sortKeys(value.toJSON());
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) sorted[key] = sortKeys(source[key]);
    return sorted;
  }
  return value;
}
