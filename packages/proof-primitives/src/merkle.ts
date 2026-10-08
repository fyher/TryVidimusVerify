import { PrimitiveError } from './errors';
import { hexToBytes, isSha256Hex, sha256Hex } from './hash';

export type MerkleTree = {
  /** layers[0] = feuilles ; le dernier élément = [racine]. */
  layers: string[][];
  root: string;
  /** Nombre de feuilles RÉELLES fournies (avant duplication de parité). */
  leafCount: number;
};

export type InclusionStep = { hash: string; position: 'left' | 'right' };
export type InclusionProof = { leafIndex: number; steps: InclusionStep[] };

function parentHash(left: string, right: string): string {
  const bytes = new Uint8Array(64);
  bytes.set(hexToBytes(left), 0);
  bytes.set(hexToBytes(right), 32);
  return sha256Hex(bytes);
}

function nextLayer(layer: string[]): string[] {
  const last = layer[layer.length - 1] as string;
  // Nombre impair : le dernier nœud est dupliqué, à CHAQUE niveau (convention Bitcoin).
  const padded = layer.length % 2 === 0 ? layer : [...layer, last];
  const parents: string[] = [];
  for (let i = 0; i < padded.length; i += 2) {
    parents.push(parentHash(padded[i] as string, padded[i + 1] as string));
  }
  return parents;
}

/** Construit l'arbre complet à partir de feuilles (empreintes SHA-256 hexadécimales), dans l'ordre fourni. */
export function buildTree(leaves: string[]): MerkleTree {
  if (leaves.length === 0) throw new PrimitiveError('EMPTY_TREE', 'buildTree : aucune feuille');
  if (!leaves.every(isSha256Hex))
    throw new PrimitiveError(
      'INVALID_HEX',
      'les feuilles doivent être des SHA-256 en hexadécimal minuscule',
    );
  const layers: string[][] = [leaves];
  let current = leaves;
  while (current.length > 1) {
    current = nextLayer(current);
    layers.push(current);
  }
  return { layers, root: current[0] as string, leafCount: leaves.length };
}

/** Preuve d'inclusion de la feuille à `leafIndex` (index dans le tableau ORIGINAL, avant duplication de parité). */
export function inclusionProof(tree: MerkleTree, leafIndex: number): InclusionProof {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= tree.leafCount) {
    throw new PrimitiveError('LEAF_INDEX_OUT_OF_RANGE', 'inclusionProof : index hors bornes');
  }
  const steps: InclusionStep[] = [];
  let index = leafIndex;
  for (let level = 0; level < tree.layers.length - 1; level += 1) {
    const layer = tree.layers[level] as string[];
    const isRight = index % 2 === 1;
    const siblingIndex = isRight ? index - 1 : index + 1;
    // Nœud dupliqué pour parité : son frère est lui-même.
    const sibling =
      siblingIndex < layer.length
        ? (layer[siblingIndex] as string)
        : (layer[layer.length - 1] as string);
    steps.push({ hash: sibling, position: isRight ? 'left' : 'right' });
    index = Math.floor(index / 2);
  }
  return { leafIndex, steps };
}

/**
 * Recalcule la racine à partir d'une feuille et de sa preuve, sans l'arbre complet : c'est ce qu'un tiers rejoue.
 * Renvoie `false` (jamais d'exception) pour toute entrée mal formée.
 */
export function verifyInclusion(
  leaf: string,
  proof: InclusionProof,
  expectedRoot: string,
): boolean {
  if (!isSha256Hex(leaf) || !isSha256Hex(expectedRoot)) return false;
  let current = leaf;
  for (const step of proof.steps) {
    if (!isSha256Hex(step.hash)) return false;
    if (step.position !== 'left' && step.position !== 'right') return false;
    current =
      step.position === 'left' ? parentHash(step.hash, current) : parentHash(current, step.hash);
  }
  return current === expectedRoot;
}
