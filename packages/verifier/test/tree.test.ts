import { buildTree, inclusionProof, sha256Hex } from '@repo/proof-primitives';
import { describe, expect, it } from 'vitest';

import { indexMatchesPath } from '../src/index';

// Garde-fou contre le faux rejet : tout chemin produit par l'arbre de proof-primitives, pour toute taille d'arbre et
// tout index (y compris le dernier nœud dupliqué), doit être jugé cohérent avec son index.
describe('indexMatchesPath', () => {
  it('accepte les chemins de tous les index de toutes les tailles jusqu’à 70 feuilles', () => {
    for (let count = 1; count <= 70; count += 1) {
      const leaves = Array.from({ length: count }, (_, i) => sha256Hex(`leaf-${count}-${i}`));
      const tree = buildTree(leaves);
      for (let index = 0; index < count; index += 1) {
        const proof = inclusionProof(tree, index);
        expect(indexMatchesPath(proof.leafIndex, proof.steps)).toBe(true);
      }
    }
  });

  it('refuse un autre index que celui du chemin', () => {
    const tree = buildTree(Array.from({ length: 8 }, (_, i) => sha256Hex(String(i))));
    const proof = inclusionProof(tree, 5);
    for (const wrong of [0, 1, 2, 3, 4, 6, 7])
      expect(indexMatchesPath(wrong, proof.steps)).toBe(false);
  });
});
