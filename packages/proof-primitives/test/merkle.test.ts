import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  buildTree,
  inclusionProof,
  PrimitiveError,
  sha256Hex,
  verifyInclusion,
  type InclusionProof,
} from '../src/index';
import { loadJson } from './vectors';

type Vector = { leaves: string[]; root: string; proofs: InclusionProof[] };
const vectors = loadJson<Vector[]>('merkle.json');
const leaf = (i: number): string => sha256Hex(`leaf-${i}`);

describe('vecteurs de référence', () => {
  it.each(vectors.map((v) => [v.leaves.length, v] as const))(
    'n=%i : même racine et mêmes preuves que l’implémentation de référence',
    (_n, vector) => {
      const tree = buildTree(vector.leaves);
      expect(tree.root).toBe(vector.root);
      vector.leaves.forEach((leafHash, index) => {
        const proof = inclusionProof(tree, index);
        expect(proof).toEqual(vector.proofs[index]);
        expect(verifyInclusion(leafHash, proof, vector.root)).toBe(true);
      });
    },
  );
});

describe('buildTree', () => {
  it('refuse un arbre vide', () => {
    expect(() => buildTree([])).toThrowError(expect.objectContaining({ code: 'EMPTY_TREE' }));
  });

  it('refuse une feuille qui n’est pas un SHA-256', () => {
    expect(() => buildTree(['nope'])).toThrowError(
      expect.objectContaining({ code: 'INVALID_HEX' }),
    );
  });

  it('une feuille unique est sa propre racine', () => {
    expect(buildTree([leaf(0)]).root).toBe(leaf(0));
  });

  it('la racine dépend de l’ordre des feuilles', () => {
    expect(buildTree([leaf(0), leaf(1)]).root).not.toBe(buildTree([leaf(1), leaf(0)]).root);
  });
});

describe('inclusionProof', () => {
  it('refuse un index hors bornes', () => {
    const tree = buildTree([leaf(0), leaf(1)]);
    for (const index of [-1, 2, 1.5]) {
      expect(() => inclusionProof(tree, index)).toThrow(PrimitiveError);
    }
  });
});

describe('verifyInclusion', () => {
  const leaves = [0, 1, 2, 3, 4].map(leaf);
  const tree = buildTree(leaves);
  const proof = inclusionProof(tree, 2);

  it('refuse une autre feuille', () => {
    expect(verifyInclusion(leaf(9), proof, tree.root)).toBe(false);
  });

  it('refuse une autre racine', () => {
    expect(verifyInclusion(leaves[2] as string, proof, leaf(9))).toBe(false);
  });

  it('refuse une preuve altérée', () => {
    const tampered: InclusionProof = {
      ...proof,
      steps: proof.steps.map((s, i) => (i === 0 ? { ...s, hash: leaf(9) } : s)),
    };
    expect(verifyInclusion(leaves[2] as string, tampered, tree.root)).toBe(false);
  });

  it('refuse un côté inversé', () => {
    const flipped: InclusionProof = {
      ...proof,
      steps: proof.steps.map((s, i) =>
        i === 0 ? { ...s, position: s.position === 'left' ? 'right' : 'left' } : s,
      ),
    };
    expect(verifyInclusion(leaves[2] as string, flipped, tree.root)).toBe(false);
  });

  it('renvoie false (sans lever) sur des entrées malformées', () => {
    expect(verifyInclusion('zz', proof, tree.root)).toBe(false);
    expect(verifyInclusion(leaves[2] as string, proof, 'zz')).toBe(false);
    expect(
      verifyInclusion(
        leaves[2] as string,
        { leafIndex: 0, steps: [{ hash: 'zz', position: 'left' }] },
        tree.root,
      ),
    ).toBe(false);
  });
});

describe('propriétés', () => {
  const leafSets = fc.array(fc.uint8Array({ minLength: 1, maxLength: 8 }), {
    minLength: 1,
    maxLength: 40,
  });

  it('toute feuille est prouvable et la preuve échoue pour une autre feuille', () => {
    fc.assert(
      fc.property(leafSets, (inputs) => {
        const hashes = inputs.map((bytes) => sha256Hex(bytes));
        const tree = buildTree(hashes);
        hashes.forEach((hash, index) => {
          const proof = inclusionProof(tree, index);
          expect(verifyInclusion(hash, proof, tree.root)).toBe(true);
          expect(verifyInclusion(sha256Hex(`${hash}x`), proof, tree.root)).toBe(false);
        });
      }),
    );
  });
});
