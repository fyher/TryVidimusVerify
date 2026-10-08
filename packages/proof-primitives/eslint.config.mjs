import base from '../../tooling/eslint.mjs';

const config = [
  ...base,
  {
    // ADR-0014 : aucun accès à l'environnement ni à la console dans un paquet.
    files: ['src/**/*.ts'],
    rules: {
      'no-console': 'error',
      'no-restricted-properties': [
        'error',
        { object: 'process', property: 'env', message: 'Injecter la configuration (ADR-0014).' },
      ],
    },
  },
  {
    files: ['test/**/*.ts', 'scripts/**/*.ts'],
    rules: { 'max-lines-per-function': 'off', 'max-lines': 'off', 'no-console': 'off' },
  },
  { files: ['vitest.config.ts'], rules: { 'no-restricted-syntax': 'off' } },
];

export default config;
