# Golden proofs du mode `direct` (ADR-0026)

`direct-freetsa-photo` : jeton **réel** de FreeTSA (`https://freetsa.org/tsr`), obtenu le 2026-10-07 pour le `manifest_sha256` de la preuve, avec l'empreinte du jeton égale au condensat lui-même. `direct-simulated-photo` : jeton d'une autorité simulée dont l'autorité racine est dans son `trust-chain.pem`.

Ces deux dossiers reprennent les médias, le dossier et les ancres C2PA de `freetsa-photo` et `direct-upload-simulated` ; seuls changent `proof_id` (donc `manifest_sha256`) et l'horodatage, au format `timestamp: { mode: "direct", … }`. **Ils ne sont jamais régénérés** : un jeton réel ne se refait pas à l'identique, et le test doit rester vert à chaque version du vérificateur.

Chaque jeton se vérifie sans notre code :

```
openssl ts -verify -digest <manifest_sha256 du bundle.json> -in <timestamp.tsr_base64 décodé> -CAfile trust-chain.pem
```
