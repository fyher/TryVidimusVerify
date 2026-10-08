#!/usr/bin/env bash
# Génère fixtures/tsa/ : une autorité de test locale (openssl) et un jeton réel FreeTSA.
# Les clés de test sont jetables et n'ont aucune valeur ; ne sert qu'aux tests. Jamais lancé en CI.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=fixtures/tsa
TSX="${TSX:-tsx}"
mkdir -p "$OUT"; W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

ROOT=$(printf 'proof-primitives tsa vector' | shasum -a 256 | cut -d' ' -f1)
NONCE=1122334455667788
echo "$ROOT" > "$OUT/root.hex"

# --- Autorité de test : CA + certificat TSA (EKU timeStamping critique, comme RFC 3161 l'exige)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/ca.key" -out "$OUT/ca.pem" -days 36500 \
  -subj "/C=FR/O=Test Timestamp Authority/CN=Test Root CA" 2>/dev/null
cat > "$W/tsa.ext" <<X
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
X
openssl req -newkey rsa:2048 -nodes -keyout "$W/tsa.key" -out "$W/tsa.csr" \
  -subj "/C=FR/O=Test Timestamp Authority/CN=Test TSA Unit" 2>/dev/null
openssl x509 -req -in "$W/tsa.csr" -CA "$OUT/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
  -out "$W/tsa.pem" -days 36500 -extfile "$W/tsa.ext" 2>/dev/null
cat > "$W/ts.cnf" <<X
[tsa]
default_tsa=tsa_config
[tsa_config]
serial=$W/serial
crypto_device=builtin
signer_cert=$W/tsa.pem
certs=$OUT/ca.pem
signer_key=$W/tsa.key
default_policy=1.2.3.4.5
digests=sha256
signer_digest=sha256
accuracy=secs:1
ordering=no
tsa_name=yes
ess_cert_id_chain=no
X
echo 01 > "$W/serial"

# --- Requête construite par NOTRE code (nonce imposé), réponse signée par l'autorité de test
"$TSX" --eval "
import { writeFileSync } from 'node:fs';
import { buildTimeStampReq } from './src/index.ts';
const { reqBytes } = await buildTimeStampReq('$ROOT', { nonceHex: '$NONCE' });
writeFileSync('$OUT/synthetic.tsq', reqBytes);
" --input-type=module 2>/dev/null || "$TSX" -e "
import { writeFileSync } from 'node:fs';
import { buildTimeStampReq } from './src/index.ts';
buildTimeStampReq('$ROOT', { nonceHex: '$NONCE' }).then((r) => writeFileSync('$OUT/synthetic.tsq', r.reqBytes));
"
openssl ts -reply -queryfile "$OUT/synthetic.tsq" -config "$W/ts.cnf" -section tsa_config -out "$OUT/synthetic.tsr"
printf '%s' "$NONCE" > "$OUT/synthetic.nonce"

# --- Jeton réel FreeTSA (réseau ; seul un hash de test est envoyé)
if curl -fsS -m 20 https://freetsa.org/files/cacert.pem -o "$OUT/freetsa-ca.pem" \
  && openssl ts -query -digest "$(printf '%s' "$ROOT" | xxd -r -p | shasum -a 256 | cut -d' ' -f1)" -sha256 -cert -out "$W/f.tsq" \
  && curl -fsS -m 20 -H 'Content-Type: application/timestamp-query' --data-binary @"$W/f.tsq" https://freetsa.org/tsr -o "$OUT/freetsa.tsr"; then
  openssl ts -reply -in "$OUT/freetsa.tsr" -text | head -20 > "$OUT/freetsa.info.txt"
  echo "FreeTSA : OK"
else
  echo "FreeTSA indisponible : jeton réel non régénéré" >&2
fi
ls -la "$OUT"
