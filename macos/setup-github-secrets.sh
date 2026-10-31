#!/bin/bash
# Builds .p12 from Developer ID certificate + private key and uploads all signing secrets to GitHub.
# Run it again after yearly certificate renewal.
#
# usage: setup-github-secrets.sh <dir>
#
# <dir> must contain:
#   *.key                 - private key used for CSR
#   *.cer                 - Developer ID Application certificate downloaded from Apple
#   AuthKey_<KEYID>.p8    - App Store Connect API key
#
# env:
#   NOTARY_ISSUER  - App Store Connect issuer id (asked if not set)
#   REPO           - target repo, default consulo/distro-signer
#   GH_ENV         - GitHub environment name, if secrets must be stored in environment
#   DRY_RUN=1      - check everything and build .p12, but do not upload
set -euo pipefail

DIR=${1:?usage: setup-github-secrets.sh <dir>}
REPO=${REPO:-consulo/distro-signer}

for tool in openssl curl base64; do
  command -v "$tool" >/dev/null || { echo "$tool not found" >&2; exit 1; }
done
if [ "${DRY_RUN:-}" != 1 ]; then
  command -v gh >/dev/null || { echo "gh not found" >&2; exit 1; }
  gh auth status >/dev/null 2>&1 || { echo "gh is not logged in, run: gh auth login" >&2; exit 1; }
fi

cd "$DIR"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

single() {
  local pattern=$1 found
  found=$(find . -maxdepth 1 -type f -name "$pattern" ! -name 'DeveloperIDG2CA.cer' | sed 's#^\./##')
  if [ "$(printf '%s\n' "$found" | grep -c .)" != 1 ]; then
    echo "Expected exactly one $pattern in $DIR, found: ${found:-none}" >&2
    exit 1
  fi
  echo "$found"
}

modulus() {
  sha256sum | cut -d' ' -f1
}

KEY=$(single '*.key')
CER=$(single '*.cer')
P8=$(single 'AuthKey_*.p8')

echo "== certificate"
if grep -q 'BEGIN CERTIFICATE' "$CER"; then
  cp "$CER" "$WORK/cert.pem"
else
  openssl x509 -inform DER -in "$CER" -out "$WORK/cert.pem"
fi

IDENTITY=$(openssl x509 -noout -subject -nameopt multiline -in "$WORK/cert.pem" | sed -n 's/^ *commonName *= *//p')
case "$IDENTITY" in
  "Developer ID Application: "*) ;;
  *) echo "Not a Developer ID Application certificate: $IDENTITY" >&2; exit 1 ;;
esac
echo "identity: $IDENTITY"
echo "expires:  $(openssl x509 -noout -enddate -in "$WORK/cert.pem" | cut -d= -f2)"

if ! openssl x509 -noout -checkend 0 -in "$WORK/cert.pem" >/dev/null; then
  echo "Certificate expired" >&2
  exit 1
fi

if [ "$(openssl x509 -noout -modulus -in "$WORK/cert.pem" | modulus)" != "$(openssl rsa -noout -modulus -in "$KEY" 2>/dev/null | modulus)" ]; then
  echo "$KEY does not match $CER - certificate was issued for another CSR/key" >&2
  exit 1
fi
echo "key:      $KEY matches"

# intermediate CA must be inside .p12, otherwise codesign can fail to build chain on runner
curl -fsSL -o "$WORK/g2.cer" https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
openssl x509 -inform DER -in "$WORK/g2.cer" -out "$WORK/g2.pem"
# Apple certificates have own critical extension, which openssl does not know
openssl verify -ignore_critical -partial_chain -CAfile "$WORK/g2.pem" "$WORK/cert.pem" >/dev/null
echo "chain:    OK (Developer ID G2)"

echo "== p12"
# random password - .p12 is used only by CI, private key stays in $DIR
P12_PASSWORD=$(openssl rand -base64 32 | tr -d '\n/+=')
export P12_PASSWORD
# -legacy: macOS `security import` can not read OpenSSL 3 default .p12 encryption
openssl pkcs12 -export -legacy \
  -inkey "$KEY" -in "$WORK/cert.pem" -certfile "$WORK/g2.pem" \
  -name "Developer ID Application" \
  -passout env:P12_PASSWORD -out "$WORK/devid.p12"
openssl pkcs12 -legacy -in "$WORK/devid.p12" -passin env:P12_PASSWORD -noout
echo "p12:      OK"

echo "== notary key"
NOTARY_KEY_ID=${P8#AuthKey_}
NOTARY_KEY_ID=${NOTARY_KEY_ID%.p8}
grep -q 'BEGIN PRIVATE KEY' "$P8" || { echo "$P8 is not a private key" >&2; exit 1; }
echo "key id:   $NOTARY_KEY_ID"

if [ -z "${NOTARY_ISSUER:-}" ]; then
  read -r -p "App Store Connect Issuer ID: " NOTARY_ISSUER
fi
if ! [[ "$NOTARY_ISSUER" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "Issuer ID must be UUID: $NOTARY_ISSUER" >&2
  exit 1
fi
echo "issuer:   $NOTARY_ISSUER"

if [ "${DRY_RUN:-}" = 1 ]; then
  echo "DRY_RUN - nothing uploaded"
  exit 0
fi

TARGET="--repo $REPO"
[ -n "${GH_ENV:-}" ] && TARGET="$TARGET --env $GH_ENV"

echo
echo "Will set secrets in $REPO${GH_ENV:+ (environment $GH_ENV)}:"
echo "  MAC_CERT_P12_BASE64 MAC_CERT_PASSWORD MAC_SIGN_IDENTITY NOTARY_KEY_P8_BASE64 NOTARY_KEY_ID NOTARY_ISSUER"
read -r -p "Continue? [y/N] " answer
[ "$answer" = y ] || [ "$answer" = Y ] || { echo "Cancelled"; exit 1; }

# values go via stdin - not visible in process list
set_secret() {
  # shellcheck disable=SC2086
  gh secret set "$1" $TARGET
  echo "  $1 set"
}

base64 < "$WORK/devid.p12" | tr -d '\n' | set_secret MAC_CERT_P12_BASE64
printf '%s' "$P12_PASSWORD" | set_secret MAC_CERT_PASSWORD
printf '%s' "$IDENTITY" | set_secret MAC_SIGN_IDENTITY
base64 < "$P8" | tr -d '\n' | set_secret NOTARY_KEY_P8_BASE64
printf '%s' "$NOTARY_KEY_ID" | set_secret NOTARY_KEY_ID
printf '%s' "$NOTARY_ISSUER" | set_secret NOTARY_ISSUER

echo "Done. Certificate expires $(openssl x509 -noout -enddate -in "$WORK/cert.pem" | cut -d= -f2) - run this script again after renewal."
