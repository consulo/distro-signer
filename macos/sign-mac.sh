#!/bin/bash
# Signs, notarizes and staples Consulo.app from an unsigned tar.gz, and packs it into dmg.
# Produces <out-dir>/<name> (signed, notarized, stapled dmg). Input tar.gz is not changed.
#
# usage: sign-mac.sh <input.tar.gz> <out-dir> <dmg-file-name>
#
# env:
#   MAC_SIGN_IDENTITY  - "Developer ID Application: ... (TEAMID)"
#   NOTARY_KEY_PATH    - path to App Store Connect API key (.p8)
#   NOTARY_KEY_ID      - API key id
#   NOTARY_ISSUER      - API key issuer id
set -euo pipefail

: "${MAC_SIGN_IDENTITY:?}" "${NOTARY_KEY_PATH:?}" "${NOTARY_KEY_ID:?}" "${NOTARY_ISSUER:?}"

INPUT=$1
OUT_DIR=$2
DMG_NAME=$3

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ENTITLEMENTS="$SCRIPT_DIR/entitlements.plist"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT_DIR" "$WORK/src"
OUT_DIR=$(cd "$OUT_DIR" && pwd)

tar -xzf "$INPUT" -C "$WORK/src"

APP=$(find "$WORK/src" -maxdepth 3 -type d -name '*.app' | head -n 1)
if [ -z "$APP" ]; then
  echo "No .app found in $INPUT" >&2
  exit 1
fi
echo "Signing $APP"

is_macho() {
  file -b "$1" | grep -q 'Mach-O'
}

sign() {
  codesign --force --timestamp --options runtime --sign "$MAC_SIGN_IDENTITY" "$@"
}

sign_file() {
  if file -b "$1" | grep -q 'executable'; then
    sign --entitlements "$ENTITLEMENTS" "$1"
  else
    sign "$1"
  fi
}

# prints paths deepest first
by_depth_desc() {
  awk -F/ '{ print NF "\t" $0 }' | sort -rn | cut -f2-
}

# Native libraries inside jars (jna, pty4j, etc) must be signed too, otherwise notarization fails
sign_jar() {
  local jar=$1
  local tmp="$WORK/jar"
  local list="$WORK/jar.list"

  rm -rf "$tmp" && mkdir -p "$tmp"
  : > "$list"

  unzip -qq -o "$jar" -d "$tmp" -x '*.class' 2>/dev/null || true

  while IFS= read -r f; do
    if is_macho "$f"; then
      sign_file "$f"
      echo "${f#$tmp/}" >> "$list"
    fi
  done < <(find "$tmp" -type f)

  if [ -s "$list" ]; then
    echo "  repacked $jar"
    (cd "$tmp" && zip -q "$jar" -@ < "$list")
  fi
}

# nested bundles (bundled JBR), deepest first
NESTED="$WORK/nested.list"
find "$APP" -mindepth 3 -type f -path '*/Contents/Info.plist' | while IFS= read -r plist; do
  dirname "$(dirname "$plist")"
done | by_depth_desc > "$NESTED"

# Bundles which still have valid signature (JBR signed & notarized by JetBrains) are kept as is
KEEP="$WORK/keep.list"
: > "$KEEP"
while IFS= read -r bundle; do
  if codesign --verify --deep --strict "$bundle" 2>/dev/null; then
    echo "keep existing signature: $bundle"
    echo "$bundle/" >> "$KEEP"
  fi
done < "$NESTED"

is_kept() {
  local prefix
  while IFS= read -r prefix; do
    case "$1" in "$prefix"*) return 0 ;; esac
  done < "$KEEP"
  return 1
}

echo "== jars"
while IFS= read -r jar; do
  is_kept "$jar" || sign_jar "$jar"
done < <(find "$APP" -type f -name '*.jar')

echo "== Mach-O files"
while IFS= read -r f; do
  if ! is_kept "$f" && is_macho "$f"; then
    sign_file "$f"
  fi
done < <(find "$APP" -type f | by_depth_desc)

echo "== nested bundles"
while IFS= read -r bundle; do
  is_kept "$bundle/" && continue
  # stale stapled ticket from previous signature
  rm -f "$bundle/Contents/CodeResources"
  sign "$bundle"
done < "$NESTED"

echo "== app"
sign --entitlements "$ENTITLEMENTS" "$APP"

codesign --verify --deep --strict --verbose=2 "$APP"

notarize() {
  local file=$1 result id status
  result=$(xcrun notarytool submit "$file" \
    --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" \
    --wait --output-format json)
  id=$(plutil -extract id raw -o - - <<< "$result")
  status=$(plutil -extract status raw -o - - <<< "$result")
  echo "Notarization $id: $status"
  if [ "$status" != "Accepted" ]; then
    xcrun notarytool log "$id" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" >&2
    exit 1
  fi
}

# app is stapled too - so it passes Gatekeeper offline after copying from dmg
echo "== notarize app"
ditto -c -k --keepParent "$APP" "$WORK/app.zip"
notarize "$WORK/app.zip"
xcrun stapler staple "$APP"

echo "== dmg"
DMG_ROOT="$WORK/dmg"
mkdir -p "$DMG_ROOT"
ditto "$APP" "$DMG_ROOT/$(basename "$APP")"
ln -s /Applications "$DMG_ROOT/Applications"
hdiutil create -volname "Consulo" -srcfolder "$DMG_ROOT" -format UDZO -ov "$OUT_DIR/$DMG_NAME"
codesign --force --timestamp --sign "$MAC_SIGN_IDENTITY" "$OUT_DIR/$DMG_NAME"
notarize "$OUT_DIR/$DMG_NAME"
xcrun stapler staple "$OUT_DIR/$DMG_NAME"

spctl -a -vvv -t exec "$APP"
spctl -a -vvv -t open --context context:primary-signature "$OUT_DIR/$DMG_NAME"

echo "Done: $OUT_DIR/$DMG_NAME"
