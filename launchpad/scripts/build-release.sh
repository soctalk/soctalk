#!/usr/bin/env bash
# Cross-build the launchpad CLI and every plugin for the release matrix into
# dist/artifacts, then hand off to lpindex for index generation + signing.
#
# Required env: VERSION, PUBKEY (hex ed25519 public key), BASE_URL.
# Pure-Go (CGO disabled), so a single Linux runner cross-compiles all targets.
set -euo pipefail

cd "$(dirname "$0")/.."   # launchpad/
: "${VERSION:?set VERSION}"
: "${PUBKEY:?set PUBKEY}"
: "${BASE_URL:?set BASE_URL}"

OUT="$(pwd)/dist/artifacts"
rm -rf "$OUT"; mkdir -p "$OUT"

TARGETS=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64" "windows/amd64" "windows/arm64")
PUBVAR="github.com/soctalk/launchpad/internal/pluginstore.releasePublicKey"
LDFLAGS="-s -w -X main.version=${VERSION} -X ${PUBVAR}=${PUBKEY}"

for t in "${TARGETS[@]}"; do
  os="${t%/*}"; arch="${t#*/}"; ext=""; [ "$os" = windows ] && ext=".exe"

  echo ">> cli ${os}/${arch}"
  ( cd cli && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
      go build -trimpath -ldflags "$LDFLAGS" \
      -o "$OUT/launchpad_${os}_${arch}${ext}" ./cmd/launchpad )

  for d in plugins/*/; do
    name="$(basename "$d")"
    [ "$name" = "mock" ] && continue          # reference plugin, not shipped
    [ -f "${d}go.mod" ] || continue
    echo ">> plugin ${name} ${os}/${arch}"
    if ! ( cd "$d" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
        go build -trimpath -o "$OUT/${name}_${os}_${arch}${ext}" . ); then
      echo "   (skip ${name} ${os}/${arch}: not buildable for this platform)"
    fi
  done
done

echo ">> generating + signing index"
( cd cli && go build -trimpath -o "$OUT/../lpindex" ./cmd/lpindex )
"$OUT/../lpindex" build \
  --plugins-src plugins \
  --artifacts "$OUT" \
  --base-url "$BASE_URL" \
  --version "$VERSION" \
  --out "$OUT"

rm -f "$OUT/../lpindex"

echo ">> creating offline bundle"
# Tar the artifacts (index + signature + binaries) into an air-gapped bundle.
# Built before the file exists in $OUT, so it never includes itself.
( cd "$OUT" && tar -czf "../launchpad-plugins-bundle.tar.gz" . )
mv "$OUT/../launchpad-plugins-bundle.tar.gz" "$OUT/"

echo ">> release artifacts in $OUT"
ls -1 "$OUT"
