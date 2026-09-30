#!/bin/sh
# Build the Writ command-line programs for release: build-release.sh TAG OUTDIR.
# Portable sh; pure Go with cgo off, so every target cross-compiles.
set -eu
tag=$1
out=$(mkdir -p "$2" && cd "$2" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
cmds="writ writ-agent writ-demo writ-hook writ-mcp writ-mcp-proxy writ-gate"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${target%/*}
  arch=${target#*/}
  name="writ-$tag-$os-$arch"
  stage="$out/$name"
  mkdir -p "$stage"
  for c in $cmds; do
    if [ -d "$root/impl/go/cmd/$c" ]; then
      ( cd "$root/impl/go" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$stage/$c" "./cmd/$c" )
    fi
  done
  cp "$root/README.md" "$root/LICENSE" "$stage/"
  ( cd "$out" && tar -czf "$name.tar.gz" "$name" && rm -r "$name" )
done
( cd "$out" && if command -v sha256sum >/dev/null; then sha256sum ./*.tar.gz; else shasum -a 256 ./*.tar.gz; fi > SHA256SUMS )
echo "built $(ls "$out"/*.tar.gz | wc -l | tr -d ' ') archives in $out"
