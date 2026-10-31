#!/usr/bin/env bash
# Install a pinned, checksum-verified TruffleHog binary into ~/.local/bin.
set -euo pipefail

VERSION="3.99.2"
SHA256_AMD64="3c7b0d1dc4278294269bfdd7594bca8bb28c78da0a4a06ad202ded37b48deca4"
SHA256_ARM64="929b81efffca752eafd58bf6f17bf725d354f338636a7bbbee65c086d2f9ddf3"
BIN_DIR="${HOME}/.local/bin"
BIN="${BIN_DIR}/trufflehog"

if [[ -x "$BIN" ]] && "$BIN" --version 2>&1 | grep -q "$VERSION"; then
  echo "trufflehog $VERSION already installed at $BIN"
  exit 0
fi

case "$(uname -m)" in
  x86_64)        ARCH=amd64; SHA="$SHA256_AMD64" ;;
  aarch64|arm64) ARCH=arm64; SHA="$SHA256_ARM64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TARBALL="trufflehog_${VERSION}_linux_${ARCH}.tar.gz"
URL="https://github.com/trufflesecurity/trufflehog/releases/download/v${VERSION}/${TARBALL}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "downloading $URL"
curl -fsSL -o "$WORK/$TARBALL" "$URL"
echo "$SHA  $WORK/$TARBALL" | sha256sum -c --quiet
tar -xzf "$WORK/$TARBALL" -C "$WORK" trufflehog

mkdir -p "$BIN_DIR"
install -m 0755 "$WORK/trufflehog" "$BIN"
echo "installed trufflehog $VERSION at $BIN"
