#!/usr/bin/env bash
# Print a one-line command that installs this exact copy of the skill on
# another machine: it downloads the matching release tag from GitHub, checks
# the files against this copy's checksum, and only then installs them into
# ~/.agents/skills/secret-scan (where Shelley and other agents look).
#
# The checksum is a SHA-256 over every file (sorted; .git and __pycache__
# excluded), so it does not depend on how GitHub compresses the tarball. The check is written into
# the printed command, not read from the download, so a tampered download
# cannot vouch for itself.
#
# Usage: install-command.sh            print the command
#        install-command.sh --sum      print only the checksum
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="https://github.com/HLD/exechecker"
HASH='find . \( -name .git -o -name __pycache__ \) -prune -o -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-64'

VERSION="$(sed -n 's/^  version: "\(.*\)"$/\1/p' "$SKILL_DIR/SKILL.md")"
SUM="$(cd "$SKILL_DIR" && eval "$HASH")"

if [[ "${1:-}" == "--sum" ]]; then
  echo "$SUM"
  exit 0
fi

# No single quotes, so callers can wrap the whole thing as: ssh <vm> '<command>'
printf '%s\n' "V=$VERSION S=$SUM; D=~/.agents/skills/secret-scan; if grep -qs \"version: \\\"\$V\\\"\" \"\$D/SKILL.md\"; then echo \"secret-scan \$V already installed\"; else T=\$(mktemp -d); curl -fsSL \"$REPO/archive/refs/tags/v\$V.tar.gz\" | tar -xzf - --strip-components=1 -C \"\$T\" && [ \"\$(cd \"\$T\" && $HASH)\" = \"\$S\" ] && mkdir -p \"\${D%/*}\" && rm -rf \"\$D\" && mv \"\$T\" \"\$D\" && chmod 755 \"\$D\" && echo \"installed secret-scan \$V\" || { echo \"secret-scan install failed or checksum mismatch\" >&2; rm -rf \"\$T\"; false; }; fi"
