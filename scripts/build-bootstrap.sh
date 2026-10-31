#!/usr/bin/env bash
# Regenerate bootstrap.txt: one VM shell command that unpacks the scan scripts
# into ~/.secret-scan-skill and runs a scan. Lets an agent that only has a
# run-a-command tool (the exe.dev MCP server) use this skill on a remote VM.
# Rerun after changing anything in scripts/.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAYLOAD="$(tar --owner=0 --group=0 --numeric-owner --mtime=@0 --sort=name -cf - -C "$SKILL_DIR" scripts/install.sh scripts/scan.sh scripts/report.py scripts/exclude-paths.txt | gzip -n | base64 -w0)"

printf 'mkdir -p ~/.secret-scan-skill && echo %s | base64 -d | tar -xzf - -C ~/.secret-scan-skill && ~/.secret-scan-skill/scripts/scan.sh\n' \
  "$PAYLOAD" > "$SKILL_DIR/bootstrap.txt"
echo "wrote $SKILL_DIR/bootstrap.txt ($(wc -c < "$SKILL_DIR/bootstrap.txt") bytes)"
