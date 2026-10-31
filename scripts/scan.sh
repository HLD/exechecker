#!/usr/bin/env bash
# Scan this VM for secrets with TruffleHog and write a redacted report.
#
# Usage: scan.sh [--verify] [--no-git] [PATH ...]
#   --verify   check findings against provider APIs (sends each secret to its provider)
#   --no-git   skip scanning git history of repositories found under the scan paths
#   PATH       paths to scan (default: $HOME /etc /opt /srv /var/www /root)
#
# Raw secret values never leave this script: TruffleHog output is piped straight
# into report.py, which masks them. Only the redacted report is written to disk.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${HOME}/.cache/secret-scan"
TRUFFLEHOG="${HOME}/.local/bin/trufflehog"

VERIFY=0
GIT=1
PATHS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify) VERIFY=1 ;;
    --no-git) GIT=0 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) PATHS+=("$1") ;;
  esac
  shift
done

if [[ ${#PATHS[@]} -eq 0 ]]; then
  for p in "$HOME" /etc /opt /srv /var/www /root; do
    [[ -r "$p" ]] && PATHS+=("$p")
  done
fi

[[ -x "$TRUFFLEHOG" ]] || "$SCRIPT_DIR/install.sh"

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

VERIFY_ARGS=(--no-verification)
[[ $VERIFY -eq 1 ]] && VERIFY_ARGS=()

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$OUT_DIR/report-$STAMP.json"

{
  echo "scanning filesystem: ${PATHS[*]}" >&2
  "$TRUFFLEHOG" filesystem "${PATHS[@]}" \
    --json --no-update --exclude-paths="$SCRIPT_DIR/exclude-paths.txt" \
    "${VERIFY_ARGS[@]}" 2>/dev/null || true

  if [[ $GIT -eq 1 ]]; then
    while IFS= read -r gitdir; do
      repo="$(dirname "$gitdir")"
      echo "scanning git history: $repo" >&2
      "$TRUFFLEHOG" git "file://$repo" --json --no-update \
        "${VERIFY_ARGS[@]}" 2>/dev/null || true
    done < <(find "${PATHS[@]}" -maxdepth 5 \
               \( -name node_modules -o -name .cache -o -name plugins \) -prune -o \
               -type d -name .git -print 2>/dev/null)
  fi
} | python3 -I "$SCRIPT_DIR/report.py" --verified-checked "$VERIFY" \
    --key-file "$OUT_DIR/fingerprint.key" --out "$REPORT"

chmod 600 "$REPORT"
echo >&2
echo "redacted report: $REPORT" >&2
