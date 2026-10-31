# exechecker: secret scan for exe.dev VMs

A coding-agent skill that scans an [exe.dev](https://exe.dev) VM for leaked credentials with [TruffleHog](https://github.com/trufflesecurity/trufflehog), then helps move each one into an [exe.dev integration](https://exe.dev/docs/integrations.md) so it no longer lives on disk.

- **Redacted by design.** TruffleHog output is piped straight into `scripts/report.py`, which drops raw values before anything is printed or saved. Each secret appears only as its length and a keyed fingerprint (an HMAC whose key stays on the VM in `~/.cache/secret-scan/fingerprint.key`), so the report is safe to show an agent.
- **Maps findings to fixes.** GitHub tokens go to the GitHub integration; AWS, GCP, Anthropic, OpenAI and Tailscale keys go to workload identity federation; other HTTP APIs go to the HTTP proxy. See `references/remediation.md`.
- **Works locally or remotely.** Run it on the VM, or send `bootstrap.txt` (one shell command with the scripts embedded) through the exe.dev MCP server.
- **Pinned, verified install.** The first run downloads a fixed TruffleHog release and checks its SHA-256.

## Use as a skill

Copy this directory into your agent's skills folder (for Claude Code, `~/.claude/skills/secret-scan/`) and ask it to scan the VM for secrets. `SKILL.md` has the full workflow: scan, triage, remediate, rescan.

## Run directly

```bash
scripts/scan.sh                 # $HOME, /etc, /opt, /srv, /var/www, /root + git history of repos found there
scripts/scan.sh --verify        # also check which secrets are live (sends each to its provider)
scripts/scan.sh --no-git PATH   # one path, filesystem only
```

The redacted JSON report goes to `~/.cache/secret-scan/report-<timestamp>.json` (mode 600).

## Updating

After changing anything in `scripts/`, run `scripts/build-bootstrap.sh` to regenerate `bootstrap.txt`. To move to a new TruffleHog release, update `VERSION` and both checksums in `scripts/install.sh`.
