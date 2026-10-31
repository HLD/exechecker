---
name: secret-scan
description: Scan this exe.dev VM for leaked secrets and credentials (API keys, tokens, private keys, webhooks) with TruffleHog, then help move each one into an exe.dev integration so it no longer lives on disk. Use when the user asks to scan for secrets, audit credentials, check for leaked keys, or clean up API keys on their VM.
---

# Secret scan

Find secrets on this VM, report them without exposing their values, and replace each one with an exe.dev integration. Integrations keep credentials outside the VM: the VM can use them but never read them.

## Rules

- **Never print, read or quote a secret value.** Work only from the redacted report. Do not `cat`, `grep` or open the lines a finding points to. To show context, mask the values first (e.g. `sed -E 's/(=|: *)[^ ]{8,}/\1<redacted>/' FILE`).
- **Verification is opt-in.** `--verify` sends each secret to its provider's API to check if it is live. Ask the user before using it.
- Do not delete or edit files that hold secrets until the replacement is working and the user has approved the change.

## Where you are running

- **On the VM** (you have a shell there): run `scripts/scan.sh` directly, as in step 1.
- **Remotely, through the exe.dev MCP server** (you have `run_vm_command` from the exe.dev plugin, or `exec` from `https://exe.dev/mcp`): the scripts are not on the VM. Follow "Remote scan" below instead of step 1, then continue at step 2.

## Remote scan (exe.dev MCP)

1. List VMs (`list_vms`, or `exec` with `ls --json`) and ask the user which to scan. Use only names the tool returned.
2. Read `bootstrap.txt` in this skill. It is one shell command that unpacks the scan scripts into `~/.secret-scan-skill` on the VM and runs a scan. Append flags at the end if needed (`--verify`, `--no-git`, paths).
3. Send it to each chosen VM:
    - `run_vm_command`: pass the contents of `bootstrap.txt` as the command, for that VM.
    - `exec`: pass `ssh <vm> '<contents of bootstrap.txt>'`. It contains no single quotes, so the outer quotes keep the lobby from splitting it.
4. `exec` returns after `wait_seconds` (max 45) and leaves longer commands running as a job; follow it with `wait`. Later scans on the same VM can run `~/.secret-scan-skill/scripts/scan.sh` directly.

Only the redacted table comes back over MCP; raw values stay on the VM.

## 1. Scan

Confirm the scope with the user, then run:

```bash
scripts/scan.sh                 # $HOME, /etc, /opt, /srv, /var/www, /root + git history of repos found there
scripts/scan.sh --verify        # also check which secrets are live (ask first)
scripts/scan.sh --no-git PATH   # one path, filesystem only
```

The first run installs a pinned, checksum-verified TruffleHog into `~/.local/bin`. The script prints a Markdown table and writes a redacted JSON report to `~/.cache/secret-scan/report-<timestamp>.json` (mode 600). Raw values never reach the report: each secret appears only as its length and a fingerprint. The fingerprint is an HMAC keyed by `~/.cache/secret-scan/fingerprint.key` (mode 600, created on first scan), so it matches the same secret across scans but cannot be brute-forced from the report alone.

## 2. Triage

Present the table to the user, verified findings first. Flag likely false positives:

- matches inside compiled binaries or bundled JS (e.g. agent installs under `~/.local`)
- test fixtures, docs examples and vendored code
- the same fingerprint at several locations is one secret; count it once

Secrets in git history stay exposed even after the file is fixed; treat them as leaked and rotate.

## 3. Remediate

For each real secret, follow `references/remediation.md`:

1. Create the matching exe.dev integration (the report's `replace_with` and `docs` fields say which). Fetch the linked doc before giving commands. Integrations are managed in the exe.dev lobby (`ssh exe.dev integrations ...`), which a VM cannot reach.
    - **No secret needed** (workload identity federation for AWS, GCP, Anthropic, OpenAI and Tailscale; GitHub): with the MCP `exec` tool, you can run `integrations add` and `integrations attach <name> vm:<vm>` after the user confirms.
    - **Secret needed** (`http-proxy --bearer`, webhooks): do not pass the secret through a tool call or chat. Give the user the command with a placeholder, e.g. `ssh exe.dev integrations add http-proxy --name myapi --target https://api.example.com --bearer <your-key> --attach vm:<vm>`, and have them run it in their own terminal. Better still, have them mint a fresh key for the integration and revoke the leaked one.
2. Attach it to this VM and point the app or config at the integration hostname instead of the raw key.
3. Confirm the app still works.
4. With the user's approval, remove the secret from the file.
5. Tell the user to rotate or revoke the old secret with the provider (use `rotation_guide` when the report has one).

## 4. Rescan

Run `scripts/scan.sh` again and confirm the fixed findings are gone.
