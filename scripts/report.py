"""Redact TruffleHog JSON findings and summarize them with exe.dev remediations.

Reads TruffleHog's newline-delimited JSON on stdin. Raw secret values are
replaced by their length and a keyed fingerprint before anything is printed
or written, so the report is safe to show to an agent or a person.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys

DOCS = "https://exe.dev/docs"

# Lower-cased TruffleHog detector name -> (exe.dev replacement, doc path).
REMEDIATIONS = {
    "github": ("GitHub integration", "integrations-github.md"),
    "githubapp": ("GitHub integration", "integrations-github.md"),
    "githuboauth2": ("GitHub integration", "integrations-github.md"),
    "aws": ("AWS workload identity federation", "integrations-aws-wif.md"),
    "awssessionkey": ("AWS workload identity federation", "integrations-aws-wif.md"),
    "gcp": ("GCP workload identity federation", "integrations-gcp-wif.md"),
    "gcpapplicationdefaultcredentials": ("GCP workload identity federation", "integrations-gcp-wif.md"),
    "anthropic": ("Anthropic workload identity federation or LLM integration", "integrations-anthropic-wif.md"),
    "openai": ("OpenAI workload identity federation or LLM integration", "integrations-openai-wif.md"),
    "openaiadmin": ("OpenAI workload identity federation or LLM integration", "integrations-openai-wif.md"),
    "slackwebhook": ("Slack integration", "integrations-slack.md"),
    "slack": ("Slack bot integration", "integrations-slack-bot.md"),
    "discordwebhook": ("Discord integration", "integrations-discord.md"),
    "discordbottoken": ("Discord bot integration", "integrations-discord-bot.md"),
    "tailscale": ("Tailscale workload identity federation", "integrations-tailscale-wif.md"),
    "tailscaleapikey": ("Tailscale workload identity federation", "integrations-tailscale-wif.md"),
    "dockerhub": ("Container registry integration (check the catalog for your registry)", "integrations-oci-registries.md"),
    "docker": ("Container registry integration (check the catalog for your registry)", "integrations-oci-registries.md"),
    "privatekey": ("No integration: rotate it; for SSH access use VM-scoped SSH keys", "vm-scoped-ssh-keys.md"),
}

# Database credentials have no integration equivalent: lock down and rotate.
DATABASE_REMEDIATION = (
    "No integration: restrict file access, rotate the password, consider an egress policy",
    "internet-access.md",
)
for _name in ("postgres", "mongodb", "redis", "jdbc", "sqlserver", "uri"):
    REMEDIATIONS[_name] = DATABASE_REMEDIATION

DEFAULT_REMEDIATION = (
    "HTTP proxy header injection (or token-mint for short-lived tokens)",
    "integrations-http-proxy.md",
)


def mask(raw: str) -> str:
    # Length only: even a short prefix narrows the search for weak secrets.
    return f"<{len(raw)} chars>" if raw else ""


def load_key(path: str) -> bytes:
    """Return the per-VM fingerprint key, creating it (mode 600) on first use.

    Keying the fingerprint keeps it stable across scans, so the same secret can
    be matched between runs, without letting anyone who has only the report
    recover a short secret by hashing guesses.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "rb") as fh:
            return fh.read()
    with os.fdopen(fd, "wb") as fh:
        key = os.urandom(32)
        fh.write(key)
    return key


def fingerprint(raw: str, key: bytes) -> str:
    return hmac.new(key, raw.encode(), hashlib.sha256).hexdigest()[:12] if raw else ""


def location(meta: dict) -> dict:
    data = (meta or {}).get("Data") or {}
    if "Filesystem" in data:
        fs = data["Filesystem"]
        return {"source": "filesystem", "file": fs.get("file"), "line": fs.get("line")}
    if "Git" in data:
        g = data["Git"]
        return {
            "source": "git",
            "repository": g.get("repository"),
            "commit": g.get("commit"),
            "file": g.get("file"),
            "line": g.get("line"),
        }
    kind = next(iter(data), "unknown")
    return {"source": kind.lower()}


def status(finding: dict, verified_checked: bool) -> str:
    if finding.get("Verified"):
        return "verified"
    if not verified_checked:
        return "not checked"
    if finding.get("VerificationError") or finding.get("verificationError"):
        return "unknown"
    return "unverified"


def redact(finding: dict, verified_checked: bool, key: bytes) -> dict:
    raw = finding.get("RawV2") or finding.get("Raw") or ""
    name = finding.get("DetectorName") or "Unknown"
    replacement, doc = REMEDIATIONS.get(name.lower(), DEFAULT_REMEDIATION)
    extra = finding.get("ExtraData") or {}
    return {
        "detector": name,
        "status": status(finding, verified_checked),
        "preview": mask(finding.get("Raw") or ""),
        "fingerprint": fingerprint(raw, key),
        "location": location(finding.get("SourceMetadata")),
        "rotation_guide": extra.get("rotation_guide"),
        "replace_with": replacement,
        "docs": f"{DOCS}/{doc}",
    }


def where(loc: dict) -> str:
    if loc["source"] == "git":
        return f"{loc.get('repository')} @ {str(loc.get('commit'))[:8]}:{loc.get('file')}:{loc.get('line')}"
    if loc.get("file"):
        return f"{loc['file']}:{loc.get('line')}"
    return loc["source"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--verified-checked", type=int, default=0)
    args = ap.parse_args()
    checked = bool(args.verified_checked)
    key = load_key(args.key_file)

    findings, seen = [], set()
    for line in sys.stdin:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            raw_finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in raw_finding:
            continue
        f = redact(raw_finding, checked, key)
        dedupe = (f["fingerprint"], where(f["location"]))
        if dedupe in seen:
            continue
        seen.add(dedupe)
        findings.append(f)

    order = {"verified": 0, "unknown": 1, "not checked": 2, "unverified": 3}
    findings.sort(key=lambda f: (order[f["status"]], f["detector"]))

    with open(args.out, "w") as fh:
        json.dump({"verification": checked, "findings": findings}, fh, indent=2)

    secrets = len({f["fingerprint"] for f in findings})
    print(f"\n{len(findings)} finding(s), {secrets} distinct secret(s)\n")
    if findings:
        print("| Status | Detector | Location | Preview | Replace with |")
        print("| --- | --- | --- | --- | --- |")
        for f in findings:
            print(f"| {f['status']} | {f['detector']} | `{where(f['location'])}` "
                  f"| `{f['preview']}` | [{f['replace_with']}]({f['docs']}) |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
