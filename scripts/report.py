"""Redact TruffleHog JSON findings and summarize them with exe.dev remediations.

Reads TruffleHog's newline-delimited JSON on stdin. Raw secret values are
replaced by their length and a keyed fingerprint before anything is printed
or written, so the report is safe to show to an agent or a person.

Each finding is mapped to the exe.dev integration that replaces it: a built-in
type from REMEDIATIONS, else a catalog service from catalog.json (regenerate
with update-catalog.py), else the generic HTTP proxy. Given the VM's attached
integrations (from the Reflection integration), it also names any already
attached integration that covers the finding.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

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
for _name in ("mongodb", "redis", "jdbc", "sqlserver", "uri"):
    REMEDIATIONS[_name] = DATABASE_REMEDIATION
# Database integrations are still rolling out, so keep the fallback in view.
REMEDIATIONS["postgres"] = (
    "Postgres database integration (db:postgres) if your account has it; "
    "otherwise restrict file access and rotate the password",
    "integrations-catalog.md",
)

# Detector -> (attached integration types that cover it, word its name or help
# must contain). Catalog services are matched separately, by service name.
ATTACHED_MATCH = {
    "github": (("github",), None),
    "githubapp": (("github",), None),
    "githuboauth2": (("github",), None),
    "aws": (("wif",), "aws"),
    "awssessionkey": (("wif",), "aws"),
    "gcp": (("wif",), "gcp"),
    "gcpapplicationdefaultcredentials": (("wif",), "gcp"),
    "anthropic": (("wif", "llm"), "anthropic"),
    "openai": (("wif", "llm"), "openai"),
    "openaiadmin": (("wif", "llm"), "openai"),
    "tailscale": (("wif",), "tailscale"),
    "tailscaleapikey": (("wif",), "tailscale"),
    "slackwebhook": (("slack",), None),
    "slack": (("slack", "slack-bot"), None),
    "discordwebhook": (("discord",), None),
    "discordbottoken": (("discord",), None),
}
# The LLM gateway serves both providers without naming them in its help.
LLM_TYPES_ANY_PROVIDER = {"anthropic", "openai", "openaiadmin"}

CONNECT_LINKS = {"postgres": "db:postgres"}

CATALOG = json.loads((Path(__file__).resolve().parent / "catalog.json").read_text())

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


def remediation(detector: str) -> tuple:
    """Return (replacement, doc path, catalog handle or None) for a detector."""
    d = detector.lower()
    if d in REMEDIATIONS:
        return (*REMEDIATIONS[d], CONNECT_LINKS.get(d))
    if d in CATALOG:
        svc = CATALOG[d]
        return (f"Catalog integration: {svc['name']} ({svc['handle']})",
                "integrations-catalog.md", svc["handle"])
    return (*DEFAULT_REMEDIATION, None)


def attached_for(detector: str, attached: list) -> list:
    """Names of attached integrations that already cover this detector."""
    d = detector.lower()
    names = []
    for i in attached:
        itype, name, help_ = i.get("type", ""), i.get("name", ""), i.get("help", "")
        if d in ATTACHED_MATCH:
            types, word = ATTACHED_MATCH[d]
            if itype not in types:
                continue
            if word and word not in f"{name} {help_}".lower():
                if not (itype == "llm" and d in LLM_TYPES_ANY_PROVIDER):
                    continue
            names.append(name)
        elif d in CATALOG and itype == "catalog":
            service = CATALOG[d]["name"].split(" (")[0]
            if help_.startswith(service):
                names.append(name)
    return names


def redact(finding: dict, verified_checked: bool, key: bytes, attached: list, vm: str) -> dict:
    raw = finding.get("RawV2") or finding.get("Raw") or ""
    name = finding.get("DetectorName") or "Unknown"
    replacement, doc, handle = remediation(name)
    extra = finding.get("ExtraData") or {}
    link = None
    if handle:
        link = f"https://exe.dev/integrations/add?service={quote(handle, safe=":")}"
        if vm:
            link += f"&attach=vm:{quote(vm)}"
    return {
        "detector": name,
        "status": status(finding, verified_checked),
        "preview": mask(finding.get("Raw") or ""),
        "fingerprint": fingerprint(raw, key),
        "location": location(finding.get("SourceMetadata")),
        "rotation_guide": extra.get("rotation_guide"),
        "replace_with": replacement,
        "docs": f"{DOCS}/{doc}",
        "connect_link": link,
        "already_attached": attached_for(name, attached),
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
    ap.add_argument("--attached", help="Reflection /integrations JSON (optional)")
    ap.add_argument("--vm", default="", help="this VM's name, for connect links")
    args = ap.parse_args()
    checked = bool(args.verified_checked)
    key = load_key(args.key_file)
    attached = []
    if args.attached:
        try:
            with open(args.attached) as fh:
                attached = json.load(fh).get("integrations") or []
        except (OSError, ValueError, AttributeError):
            attached = []

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
        f = redact(raw_finding, checked, key, attached, args.vm)
        dedupe = (f["fingerprint"], where(f["location"]))
        if dedupe in seen:
            continue
        seen.add(dedupe)
        findings.append(f)

    order = {"verified": 0, "unknown": 1, "not checked": 2, "unverified": 3}
    findings.sort(key=lambda f: (order[f["status"]], f["detector"]))

    with open(args.out, "w") as fh:
        json.dump({"verification": checked, "vm": args.vm, "findings": findings}, fh, indent=2)

    secrets = len({f["fingerprint"] for f in findings})
    print(f"\n{len(findings)} finding(s), {secrets} distinct secret(s)\n")
    if findings:
        print("| Status | Detector | Location | Preview | Replace with | Already attached |")
        print("| --- | --- | --- | --- | --- | --- |")
        for f in findings:
            fix = f"[{f['replace_with']}]({f['docs']})"
            if f["connect_link"]:
                fix += f" ([add]({f['connect_link']}))"
            print(f"| {f['status']} | {f['detector']} | `{where(f['location'])}` "
                  f"| `{f['preview']}` | {fix} | {', '.join(f['already_attached']) or '-'} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
