"""Regenerate catalog.json: TruffleHog detector name -> exe.dev catalog service.

Matches the service names in the exe.dev integration catalog against the
detector names of the TruffleHog version pinned in install.sh. Rerun when the
catalog grows or after bumping TruffleHog, then review the diff: name matching
is a heuristic, and EXCLUDE / EXTRA below hold the manual corrections.

Usage: python3 -I scripts/update-catalog.py
"""

import json
import re
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATALOG_URL = "https://exe.dev/docs/integrations-catalog.md"
DETECTORS_URL = "https://raw.githubusercontent.com/trufflesecurity/trufflehog/v{}/proto/detector_type.proto"

# Name matches that point at the wrong credential: self-hosted editions,
# database passwords, storage keys, or keys that are public by design.
EXCLUDE = {
    "BitbucketDataCenter", "ConfluenceDataCenter", "JiraDataCenterPAT",
    "CloudflareCaKey", "DigitalOceanSpaces", "PlanetScaleDb",
    "NewRelicBrowserKey", "NewRelicMobileAppToken", "Squarespace",
}
# Detectors whose names don't match their service.
EXTRA = {"NpmToken": "npm"}


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read().decode()


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def main() -> None:
    version = re.search(r'^VERSION="([^"]+)"', (HERE / "install.sh").read_text(), re.M).group(1)
    detectors = re.findall(r"^\s+(\w+) = \d+;", fetch(DETECTORS_URL.format(version)), re.M)

    services = {}
    for m in re.finditer(r"^\| \[(.+?)\]\(.*?\) \| `([^`]+)` \|", fetch(CATALOG_URL), re.M):
        name, handle = m.groups()
        if not handle.startswith("db:"):
            services.setdefault(handle, name)

    mapping = {}
    for handle, name in services.items():
        keys = {norm(handle), norm(name.split("(")[0])}
        for d in detectors:
            nd = norm(d)
            if d in EXCLUDE or d.lower() in mapping:
                continue
            if any(nd == k or (len(k) >= 4 and nd.startswith(k)) for k in keys):
                mapping[d.lower()] = {"handle": handle, "name": name}
    for d, handle in EXTRA.items():
        mapping[d.lower()] = {"handle": handle, "name": services[handle]}

    out = HERE / "catalog.json"
    out.write_text(json.dumps(dict(sorted(mapping.items())), indent=1) + "\n")
    print(f"wrote {out}: {len(mapping)} detectors -> {len({v['handle'] for v in mapping.values()})} services")


if __name__ == "__main__":
    main()
