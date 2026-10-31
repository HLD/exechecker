"""Tests for scripts/report.py, run as the scan runs it (python3 -I, stdin)."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPORT = Path(__file__).resolve().parent.parent / "scripts" / "report.py"

SECRETS = {
    "Github": "ghp_TESTONLY0000000000000000000000000000",
    "Stripe": "sk_live_TESTONLY00000000000000",
    "Postgres": "postgres://app:hunter2@db.internal/app",
    "Redis": "redis://:pw12345@cache.internal",
    "SomethingUnknown": "xyzxyzxyzxyz",
}

ATTACHED = {"integrations": [
    {"name": "my-repo", "type": "github", "help": "git clone https://github.int.exe.xyz/me/repo.git"},
    {"name": "gw", "type": "llm", "help": "Keyless LLM gateway for this VM."},
    {"name": "stripe-live", "type": "catalog", "help": "Stripe API via https://stripe-live.int.exe.xyz/"},
]}


def finding(detector, raw, path):
    return json.dumps({
        "DetectorName": detector,
        "Raw": raw,
        "SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": 1}}},
    })


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.key = self.dir / "fingerprint.key"

    def tearDown(self):
        self.tmp.cleanup()

    def run_report(self, lines, *extra):
        out = self.dir / "report.json"
        proc = subprocess.run(
            [sys.executable, "-I", str(REPORT), "--key-file", str(self.key), "--out", str(out), *extra],
            input="\n".join(lines) + "\n", capture_output=True, text=True, check=True,
        )
        return proc.stdout, json.loads(out.read_text())

    def all_findings(self):
        lines = [finding(d, raw, f"/x/{d}.env") for d, raw in SECRETS.items()]
        lines.append(finding("Github", SECRETS["Github"], "/x/other.env"))
        lines.append("not json")
        return lines

    def test_no_raw_values_anywhere(self):
        stdout, report = self.run_report(self.all_findings())
        dumped = json.dumps(report)
        for raw in SECRETS.values():
            self.assertNotIn(raw, stdout)
            self.assertNotIn(raw, dumped)
        self.assertEqual(report["findings"][0]["preview"][0], "<")

    def test_key_file_private_and_fingerprints_stable(self):
        _, first = self.run_report(self.all_findings())
        _, second = self.run_report(self.all_findings())
        self.assertEqual(stat.S_IMODE(os.stat(self.key).st_mode), 0o600)
        fps = lambda r: [f["fingerprint"] for f in r["findings"]]
        self.assertEqual(fps(first), fps(second))

    def test_same_secret_two_files_is_one_secret(self):
        stdout, report = self.run_report(self.all_findings())
        self.assertEqual(len(report["findings"]), 6)
        self.assertIn("6 finding(s), 5 distinct secret(s)", stdout)

    def test_remediation_mapping(self):
        _, report = self.run_report(self.all_findings(), "--vm", "test-vm")
        by = {f["detector"]: f for f in report["findings"]}
        self.assertIn("GitHub integration", by["Github"]["replace_with"])
        self.assertIn("Stripe (stripe)", by["Stripe"]["replace_with"])
        self.assertEqual(by["Stripe"]["connect_link"],
                         "https://exe.dev/integrations/add?service=stripe&attach=vm:test-vm")
        self.assertIn("service=db:postgres", by["Postgres"]["connect_link"])
        self.assertTrue(by["Redis"]["replace_with"].startswith("No integration"))
        self.assertIsNone(by["Redis"]["connect_link"])
        self.assertIn("HTTP proxy", by["SomethingUnknown"]["replace_with"])

    def test_already_attached(self):
        att = self.dir / "attached.json"
        att.write_text(json.dumps(ATTACHED))
        lines = self.all_findings() + [finding("Anthropic", "sk-ant-TESTONLY000000", "/x/a.env")]
        _, report = self.run_report(lines, "--attached", str(att))
        by = {f["detector"]: f["already_attached"] for f in report["findings"]}
        self.assertEqual(by["Github"], ["my-repo"])
        self.assertEqual(by["Stripe"], ["stripe-live"])
        self.assertEqual(by["Anthropic"], ["gw"])
        self.assertEqual(by["Redis"], [])

    def test_missing_attached_file_is_ignored(self):
        _, report = self.run_report(self.all_findings(), "--attached", str(self.dir / "nope.json"))
        self.assertTrue(all(f["already_attached"] == [] for f in report["findings"]))


if __name__ == "__main__":
    unittest.main()
