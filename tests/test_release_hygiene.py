"""Guard the software distribution against accidental local data inclusion.

These pattern checks supplement the release content review; they cannot prove
that an arbitrary name or number is synthetic. Customer inputs and reports do
not belong in this repository, including as test fixtures.
"""
from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class ReleaseHygieneTests(unittest.TestCase):
    def release_files(self):
        for path in REPO_ROOT.rglob("*"):
            # A developer checkout has Git bookkeeping; it is not distributed
            # in the immutable GitHub source archive.
            if ".git" not in path.relative_to(REPO_ROOT).parts and path.is_file():
                yield path

    def test_distribution_has_no_customer_input_or_runtime_artifacts(self):
        prohibited_suffixes = {
            ".csv", ".xlsx", ".xls", ".parquet", ".zip", ".gz", ".pyc",
            ".pyo", ".sqlite", ".db", ".pem", ".key",
        }
        prohibited_parts = {"__pycache__", ".venv", "venv", "node_modules", ".git"}
        failures = []
        for path in self.release_files():
            relative = path.relative_to(REPO_ROOT)
            if path.is_symlink() or path.suffix.lower() in prohibited_suffixes or prohibited_parts.intersection(relative.parts):
                failures.append(str(relative))
        self.assertEqual(failures, [], "Software release contains non-source artifacts; run tests with -B or PYTHONDONTWRITEBYTECODE=1 and remove generated caches before release")

    def test_distribution_does_not_embed_credentials_or_customer_folder_paths(self):
        patterns = {
            "GitHub access token": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})"),
            "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
            "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "personal customer folder": re.compile(r"/Users/[^/\s\"'<>]+/(?:Documents|Downloads|Desktop|Library)/[^\s\"'<>]+"),
        }
        failures = []
        for path in self.release_files():
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                # Artifact hygiene separately rejects binary customer inputs,
                # runtime files and compiled Python. Do not dump binary data.
                continue
            for label, pattern in patterns.items():
                if pattern.search(text):
                    # Never echo a matched credential or customer path in CI logs.
                    failures.append((str(path.relative_to(REPO_ROOT)), label))
        self.assertEqual(failures, [], "Review potentially sensitive release content")


if __name__ == "__main__":
    unittest.main(verbosity=2)
