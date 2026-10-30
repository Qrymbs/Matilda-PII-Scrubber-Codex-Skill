"""The verifier cannot revive a disallowed format from a historical report."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from verify_outputs import verify_directory


class VerifierFormatScope(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='verifier-format-scope-')
        self.root = Path(self.temp.name)
        self.source = self.root / 'billing.csv'
        self.source.write_text('resource_id,cost\nvm-001,1.25\n')
        self.out = self.root / 'run'
        run = subprocess.run([sys.executable, str(Path(__file__).parent/'scrub.py'),
                              str(self.source), '--output-dir', str(self.out)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.report = json.loads((self.out/'scrub-report.json').read_text())

    def tearDown(self):
        self.temp.cleanup()

    def check(self, source=None):
        (self.out/'scrub-report.json').write_text(json.dumps(self.report))
        return verify_directory(self.out, sources={'file0001': source or self.source})['files']['file0001']

    def test_historical_disallowed_input_record_cannot_pass(self):
        for kind in ('tsv', 'json', 'jsonl', 'ndjson', 'txt', 'log', 'docx', 'pdf', 'zip', 'gz'):
            with self.subTest(kind=kind):
                self.report['files'][0]['input_format'] = kind
                result = self.check()
                self.assertFalse(result['source_comparison_passed'])
                self.assertIn('unsupported_input_format', result['errors'])

    def test_disallowed_source_suffix_cannot_be_waived_by_report(self):
        renamed = self.root/'billing.txt'
        renamed.write_bytes(self.source.read_bytes())
        result = self.check(renamed)
        self.assertFalse(result['source_comparison_passed'])
        self.assertIn('unsupported_format', result['errors'])

    def test_disallowed_artifact_extension_cannot_be_waived_by_report(self):
        record = self.report['files'][0]
        original = self.out/record['artifact']
        renamed = original.with_suffix('.txt')
        original.rename(renamed)
        record['artifact'] = str(renamed.relative_to(self.out))
        result = self.check()
        self.assertFalse(result['source_comparison_passed'])
        self.assertIn('unsupported_output_format', result['errors'])

    def test_declared_allowed_format_must_match_source_and_artifact(self):
        self.report['files'][0]['input_format'] = 'xlsx'
        result = self.check()
        self.assertIn('input_format_does_not_match_source', result['errors'])
        self.report['files'][0]['input_format'] = 'csv'
        self.report['files'][0]['output_format'] = 'parquet'
        result = self.check()
        self.assertIn('output_format_does_not_match_artifact', result['errors'])


if __name__ == '__main__':
    unittest.main()
