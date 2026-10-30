"""Exercise the public four-format preflight contract using synthetic inputs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import preflight


class PreflightScope(unittest.TestCase):
    def test_only_requested_four_formats_are_available(self):
        self.assertEqual(set(preflight.FORMATS), {'csv', 'xlsx', 'xls', 'parquet'})
        for kind in ('tsv', 'json', 'jsonl', 'ndjson', 'docx', 'txt', 'log', 'pdf', 'zip', 'gz'):
            with self.subTest(kind=kind):
                proc = subprocess.run([sys.executable, str(Path(preflight.__file__)),
                                       '--formats', kind], capture_output=True, text=True)
                self.assertEqual(proc.returncode, 2)
                self.assertIn('invalid choice', proc.stderr)

    def test_embedded_xls_fixture_is_readable_and_contains_only_expected_cells(self):
        import xlrd
        with tempfile.TemporaryDirectory(prefix='preflight-xls-fixture-') as directory:
            path = Path(directory) / 'synthetic.xls'
            preflight.fixture(path, 'xls')
            with xlrd.open_workbook(path) as book:
                self.assertEqual(book.sheet_names(), ['Data'])
                sheet = book.sheet_by_index(0)
                self.assertEqual((sheet.nrows, sheet.ncols), (2, 2))
                self.assertEqual(sheet.row_values(0), ['resource_id', 'fullname'])
                self.assertEqual(sheet.row_values(1), ['vm-preflight-001', 'Avery Stone'])

    def test_all_four_preflights_verify_their_expected_release_behavior(self):
        proc = subprocess.run([sys.executable, str(Path(preflight.__file__)), '--formats',
                               'csv', 'xlsx', 'xls', 'parquet'], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(proc.stdout)
        self.assertTrue(result['synthetic_only'])
        self.assertTrue(result['passed'])
        self.assertEqual({row['format'] for row in result['results']}, set(preflight.FORMATS))
        for row in result['results']:
            self.assertTrue(row['passed'], row)
            self.assertTrue(row['processing_and_finalization_tested'], row)
            if row['format'] == 'xls':
                self.assertEqual(row['expected_submission_status'], 'blocked')
                self.assertTrue(row['legacy_conversion_only'])
                self.assertIn('does not qualify XLS for upload', row['note'])
            else:
                self.assertEqual(row['expected_submission_status'], 'ready_for_manual_submission')


if __name__ == '__main__':
    unittest.main(verbosity=2)
