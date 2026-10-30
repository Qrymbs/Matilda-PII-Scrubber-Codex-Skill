"""Public intake restrictions, actionable rejection, and safe mixed batches."""
import csv
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from input_formats import ARCHIVE_SUFFIXES, SUPPORTED_SUFFIXES, admission_error
from review_support import COVERAGE_FIELDS
from scrub import dependency_status, refresh_report_summaries
from scrub_core import ScrubError

SCRIPTS = Path(__file__).parent


class FormatAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='format-intake-')
        self.root = Path(self.temp.name)
        self.serial = 0

    def tearDown(self):
        self.temp.cleanup()

    def run_inputs(self, inputs):
        self.serial += 1
        out = self.root/f'run-{self.serial}'
        before = {path: path.read_bytes() for path in inputs}
        proc = subprocess.run([sys.executable, str(SCRIPTS/'scrub.py'), *map(str, inputs),
                               '--output-dir', str(out)], capture_output=True, text=True)
        self.assertIn(proc.returncode, (0, 2), proc.stdout + proc.stderr)
        report = json.loads((out/'scrub-report.json').read_text())
        self.assertEqual(before, {path: path.read_bytes() for path in inputs})
        return out, proc, report

    def finalize(self, out, sources):
        report = json.loads((out/'scrub-report.json').read_text())
        evidence = {'version': 2, 'run_id': report['run_id'], 'files': {
            row['file_id']: {**{key: True for key in COVERAGE_FIELDS},
                             'unresolved_items': 0, 'decisions': {}}
            for row in report['files']}}
        proof = out/'evidence.json'
        proof.write_text(json.dumps(evidence))
        args = [sys.executable, str(SCRIPTS/'finalize_report.py'), str(out/'scrub-report.json'),
                '--review-evidence', str(proof)]
        for row, source in zip(report['files'], sources):
            args.extend(['--source', row['file_id'] + '=' + str(source)])
        proc = subprocess.run(args, capture_output=True, text=True)
        return proc, json.loads((out/'scrub-report.json').read_text())

    def fixture(self, suffix):
        path = self.root/('billing' + suffix)
        kind = suffix.lower()
        if kind == '.csv':
            path.write_text('resource_id,cost\nvm-001,12.3400\n')
        elif kind == '.xlsx':
            from openpyxl import Workbook
            book = Workbook()
            book.properties.creator = ''
            book.properties.lastModifiedBy = ''
            book.active.append(['resource_id', 'cost'])
            book.active.append(['vm-001', 12])
            book.save(path)
            book.close()
        elif kind == '.parquet':
            import pyarrow as pa
            import pyarrow.parquet as pq
            pq.write_table(pa.table({'resource_id': ['vm-001'], 'cost': [12]}), path)
        elif kind == '.xls':
            import xlwt
            book = xlwt.Workbook()
            sheet = book.add_sheet('Billing')
            for r, values in enumerate([['resource_id', 'cost'], ['vm-001', 12]]):
                for c, value in enumerate(values):
                    sheet.write(r, c, value)
            book.save(str(path))
        return path

    def test_exact_four_type_contract_and_dependency_selection(self):
        self.assertEqual(SUPPORTED_SUFFIXES, {'.csv', '.xlsx', '.xls', '.parquet'})
        for suffix in SUPPORTED_SUFFIXES:
            self.assertTrue(dependency_status([suffix[1:]])['ready'])
        for denied in ('tsv', 'json', 'jsonl', 'ndjson', 'txt', 'log', 'pdf', 'docx', 'zip', 'gz'):
            with self.subTest(denied=denied), self.assertRaises(ScrubError):
                dependency_status([denied])

    def test_allowed_case_insensitive_formats_process_and_normalize_report_format(self):
        for suffix in ('.CSV', '.XLSX', '.PARQUET'):
            with self.subTest(suffix=suffix):
                source = self.fixture(suffix)
                out, proc, report = self.run_inputs([source])
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                record = report['files'][0]
                self.assertEqual(record['input_format'], suffix[1:].lower())
                self.assertEqual(record['output_format'], suffix[1:].lower())
                self.assertTrue((out/record['artifact']).is_file())
                final_proc, final = self.finalize(out, [source])
                self.assertEqual(final_proc.returncode, 0, final_proc.stdout + final_proc.stderr)
                self.assertEqual(final['files'][0]['submission_status'], 'ready_for_manual_submission')

    def test_xls_accepted_as_blocked_conversion_with_reexport_instruction(self):
        source = self.fixture('.XLS')
        out, proc, report = self.run_inputs([source])
        self.assertEqual(proc.returncode, 2)
        record = report['files'][0]
        self.assertEqual(record['input_format'], 'xls')
        self.assertEqual(record['output_format'], 'xlsx')
        self.assertTrue((out/record['artifact']).is_file())
        self.assertIn('genuine .xlsx', record['next_action'])
        self.assertIn('genuine .xlsx', record['chat_summary']['next_action'])
        self.assertIn('genuine .xlsx', (out/'scrub-report.md').read_text())
        self.assertIn('genuine .xlsx', proc.stdout)
        final_proc, final = self.finalize(out, [source])
        self.assertEqual(final_proc.returncode, 2)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')

    def test_all_archive_suffixes_rejected_without_copy_or_extraction(self):
        sources = []
        for index, suffix in enumerate(sorted(ARCHIVE_SUFFIXES)):
            path = self.root/(f'archive-{index}' + suffix)
            path.write_bytes(b'not-opened-by-intake')
            sources.append(path)
        out, proc, report = self.run_inputs(sources)
        self.assertEqual(proc.returncode, 2)
        for record in report['files']:
            self.assertIsNone(record['artifact'])
            self.assertEqual(record['submission_status'], 'blocked')
            self.assertIn('compressed_input_extract_first', record['warnings'])
            self.assertIn('Extract or decompress', record['next_action'])
            self.assertEqual(record['next_action'], record['chat_summary']['next_action'])
        self.assertIn('Extract or decompress', (out/'scrub-report.md').read_text())
        self.assertIn('Extract or decompress', proc.stdout)
        self.assertFalse(list(out.rglob('*_SCRUBBED*')))

    def test_previously_supported_and_other_formats_are_denied(self):
        suffixes = ('.tsv', '.json', '.jsonl', '.ndjson', '.txt', '.log', '.pdf', '.docx',
                    '.xml', '.yaml', '.xlsm', '.xlsb', '.png', '.exe', '')
        sources = []
        for index, suffix in enumerate(suffixes):
            path = self.root/(f'unsupported-{index}' + suffix)
            path.write_text('resource_id,cost\nvm-001,12.3400\n')
            sources.append(path)
        out, proc, report = self.run_inputs(sources)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(len(report['files']), len(sources))
        for record in report['files']:
            self.assertIsNone(record['artifact'])
            self.assertIn('unsupported_format', record['warnings'])
            self.assertIn('accepts only .csv, .xlsx, .xls, and .parquet', record['next_action'])
        self.assertFalse(list(out.rglob('*_SCRUBBED*')))

    def test_real_gzip_zip_and_disguised_archives_are_not_processed(self):
        gzip_path = self.root/'billing.csv.gz'
        gzip_path.write_bytes(gzip.compress(b'resource_id,cost\nvm-001,12\n'))
        zip_path = self.root/'billing.zip'
        with zipfile.ZipFile(zip_path, 'w') as archive:
            archive.writestr('billing.csv', 'resource_id,cost\nvm-001,12\n')
        disguised_gzip = self.root/'compressed.csv'
        disguised_gzip.write_bytes(gzip_path.read_bytes())
        disguised_zip = self.root/'archive.parquet'
        disguised_zip.write_bytes(zip_path.read_bytes())
        out, _, report = self.run_inputs([gzip_path, zip_path, disguised_gzip, disguised_zip])
        self.assertTrue(all('compressed_input_extract_first' in r['warnings'] for r in report['files']))
        self.assertFalse(list(out.rglob('*_SCRUBBED*')))
        self.assertFalse((out/'billing.csv').exists())

    def test_mixed_batch_preserves_allowed_readiness_and_denied_no_artifacts(self):
        allowed = self.fixture('.csv')
        archive = self.root/'billing.csv.gz'
        archive.write_bytes(gzip.compress(b'private synthetic content'))
        denied = self.root/'report.json'
        denied.write_text('{"cost": 12}')
        out, proc, report = self.run_inputs([allowed, archive, denied])
        self.assertEqual(proc.returncode, 2)
        self.assertIsNotNone(report['files'][0]['artifact'])
        self.assertTrue(all(r['artifact'] is None for r in report['files'][1:]))
        final_proc, final = self.finalize(out, [allowed, archive, denied])
        self.assertEqual(final_proc.returncode, 2)
        self.assertEqual(final['files'][0]['submission_status'], 'ready_for_manual_submission')
        self.assertTrue(all(r['submission_status'] == 'blocked' for r in final['files'][1:]))

    def test_rejected_filename_and_contents_do_not_leak_to_reports(self):
        path = self.root/'synthetic-person-secret.json'
        marker = 'private-marker-not-for-report'
        path.write_text(marker)
        out, proc, _ = self.run_inputs([path])
        for value in (proc.stdout, (out/'scrub-report.json').read_text(), (out/'scrub-report.md').read_text()):
            self.assertNotIn(path.name, value)
            self.assertNotIn(str(path), value)
            self.assertNotIn(marker, value)

    def test_historical_report_formats_receive_fixed_current_guidance(self):
        report = {'files': [
            {'file_id': f'file{index:04d}', 'input_format': kind, 'warnings': [],
             'submission_status': 'blocked'}
            for index, kind in enumerate(('gz', 'zip', 'json', 'docx'), 1)]}
        refresh_report_summaries(report)
        for record in report['files']:
            expected = ('Extract or decompress' if record['input_format'] in {'gz', 'zip'}
                        else 'File type denied')
            self.assertIn(expected, record['next_action'])
            self.assertEqual(record['chat_summary']['next_action'], record['next_action'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
