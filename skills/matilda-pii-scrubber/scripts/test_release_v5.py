"""Release gate and artifact segregation using synthetic inputs only."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from review_support import COVERAGE_FIELDS
from scrub import dependency_status
from scrub_core import ScrubError

SCRIPTS = Path(__file__).parent

class ReleaseV5(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pii-v5-release-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, name, rows):
        path = self.root / name
        with path.open('w', newline='') as stream:
            csv.writer(stream).writerows(rows)
        return path

    def scrub(self, sources):
        out = self.root / 'out'
        proc = subprocess.run([sys.executable, str(SCRIPTS/'scrub.py'), *map(str, sources), '--output-dir', str(out)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        return out, json.loads((out/'scrub-report.json').read_text())

    def evidence(self, out, report, choices=None, unresolved=None):
        data = {'version':2, 'run_id':report['run_id'], 'files':{}}
        for file in report['files']:
            fid = file['file_id']
            n = (unresolved or {}).get(fid, 0)
            data['files'][fid] = {**{k:True for k in COVERAGE_FIELDS}, 'complete_retained_review':n == 0,
                                 'unresolved_items':n, 'decisions':(choices or {}).get(fid, {})}
        path = out/'review-evidence.json'
        path.write_text(json.dumps(data))
        return path

    def finalize(self, out, sources, evidence):
        args = [sys.executable, str(SCRIPTS/'finalize_report.py'), str(out/'scrub-report.json'), '--review-evidence', str(evidence)]
        for i, source in enumerate(sources, 1):
            args += ['--source', f'file{i:04d}={source}']
        proc = subprocess.run(args, capture_output=True, text=True)
        return proc, json.loads((out/'scrub-report.json').read_text())

    def test_mixed_batch_separates_ready_from_unchanged_blocked_copy(self):
        clear = self.fixture('clear.csv', [['resourceId', 'cost'], ['i-synthetic', '12.3400']])
        blocked = self.fixture('blocked.csv', [['resourceId', 'Owner'], ['i-other', 'rlee']])
        originals = [p.read_bytes() for p in [clear, blocked]]
        out, report = self.scrub([clear, blocked])
        evidence = self.evidence(out, report, unresolved={'file0002':1})
        proc, final = self.finalize(out, [clear, blocked], evidence)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        ready, blocked_rec = final['files']
        self.assertEqual(ready['submission_status'], 'ready_for_manual_submission')
        self.assertEqual(ready['artifact'], 'ready/clear_SCRUBBED.csv')
        self.assertEqual(blocked_rec['submission_status'], 'blocked')
        self.assertEqual(blocked_rec['artifact'], 'blocked/blocked_SCRUBBED.csv')
        for f in final['files']:
            self.assertTrue((out/f['artifact']).is_file())
            self.assertEqual(f['chat_summary']['output_link'], f['artifact'])
            self.assertEqual(f['chat_summary']['submission_status'], f['submission_status'])
        self.assertEqual([p.read_bytes() for p in [clear, blocked]], originals)
        self.assertFalse(any((out/'artifacts').rglob('*.csv')))
        md = (out/'scrub-report.md').read_text()
        self.assertIn('[Open copy](ready/clear_SCRUBBED.csv)', md)
        self.assertIn('Matilda import acceptance: unverified', md)

    def test_no_readiness_for_automatic_mask_without_exact_review(self):
        source = self.fixture('person.csv', [['contactName', 'cost'], ['Avery Stone', '1.2500']])
        out, report = self.scrub([source])
        evidence = self.evidence(out, report)
        proc, final = self.finalize(out, [source], evidence)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')
        self.assertFalse(final['files'][0]['verification']['semantic_mask_review_passed'])
        self.assertTrue(json.loads((out/'verification.json').read_text())['context_review_still_required'])
        choices = {'file0001': {'r2.c1': {'action':'mask', 'reason_code':'explicit_person_name',
                                        'spans':[{'start':0, 'end':11, 'category':'human_names'}]}}}
        evidence = self.evidence(out, final, choices)
        proc, final = self.finalize(out, [source], evidence)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertTrue(final['files'][0]['verification']['semantic_mask_review_passed'])
        self.assertEqual(final['files'][0]['artifact'], 'ready/person_SCRUBBED.csv')
        verification = json.loads((out/'verification.json').read_text())
        self.assertFalse(verification['context_review_still_required'])
        self.assertTrue(verification['readiness_statuses_modified'])

    def test_altered_ready_copy_is_quarantined_on_refinalization(self):
        source = self.fixture('clear.csv', [['resourceId', 'cost'], ['i-synthetic', '12.3400']])
        out, report = self.scrub([source])
        evidence = self.evidence(out, report)
        proc, final = self.finalize(out, [source], evidence)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        artifact = out/final['files'][0]['artifact']
        artifact.write_text(artifact.read_text().replace('12.3400', '99.0000'))
        proc, final = self.finalize(out, [source], evidence)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')
        self.assertFalse(final['files'][0]['verification']['source_comparison_passed'])
        self.assertEqual(final['files'][0]['artifact'], 'blocked/clear_SCRUBBED.csv')
        self.assertFalse(any((out/'ready').rglob('*.csv')))

    def test_invalid_evidence_revokes_previous_ready_artifact(self):
        source = self.fixture('clear.csv', [['cost'], ['1.25']])
        out, report = self.scrub([source]); evidence = self.evidence(out, report)
        proc, final = self.finalize(out, [source], evidence)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        evidence.write_text('{}')
        proc, final = self.finalize(out, [source], evidence)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertEqual(final['files'][0]['artifact'], 'blocked/clear_SCRUBBED.csv')
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')
        self.assertFalse(any((out/'ready').rglob('*.csv')))

    def test_dependency_gate_is_format_scoped_and_rejects_unknown(self):
        with patch('scrub.importlib.util.find_spec', side_effect=lambda name: object() if name == 'lxml' else None):
            self.assertTrue(dependency_status(['csv'])['ready'])
            parquet = dependency_status(['parquet'])
            self.assertFalse(parquet['ready'])
            self.assertEqual(parquet['missing_required'], ['numpy', 'pyarrow'])
        with patch('scrub.importlib.util.find_spec', return_value=None):
            self.assertFalse(dependency_status(['csv'])['ready'])
        with self.assertRaises(ScrubError):
            dependency_status(['unknown'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
