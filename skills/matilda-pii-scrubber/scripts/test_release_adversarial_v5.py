"""Synthetic adversarial source/evidence tests; no customer inputs or identities."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from review_support import COVERAGE_FIELDS
from scrub import Runner, write_report
from scrub_core import ScrubError
from source_provenance import (PRIVATE_NAME, fingerprint_source, load_provenance,
                               write_provenance)
import scrub_structured
import verify_outputs

SCRIPTS = Path(__file__).parent


class AdversarialReleaseV5(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pii-v5-adversarial-')
        self.root = Path(self.temp.name)
        self.source = self.root / 'synthetic.csv'
        self.source.write_text('full_name,cost\nAvery Stone,1.25\n')

    def tearDown(self):self.temp.cleanup()

    def run_scrub(self, out=None, plan=None):
        out = out or self.root / 'run'
        arguments = [sys.executable, str(SCRIPTS/'scrub.py'), str(self.source), '--output-dir', str(out)]
        if plan:arguments += ['--review-plan', str(plan)]
        result = subprocess.run(arguments, capture_output=True, text=True)
        self.assertIn(result.returncode, (0, 2), result.stdout)
        return out, json.loads((out/'scrub-report.json').read_text())

    @staticmethod
    def decision():
        # Independently specified exact semantic review of the invented name.
        return {'r2.c1': {'action':'mask', 'reason_code':'explicit_person_name',
                         'spans':[{'start':0, 'end':11, 'category':'human_names'}]}}

    def write_evidence(self, out, report):
        evidence = {'version':2, 'run_id':report['run_id'], 'files':{
            'file0001': {**{field: True for field in COVERAGE_FIELDS},
                         'unresolved_items':0, 'decisions':self.decision()}}}
        path = out/'evidence.json';path.write_text(json.dumps(evidence));return path

    def finalize(self, out, evidence):
        result = subprocess.run([sys.executable, str(SCRIPTS/'finalize_report.py'),
            str(out/'scrub-report.json'), '--review-evidence', str(evidence),
            '--source', f'file0001={self.source}'], capture_output=True, text=True)
        return result, json.loads((out/'scrub-report.json').read_text())

    def test_same_length_masked_source_change_cannot_reuse_review(self):
        out, report = self.run_scrub();evidence = self.write_evidence(out, report)
        self.source.write_text('full_name,cost\nCloud Agent,1.25\n')
        result, final = self.finalize(out, evidence)
        self.assertEqual(result.returncode, 2, result.stdout)
        record = final['files'][0]
        self.assertEqual(record['submission_status'], 'blocked')
        self.assertFalse(record['verification']['source_provenance_passed'])
        self.assertIn('source_changed_since_scrub', record['verification']['errors'])
        self.assertFalse((out/'ready').exists())

    def test_same_length_change_revokes_already_ready_copy(self):
        out, report = self.run_scrub();evidence = self.write_evidence(out, report)
        first, final = self.finalize(out, evidence)
        self.assertEqual(first.returncode, 0, first.stdout)
        self.assertTrue(final['files'][0]['artifact'].startswith('ready/'))
        self.source.write_text('full_name,cost\nCloud Agent,1.25\n')
        second, final = self.finalize(out, evidence)
        self.assertEqual(second.returncode, 2, second.stdout)
        self.assertTrue(final['files'][0]['artifact'].startswith('blocked/'))
        self.assertFalse(list((out/'ready').glob('*.csv')))

    def test_missing_corrupt_or_wrong_run_provenance_blocks(self):
        for defect in ['missing', 'corrupt', 'wrong_run', 'permissions', 'symlink']:
            with self.subTest(defect=defect):
                out, report = self.run_scrub(self.root/defect)
                path = out/PRIVATE_NAME
                if defect == 'missing':path.unlink()
                elif defect == 'corrupt':path.write_text('{')
                elif defect == 'wrong_run':
                    data = json.loads(path.read_text());data['run_id'] = 'another-run';path.write_text(json.dumps(data))
                elif defect == 'permissions':path.chmod(0o644)
                else:
                    moved = out/'other.json';path.rename(moved);path.symlink_to(moved)
                result = verify_outputs.verify_directory(out, {'file0001':self.source},
                                                         review_decisions={'file0001':self.decision()})
                self.assertFalse(result['all_artifacts_passed'])
                self.assertFalse(result['files']['file0001']['source_comparison_passed'])
                self.assertTrue(any('provenance' in code for code in result['files']['file0001']['errors']))

    def test_source_change_during_scrub_blocks_and_removes_partial_output(self):
        out = self.root/'run';out.mkdir();(out/'artifacts').mkdir();(out/'incomplete').mkdir()
        original = scrub_structured.scrub_csv
        def changing_adapter(source, destination, context, **kwargs):
            result = original(source, destination, context, **kwargs)
            source.write_text('full_name,cost\nCloud Agent,1.25\n')
            return result
        runner = Runner(out, 1000000, 1000000, 10, 4)
        with patch.object(scrub_structured, 'scrub_csv', side_effect=changing_adapter):
            record = runner.run_file(self.source)
        self.assertEqual(record['processing_status'], 'blocked')
        self.assertIn('source_changed_during_scrub', record['warnings'])
        self.assertIsNone(record['artifact'])
        self.assertFalse(list((out/'artifacts').glob('*.csv')))

    def test_source_change_during_verification_is_detected_after_parse(self):
        out, _ = self.run_scrub()
        original = verify_outputs.ArtifactComparison.csv
        def changing_parser(comparison, source, output):
            original(comparison, source, output)
            source.write_text('full_name,cost\nCloud Agent,1.25\n')
        with patch.object(verify_outputs.ArtifactComparison, 'csv', changing_parser):
            result = verify_outputs.verify_directory(out, {'file0001':self.source},
                                                     review_decisions={'file0001':self.decision()})
        self.assertFalse(result['all_artifacts_passed'])
        self.assertIn('source_changed_since_scrub', result['files']['file0001']['errors'])
        self.assertFalse(result['files']['file0001']['source_provenance_passed'])

    def test_review_plan_does_not_transfer_to_changed_original(self):
        out, report = self.run_scrub()
        plan = out/'review-plan.json'
        plan.write_text(json.dumps({'version':2, 'source_run_id':report['run_id'],
                                    'files':{'file0001':{'decisions':self.decision()}}}))
        self.source.write_text('full_name,cost\nCloud Agent,1.25\n')
        _, rerun = self.run_scrub(self.root/'rerun', plan)
        self.assertEqual(rerun['files'][0]['processing_status'], 'blocked')
        self.assertIn('source_changed_since_scrub', rerun['files'][0]['warnings'])
        self.assertIsNone(rerun['files'][0]['artifact'])

    def test_private_manifest_is_create_only_and_absent_from_portable_reports(self):
        out, report = self.run_scrub();path = out/PRIVATE_NAME
        private = json.loads(path.read_text());binding = private['files']['file0001']
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(binding), {'sha256', 'size', 'basename_sha256'})
        self.assertNotIn(str(self.source), path.read_text())
        self.assertNotIn(self.source.name, path.read_text())
        portable = (out/'scrub-report.json').read_text() + (out/'scrub-report.md').read_text()
        self.assertNotIn(binding['sha256'], portable)
        self.assertNotIn(binding['basename_sha256'], portable)
        previous = path.read_bytes()
        write_provenance(out, report['run_id'], private['files'])
        self.assertEqual(path.read_bytes(), previous)
        altered = {'file0001':{**binding, 'sha256':'0'*64}}
        with self.assertRaisesRegex(ScrubError, 'source_provenance_overwrite_forbidden'):
            write_provenance(out, report['run_id'], altered)
        self.assertEqual(path.read_bytes(), previous)

    def test_duplicate_and_overlapping_mask_ledger_entries_fail_closed(self):
        for defect in ['duplicate_event', 'duplicate_span', 'overlap_span']:
            with self.subTest(defect=defect):
                out, report = self.run_scrub(self.root/defect)
                ledger = out/report['files'][0]['removal_location_index']
                original = ledger.read_text()
                event = json.loads(original)
                if defect == 'duplicate_event':ledger.write_text(original+original)
                else:
                    event['spans'].append({'start':0 if defect == 'duplicate_span' else 5, 'end':11})
                    ledger.write_text(json.dumps(event)+'\n')
                result = verify_outputs.verify_directory(out, {'file0001':self.source},
                                                         review_decisions={'file0001':self.decision()})
                self.assertFalse(result['all_artifacts_passed'])
                self.assertFalse(result['files']['file0001']['source_comparison_passed'])

    def test_mixed_batch_missing_bindings_do_not_block_unchanged_good_file(self):
        good = self.root/'good.csv';good.write_text('cost\n1.25\n')
        unsupported = self.root/'unsupported.bin';unsupported.write_bytes(b'synthetic unsupported fixture')
        missing = self.root/'missing.csv';out = self.root/'mixed'
        result = subprocess.run([sys.executable, str(SCRIPTS/'scrub.py'), str(good), str(unsupported), str(missing),
                                 '--output-dir', str(out)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        report = json.loads((out/'scrub-report.json').read_text())
        self.assertEqual(set(load_provenance(out, report['run_id'])), {'file0001'})
        evidence = {'version':2, 'run_id':report['run_id'], 'files':{}}
        for record in report['files']:
            complete = record['file_id']=='file0001'
            evidence['files'][record['file_id']] = {**{field:complete for field in COVERAGE_FIELDS},
                                                   'unresolved_items':0 if complete else 1, 'decisions':{}}
        path=out/'evidence.json';path.write_text(json.dumps(evidence))
        result=subprocess.run([sys.executable,str(SCRIPTS/'finalize_report.py'),str(out/'scrub-report.json'),
                               '--review-evidence',str(path),'--source',f'file0001={good}'], capture_output=True,text=True)
        self.assertEqual(result.returncode,2,result.stdout)
        final=json.loads((out/'scrub-report.json').read_text())
        self.assertEqual([record['submission_status'] for record in final['files']],
                         ['ready_for_manual_submission','blocked','blocked'])

    def test_prior_plan_cannot_transfer_to_renamed_source(self):
        out, report = self.run_scrub()
        plan = out/'review-plan.json'
        plan.write_text(json.dumps({'version':2,'source_run_id':report['run_id'],
                                    'files':{'file0001':{'decisions':self.decision()}}}))
        renamed = self.root/'renamed.csv';self.source.rename(renamed);self.source=renamed
        _, rerun = self.run_scrub(self.root/'rerun', plan)
        self.assertEqual(rerun['files'][0]['processing_status'],'blocked')
        self.assertIn('source_changed_since_scrub',rerun['files'][0]['warnings'])


if __name__ == '__main__':unittest.main()
