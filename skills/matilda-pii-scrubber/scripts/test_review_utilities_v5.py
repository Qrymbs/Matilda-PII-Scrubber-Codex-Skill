"""Synthetic CLI checks for review grouping and runtime preflight."""
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).parent
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')

class ReviewUtilitiesV5(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pii-utilities-v5-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, script, *args):
        return subprocess.run([sys.executable, str(SCRIPTS/script), *map(str,args)],
                              capture_output=True, text=True, env=ENV, timeout=120)

    def grouped_run(self):
        source = self.root/'synthetic.csv'
        with source.open('w', newline='') as stream:
            csv.writer(stream).writerows([['Owner','cost'], *[['opaquealiasz','1.2500'] for _ in range(125)]])
        out = self.root/'run'
        processed = self.cli('scrub.py', source, '--output-dir', out)
        self.assertEqual(processed.returncode,0,processed.stdout)
        report = json.loads((out/'scrub-report.json').read_text())
        flags = ('complete_source_review','complete_retained_review','all_changed_values_reviewed',
                 'metadata_and_hidden_content_reviewed','independent_candidate_review')
        evidence = {'version':2, 'run_id':report['run_id'], 'files':{'file0001':{
            **{key:False for key in flags}, 'unresolved_items':125,'decisions':{}}}}
        proof = out/'evidence.json';proof.write_text(json.dumps(evidence))
        final = self.cli('finalize_report.py', out/'scrub-report.json', '--review-evidence', proof,
                         '--source', 'file0001='+str(source))
        self.assertEqual(final.returncode,2,final.stdout)
        return source,out

    def test_grouping_retains_every_coordinate_without_source_data_or_readiness_changes(self):
        source,out = self.grouped_run()
        before = {name:(out/name).read_bytes() for name in ['scrub-report.json','scrub-report.md','verification.json','evidence.json']}
        grouping = out/'grouped.json'
        result = self.cli('group_review.py',out/'scrub-report.json','--source','file0001='+str(source),'--output',grouping)
        self.assertEqual(result.returncode,0,result.stdout)
        payload=json.loads(grouping.read_text());file=payload['files'][0]
        self.assertFalse(payload['readiness_modified'])
        self.assertFalse(payload['source_values_included'])
        self.assertEqual(file['candidate_locations'],125)
        self.assertEqual(len(file['groups']),1)
        group=file['groups'][0]
        self.assertEqual(group['occurrences'],125)
        self.assertEqual(group['locations'],[f'r{row}.c1' for row in range(2,127)])
        self.assertEqual(group['representative_location'],'r2.c1')
        self.assertEqual(group['decision'],'pending_context_review')
        self.assertEqual(group['review_kinds'],['independent_candidate','initial_candidate'])
        serialized=grouping.read_text()+result.stdout+result.stderr
        for forbidden in ['opaquealiasz','1.2500',str(source)]:
            self.assertNotIn(forbidden,serialized)
        self.assertEqual({name:(out/name).read_bytes() for name in before},before)
        report=json.loads((out/'scrub-report.json').read_text())
        self.assertEqual(report['files'][0]['submission_status'],'blocked')
        self.assertTrue((out/report['files'][0]['artifact']).is_file())

    def test_grouping_refuses_overwrite_and_out_of_source_coordinates(self):
        source,out=self.grouped_run()
        target=out/'grouped.json';target.write_text('keep this existing file')
        args=[out/'scrub-report.json','--source','file0001='+str(source),'--output',target]
        result=self.cli('group_review.py',*args)
        self.assertEqual(result.returncode,2)
        self.assertEqual(target.read_text(),'keep this existing file')
        report=json.loads((out/'scrub-report.json').read_text())
        with (out/report['files'][0]['review_location_index']).open('a') as stream:
            stream.write(json.dumps({'location':'r999.c1','count':1,'reason':'ambiguous_person_identifier','resolved':False})+'\n')
        result=self.cli('group_review.py',out/'scrub-report.json','--source','file0001='+str(source),'--output',out/'bad-group.json')
        self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['error'],'review_coordinate_not_in_source')
        self.assertFalse((out/'bad-group.json').exists())

    def test_preflight_executes_processing_and_finalization_for_each_supported_format(self):
        formats=['csv','xlsx','xls','parquet']
        result=self.cli('preflight.py','--formats',*formats)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        payload=json.loads(result.stdout)
        self.assertTrue(payload['passed'])
        self.assertTrue(payload['synthetic_only'])
        self.assertEqual([row['format'] for row in payload['results']],formats)
        for row in payload['results']:
            self.assertTrue(row['passed'],row)
            self.assertTrue(row['processing_and_finalization_tested'],row)
            self.assertEqual(row['expected_submission_status'],
                             'blocked' if row['format']=='xls' else 'ready_for_manual_submission')
        for forbidden in ['Avery Stone','vm-preflight-001','matilda-preflight-']:
            self.assertNotIn(forbidden,result.stdout)

    def test_preflight_refuses_unsupported_format_and_deduplicates_selected_formats(self):
        result=self.cli('preflight.py','--formats','pdf')
        self.assertEqual(result.returncode,2)
        result=self.cli('preflight.py','--formats','csv','csv')
        self.assertEqual(result.returncode,0,result.stdout)
        self.assertEqual(len(json.loads(result.stdout)['results']),1)

if __name__=='__main__':
    unittest.main(verbosity=2)
