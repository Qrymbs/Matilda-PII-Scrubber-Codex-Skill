"""Synthetic AWS legacy billing layout and preservation regressions."""
import builtins
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import group_review
from scrub_core import ScrubContext, ScrubError, is_protected_resource_field
import scrub_structured as structured
import verify_outputs as verify

SCRIPTS = Path(__file__).parent
HEADERS = ['InvoiceID', 'PayerAccountId', 'LinkedAccountId', 'RecordType', 'RecordID',
           'ProductCode', 'UsageType', 'UsageQuantity', 'BillingPeriodStartDate',
           'BillingPeriodEndDate', 'TotalCost', 'contact_email', 'user:PLATFORM_CLUSTER_NAME', 'notes']
EMAIL = 'avery.stone@example.invalid'
ROW = ['invoice-1', '123456789012', '210987654321', 'LineItem', 'record-1',
       'Compute', 'RunHours', '24.0000', '2026-09-01', '2026-10-01', '1.2300',
       EMAIL, 'Avery Stone', 'CPU=4; service stable']
BANNER = 'Synthetic billing information; amounts may change.'


class LegacyCsv(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aws-layout-test-')
        self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def source(self, rows=None, name='input.csv'):
        source = self.root / name
        with source.open('w', newline='') as stream:
            csv.writer(stream).writerows(rows if rows is not None else [[BANNER], HEADERS, ROW])
        return source
    def rows(self, path):
        with path.open(newline='') as stream:
            return list(csv.reader(stream))
    def run_scrub(self, source):
        out = self.root / 'run'
        proc = subprocess.run([sys.executable, str(SCRIPTS/'scrub.py'), str(source), '--output-dir', str(out)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        report = json.loads((out/'scrub-report.json').read_text())
        return out, report, out / report['files'][0]['artifact']
    def decisions(self):
        return {'r3.c12': {'action': 'mask', 'reason_code': 'named_person_email',
                          'spans': [{'start': 0, 'end': len(EMAIL), 'category': 'human_email_addresses'}]}}

    def test_preamble_header_and_physical_record_coordinates(self):
        source = self.source(); original = source.read_bytes()
        output = self.root/'clean.csv'; events = []
        metrics = structured.scrub_csv(source, output, ScrubContext(removal_location_sink=events.append))
        expected = [list(ROW)]; expected[0][11] = 'X' * len(EMAIL)
        self.assertEqual(self.rows(output), [[BANNER], HEADERS, *expected])
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual([e['location'] for e in events], ['r3.c12'])
        self.assertEqual(metrics['rows'], 1); self.assertEqual(metrics['header_row'], 2)
        self.assertEqual(metrics['preamble_rows'], 1); self.assertEqual(metrics['source_profile'], 'aws_cost_allocation')

    def test_multiline_metadata_remains_one_csv_record(self):
        banner = 'Synthetic billing metadata\ncontinued with stable text'
        source = self.source([[banner], HEADERS, ROW]); output = self.root/'clean.csv'; events=[]
        structured.scrub_csv(source, output, ScrubContext(removal_location_sink=events.append))
        self.assertEqual(self.rows(output)[0], [banner])
        self.assertEqual([e['location'] for e in events], ['r3.c12'])

    def test_standard_library_fallback_matches_arrow_coordinates(self):
        source=self.source(); output=self.root/'fallback.csv'; events=[]
        original_import=builtins.__import__
        def limited_import(name,*args,**kwargs):
            if name.split('.')[0] in {'numpy','pyarrow'}: raise ImportError('synthetic missing optional acceleration')
            return original_import(name,*args,**kwargs)
        with mock.patch('builtins.__import__',side_effect=limited_import):
            metrics=structured.scrub_csv(source,output,ScrubContext(removal_location_sink=events.append))
        self.assertEqual(self.rows(output)[0:2],[[BANNER],HEADERS]); self.assertEqual(metrics['header_row'],2)
        self.assertEqual([e['location'] for e in events],['r3.c12'])
        self.assertEqual(self.rows(output)[2][11],'X'*len(EMAIL))

    def test_unknown_prefix_and_ragged_rows_are_rejected(self):
        cases=[[[BANNER],['cost','contact'],['1',EMAIL]],
               [['two','prefix cells'],HEADERS,ROW],
               [[BANNER],['another prefix'],HEADERS,ROW],
               [[],HEADERS,ROW],
               [[BANNER],HEADERS,ROW[:-1]],
               [[BANNER],HEADERS,ROW,[]]]
        for i, rows in enumerate(cases):
            with self.subTest(case=i):
                source=self.source(rows,name=f'in-{i}.csv'); output=self.root/f'out-{i}.csv'
                with self.assertRaises(ScrubError): structured.scrub_csv(source,output,ScrubContext())
                self.assertFalse(output.exists())

    def test_independent_verifier_compares_entire_prefix_and_data(self):
        source=self.source(); out,report,artifact=self.run_scrub(source)
        choices={'file0001':self.decisions()}
        result=verify.verify_directory(out,{'file0001':source},review_decisions=choices)['files']['file0001']
        self.assertTrue(result['source_comparison_passed'],result)
        self.assertTrue(result['semantic_mask_review_passed'],result)
        self.assertEqual(result['source_values_compared'],1+2*len(HEADERS))
        self.assertEqual(result['protected_identifiers_compared'],4)
        rows=self.rows(artifact); rows[0][0]='Changed technical metadata'
        with artifact.open('w',newline='') as stream: csv.writer(stream).writerows(rows)
        result=verify.verify_directory(out,{'file0001':source},review_decisions=choices)['files']['file0001']
        self.assertFalse(result['source_comparison_passed'])
        self.assertIn('retained_source_value_changed',result['errors'])
        rows[0][0]=BANNER; rows[2][10]='1.2400'
        with artifact.open('w',newline='') as stream: csv.writer(stream).writerows(rows)
        result=verify.verify_directory(out,{'file0001':source},review_decisions=choices)['files']['file0001']
        self.assertFalse(result['source_comparison_passed'])

    def test_removed_prefix_is_rejected(self):
        source=self.source(); out,report,artifact=self.run_scrub(source)
        rows=self.rows(artifact)[1:]
        with artifact.open('w',newline='') as stream: csv.writer(stream).writerows(rows)
        result=verify.verify_directory(out,{'file0001':source},review_decisions={'file0001':self.decisions()})['files']['file0001']
        self.assertFalse(result['source_comparison_passed'])
        self.assertIn('csv_preamble_structure_changed',result['errors'])

    def test_personal_metadata_stays_preserved_and_blocked(self):
        source=self.source([[f'Contact: {EMAIL}'],HEADERS,ROW]); output=self.root/'clean.csv'; events=[]
        structured.scrub_csv(source,output,ScrubContext(review_location_sink=events.append))
        self.assertEqual(self.rows(output)[0],[f'Contact: {EMAIL}'])
        self.assertTrue(any(e['location']=='r1.c1' and e['reason']=='schema_label_contains_pii' for e in events),events)
        out,report,artifact=self.run_scrub(source)
        choices=self.decisions(); choices['r1.c1']={'action':'retain','reason_code':'technical_description'}
        result=verify.verify_directory(out,{'file0001':source},review_decisions={'file0001':choices})['files']['file0001']
        self.assertFalse(result['policy_scan_passed'])
        self.assertFalse(result['independent_candidate_scan_passed'])

    def test_grouping_keeps_metadata_schema_and_data_record_coordinates(self):
        source=self.source(); out,report,artifact=self.run_scrub(source)
        verification=verify.verify_directory(out,{'file0001':source})
        record=report['files'][0]
        with (out/record['review_location_index']).open('a') as stream:
            for location in ['r1.c1','r2.c1']:
                stream.write(json.dumps({'location':location,'reason':'ambiguous_human_name','count':1})+'\n')
        grouped=group_review.group_file(out,record,source,verification)
        contexts={loc:g['context'] for g in grouped['groups'] for loc in g['locations']}
        self.assertEqual(contexts['r1.c1'],'metadata');self.assertEqual(contexts['r2.c1'],'schema');self.assertEqual(contexts['r3.c12'],'data')
        self.assertNotIn(EMAIL,json.dumps(grouped));self.assertNotIn(BANNER,json.dumps(grouped))

    def test_resource_suffixes_are_bounded_and_record_id_contextual(self):
        protected=['user:PLATFORM_CLUSTERID','user:APP_CORE_CLUSTER_NAME','customVpcId','user:APP_VPC',
                   'resourceTags/user:NETWORK_VPCID','LinkedAccountId']
        for field in protected:
            with self.subTest(field=field):
                self.assertTrue(is_protected_resource_field(field))
                ctx=ScrubContext();self.assertEqual(ctx.scrub(EMAIL,field,'r3.c1'),EMAIL)
                self.assertEqual(ctx.review_counts['protected_identifier_contains_pii'],1)
        for field in ['RecordID','user:Owner','user:Name','user:contact_email','user:cluster_owner','user:clusteridOwner']:
            self.assertFalse(is_protected_resource_field(field),field)
        layout=structured.csv_layout(self.source())
        self.assertEqual(layout.field('RecordID'),'billingrecordid')
        generic=self.source([['RecordID','cost'],['row-1','1.2']],name='generic.csv')
        self.assertEqual(structured.csv_layout(generic).field('RecordID'),'RecordID')
        self.assertEqual(ScrubContext().scrub(EMAIL,'user:contact_email','r3.c1'),'X'*len(EMAIL))

    def test_legacy_header_without_preamble_keeps_header_at_row_one(self):
        source=self.source([HEADERS,ROW]); output=self.root/'clean.csv'; events=[]
        metrics=structured.scrub_csv(source,output,ScrubContext(removal_location_sink=events.append))
        self.assertEqual(metrics['header_row'],1);self.assertEqual(metrics['preamble_rows'],0)
        self.assertEqual([e['location'] for e in events],['r2.c12'])
        self.assertEqual(self.rows(output)[0],HEADERS)

    def test_aws_account_labels_and_name_tag_are_contextual_resource_keys(self):
        headers=HEADERS+['PayerAccountName','LinkedAccountName','user:Name']
        row=ROW+[EMAIL,EMAIL,EMAIL]
        source=self.source([[BANNER],headers,row]); output=self.root/'clean.csv'; events=[]
        structured.scrub_csv(source,output,ScrubContext(review_location_sink=events.append))
        self.assertEqual(self.rows(output)[2][-3:],[EMAIL,EMAIL,EMAIL])
        self.assertEqual({e['location'] for e in events if e['reason']=='protected_identifier_contains_pii'},
                         {'r3.c15','r3.c16','r3.c17'})
        generic=self.source([['user:Name','contact'],[EMAIL,'support@example.invalid']],name='generic-tag.csv')
        layout=structured.csv_layout(generic)
        self.assertEqual(layout.field('user:Name'),'user:Name')
        generic_output=self.root/'generic-clean.csv'
        structured.scrub_csv(generic,generic_output,ScrubContext())
        self.assertEqual(self.rows(generic_output)[1][0],'X'*len(EMAIL))

    def test_large_regular_csv_value_is_not_limited_by_header_probe(self):
        value='0'*200000
        source=self.source([['details'],[value]],name='large.csv'); output=self.root/'large-clean.csv'
        structured.scrub_csv(source,output,ScrubContext())
        self.assertEqual(self.rows(output),[['details'],[value]])

if __name__=='__main__': unittest.main(verbosity=2)
