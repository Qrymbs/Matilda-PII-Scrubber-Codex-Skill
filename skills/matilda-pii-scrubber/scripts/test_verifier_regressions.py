"""Synthetic source-comparison tests; values never leave temporary fixtures."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from verify_outputs import verify_directory

SCRIPTS=Path(__file__).parent

class SourceVerification(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='verifier-synthetic-')
        self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def run_scrub(self,path):
        out=self.root/('run'+str(len(list(self.root.glob('run*')))))
        proc=subprocess.run([sys.executable,str(SCRIPTS/'scrub.py'),str(path),'--output-dir',str(out)],capture_output=True,text=True)
        report=json.loads((out/'scrub-report.json').read_text())
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        return out,report
    def csv(self,rows,name='billing.csv'):
        path=self.root/name
        with path.open('w',newline='') as f:csv.writer(f).writerows(rows)
        return path
    def check(self,out,source,decisions=None):
        return verify_directory(out,sources={'file0001':source},review_decisions={'file0001':decisions or {}})['files']['file0001']
    def test_source_is_mandatory_and_not_saved(self):
        source=self.csv([['cost'],['1.20']]);out,_=self.run_scrub(source)
        result=verify_directory(out)
        self.assertFalse(result['files']['file0001']['source_comparison_passed'])
        self.assertNotIn(str(source),json.dumps(result))
        self.assertIn('original_source_required',result['files']['file0001']['errors'])
    def test_removed_values_and_uncapped_ledger_reconcile(self):
        source=self.csv([['email','cost']]+[['casey.rowan@example.invalid','1.20'] for _ in range(55)])
        out,report=self.run_scrub(source)
        result=self.check(out,source)
        self.assertTrue(result['source_comparison_passed'],result)
        self.assertTrue(result['independent_candidate_scan_passed'],result)
        ledger=out/report['files'][0]['removal_location_index']
        ledger.write_text('\n'.join(ledger.read_text().splitlines()[:-1])+'\n')
        result=self.check(out,source)
        self.assertFalse(result['source_comparison_passed'])
        self.assertIn('source_changes_do_not_match_removal_ledger',result['errors'])
    def test_report_count_and_whole_action_tampering_rejected(self):
        source=self.csv([['email'],['casey.rowan@example.invalid']]);out,report=self.run_scrub(source)
        report['files'][0]['counts_by_category']['human_email_addresses']=99
        report['files'][0]['context_review']['removed_items']=99
        (out/'scrub-report.json').write_text(json.dumps(report))
        result=self.check(out,source)
        self.assertIn('source_changes_do_not_match_reported_counts',result['errors'])
        self.assertIn('source_changes_do_not_match_whole_item_actions',result['errors'])
    def test_independent_candidate_broader_than_policy_requires_exact_decision(self):
        source=self.csv([['misc','cost'],['Casey Rowan','1.20'],['Reese Avery','2.40']]);out,report=self.run_scrub(source)
        self.assertEqual(report['files'][0]['context_review']['review_occurrences'],0)
        result=self.check(out,source)
        self.assertTrue(result['source_comparison_passed'],result)
        self.assertTrue(result['policy_scan_passed'],result)
        self.assertFalse(result['independent_candidate_scan_passed'])
        choice={'action':'retain','reason_code':'organization_or_project_label'}
        one=self.check(out,source,{'r2.c1':choice})
        self.assertFalse(one['independent_candidate_scan_passed'])
        self.assertEqual(one['unresolved_candidate_locations'],['r3.c1'])
        both=self.check(out,source,{'r2.c1':choice,'r3.c1':choice})
        self.assertTrue(both['independent_candidate_scan_passed'],both)
    def test_unknown_email_resolution_does_not_authorize_changes(self):
        source=self.csv([['contact'],['qrx@example.invalid']]);out,report=self.run_scrub(source)
        choice={'r2.c1':{'action':'retain','reason_code':'shared_organizational_mailbox'}}
        (out/report['files'][0]['artifact']).write_text('contact\nother@example.invalid\n')
        result=self.check(out,source,choice)
        self.assertFalse(result['source_comparison_passed'])
        self.assertIn('retained_source_value_changed',result['errors'])
    def test_xlsx_resolved_review_history_does_not_block_but_missing_decision_does(self):
        from openpyxl import Workbook
        source=self.root/'technical-contacts.xlsx'
        book=Workbook();sheet=book.active
        sheet.append(['Contact']);sheet.append(['qrx@example.invalid']);sheet.append(['qrs@example.invalid']);book.save(source)
        out,report=self.run_scrub(source)
        self.assertEqual(report['files'][0]['context_review']['review_occurrences'],2)
        retain={'action':'retain','reason_code':'shared_organizational_mailbox'}
        # The fixture's generator writes a known application label in app.xml;
        # explicitly review that independent metadata candidate as well.
        metadata={'action':'retain','reason_code':'technical_description'}
        partial=self.check(out,source,{'s1.r2.c1':retain,'p2.k2.i1':metadata})
        self.assertFalse(partial['independent_candidate_scan_passed'])
        self.assertIn('s1.r3.c1',partial['unresolved_candidate_locations'])
        complete=self.check(out,source,{'s1.r2.c1':retain,'s1.r3.c1':retain,'p2.k2.i1':metadata})
        self.assertTrue(complete['source_comparison_passed'],complete)
        self.assertTrue(complete['policy_scan_passed'],complete)
        self.assertTrue(complete['independent_candidate_scan_passed'],complete)
    def test_parquet_nested_schema_and_exact_numbers(self):
        from decimal import Decimal
        import pyarrow as pa
        import pyarrow.parquet as pq
        source=self.root/'precise-billing.parquet'
        schema=pa.schema([pa.field('cost',pa.decimal128(30,19)),
                          pa.field('nested',pa.struct([pa.field('email',pa.string()),pa.field('id',pa.uint64())]))])
        pq.write_table(pa.Table.from_pylist([{'cost':Decimal('0.1234567890123456789'),
                                            'nested':{'email':'casey.rowan@example.invalid','id':12345678901234567890}}],schema=schema),source)
        out,report=self.run_scrub(source)
        result=self.check(out,source)
        self.assertTrue(result['source_comparison_passed'],result)
        target=out/report['files'][0]['artifact']
        table=pq.read_table(target)
        self.assertEqual(table['cost'][0].as_py(),Decimal('0.1234567890123456789'))
        self.assertEqual(table['nested'][0].as_py()['id'],12345678901234567890)
        changed=table.set_column(0,table.schema.field('cost'),pa.array([Decimal('0.1234567890123456788')],type=schema[0].type))
        pq.write_table(changed,target)
        self.assertFalse(self.check(out,source)['source_comparison_passed'])
    def test_nulling_unknown_value_without_decision_rejected(self):
        source=self.csv([['owner'],['qrx']]);out,report=self.run_scrub(source)
        with (out/report['files'][0]['artifact']).open('w',newline='') as f:csv.writer(f).writerows([['owner'],['']])
        result=self.check(out,source)
        self.assertIn('unjustified_source_value_change',result['errors'])
    def test_schema_human_name_preserved_and_filename_masks_reconcile(self):
        source=self.csv([['casey.rowan@example.invalid','cost'],['vm-prod-4','2.50']],name='casey.rowan@example.invalid.csv')
        out,_=self.run_scrub(source)
        result=self.check(out,source)
        self.assertTrue(result['source_comparison_passed'],result)
    def test_parquet_nested_maps_use_per_parent_ordinals(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        typ=pa.struct([pa.field('tags',pa.map_(pa.string(),pa.string()))])
        schema=pa.schema([pa.field('record',typ),pa.field('cost',pa.decimal128(12,2))],metadata={b'catalog':b'billing-v1'})
        from decimal import Decimal
        source=self.root/'billing.parquet'
        pq.write_table(pa.Table.from_pylist([
            {'record':{'tags':[('owner','casey.rowan@example.invalid'),('app','db-service')]},'cost':Decimal('3.45')},
            {'record':{'tags':[('app','db-service'),('owner','casey.rowan@example.invalid')]},'cost':Decimal('6.70')}],schema=schema),source)
        out,report=self.run_scrub(source)
        result=self.check(out,source)
        self.assertTrue(result['source_comparison_passed'],result)
        self.assertTrue(result['independent_candidate_scan_passed'],result)
        events=[json.loads(x) for x in (out/report['files'][0]['removal_location_index']).read_text().splitlines()]
        self.assertEqual([x['location'] for x in events],['r1.c1.k1.k1','r2.c1.k1.k2'])
        target=out/report['files'][0]['artifact'];table=pq.read_table(target)
        pq.write_table(table.replace_schema_metadata({b'catalog':b'billing-v2'}),target)
        self.assertFalse(self.check(out,source)['source_comparison_passed'])
    def test_parquet_nullable_contract_and_type_change_rejected(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        source=self.root/'billing.parquet'
        pq.write_table(pa.Table.from_arrays([pa.array([42],type=pa.int64())],schema=pa.schema([pa.field('cost',pa.int64(),nullable=False)])),source)
        out,report=self.run_scrub(source)
        self.assertTrue(self.check(out,source)['source_comparison_passed'])
        target=out/report['files'][0]['artifact']
        pq.write_table(pa.Table.from_arrays([pa.array([42],type=pa.int64())],names=['cost']),target)
        result=self.check(out,source)
        self.assertIn('parquet_field_nullability_changed',result['errors'])
    def test_xlsx_metadata_and_formula_mutations_rejected(self):
        from openpyxl import Workbook
        source=self.root/'billing.xlsx';book=Workbook();book.properties.creator='system'
        sheet=book.active;sheet.append(['cost','email']);sheet.append([2.5,'casey.rowan@example.invalid']);sheet['A3']='=A2*2';book.save(source)
        out,report=self.run_scrub(source)
        result=self.check(out,source)
        self.assertTrue(result['source_comparison_passed'],result)
        target=out/report['files'][0]['artifact']
        with zipfile.ZipFile(target) as z:members=[(i,z.read(i)) for i in z.infolist()]
        with zipfile.ZipFile(target,'w') as z:
            for i,data in members:z.writestr(i,data.replace(b'A2*2',b'A2*3') if i.filename=='xl/worksheets/sheet1.xml' else data)
        self.assertFalse(self.check(out,source)['source_comparison_passed'])
    def test_encoded_csv_preserves_parsed_text_numbers_and_newlines(self):
        import io
        email='casey.rowan@example.invalid'
        notes='Contact '+email+'; cost=1.20\r\nservice=vm-prod-7'
        stream=io.StringIO(newline='');csv.writer(stream).writerows([['notes','cost'],[notes,'1.20']])
        original=stream.getvalue()
        for index,encoding in enumerate(('utf-8-sig','utf-16-le','utf-16-be')):
            source=self.root/f'encoded-{index}.csv'
            prefix=b'\xff\xfe' if encoding=='utf-16-le' else b'\xfe\xff' if encoding=='utf-16-be' else b''
            source.write_bytes(prefix+original.encode(encoding));source_bytes=source.read_bytes()
            out,report=self.run_scrub(source)
            result=self.check(out,source)
            self.assertTrue(result['source_comparison_passed'],result)
            self.assertTrue(result['independent_candidate_scan_passed'],result)
            target=out/report['files'][0]['artifact']
            with target.open(encoding='utf-8',newline='') as handle:rows=list(csv.reader(handle))
            self.assertEqual(rows,[['notes','cost'],[notes.replace(email,'X'*len(email)),'1.20']])
            self.assertEqual(source.read_bytes(),source_bytes)
            rows[1][1]='1.21'
            with target.open('w',encoding='utf-8',newline='') as handle:csv.writer(handle).writerows(rows)
            self.assertFalse(self.check(out,source)['source_comparison_passed'])

    def test_parquet_metadata_masks_have_exact_span_evidence(self):
        import pyarrow as pa
        import pyarrow.parquet as pq
        source=self.root/'metadata.parquet'
        schema=pa.schema([pa.field('cost',pa.int64())],metadata={b'author':b'Casey Rowan',b'catalog':b'catalog-v1'})
        pq.write_table(pa.Table.from_arrays([pa.array([42])],schema=schema),source)
        out,report=self.run_scrub(source)
        result=self.check(out,source)
        self.assertTrue(result['source_comparison_passed'],result)
        self.assertTrue(result['independent_candidate_scan_passed'],result)
        self.assertEqual(pq.read_schema(out/report['files'][0]['artifact']).metadata[b'author'],b'XXXXXXXXXXX')

    def test_span_ledger_and_character_count_tampering_are_rejected(self):
        source=self.csv([['email'],['casey.rowan@example.invalid']]);out,report=self.run_scrub(source)
        ledger=out/report['files'][0]['removal_location_index']
        event=json.loads(ledger.read_text())
        event['spans'][0]['end']-=1
        ledger.write_text(json.dumps(event)+'\n')
        result=self.check(out,source)
        self.assertTrue({'source_changes_do_not_match_mask_span_ledger','mask_span_character_count_mismatch','expected_x_mask_mismatch'} & set(result['errors']),result)
        self.assertIn('mask_span_character_count_mismatch',result['errors'])

    def test_unused_decision_cannot_pass(self):
        source=self.csv([['cost'],['1']]);out,_=self.run_scrub(source)
        result=self.check(out,source,{'r500.c1':{'action':'retain','reason_code':'billing_or_infrastructure_value'}})
        self.assertIn('unused_review_decisions',result['errors'])

if __name__=='__main__':unittest.main(verbosity=2)
