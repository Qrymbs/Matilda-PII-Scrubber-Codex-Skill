"""Synthetic end-to-end release tests; no customer input, network or permanent fixtures."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from review_support import COVERAGE_FIELDS, validate_decisions
from scrub_core import ScrubError
from finalize_report import candidate_coverage

SCRIPTS=Path(__file__).parent

class ReviewWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='pii-review-synthetic-')
        self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def source(self,rows,name='billing.csv'):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('w',newline='') as f:csv.writer(f).writerows(rows)
        return path
    def run_scrub(self,*sources,name='run',plan=None):
        out=self.root/name
        command=[sys.executable,str(SCRIPTS/'scrub.py'),*map(str,sources),'--output-dir',str(out)]
        if plan:command+=['--review-plan',str(plan)]
        proc=subprocess.run(command,capture_output=True,text=True)
        report=json.loads((out/'scrub-report.json').read_text())
        return out,report,proc
    def evidence(self,out,report,decisions=None,coverage=True):
        doc={'version':2,'run_id':report['run_id'],'files':{}}
        for r in report['files']:
            doc['files'][r['file_id']]={**{key:coverage for key in COVERAGE_FIELDS},'unresolved_items':0,'decisions':(decisions or {}).get(r['file_id'],{})}
        path=out/'review-evidence.json';path.write_text(json.dumps(doc));return path
    def finalize(self,out,report,sources,decisions=None,coverage=True,evidence=None):
        evidence=evidence or self.evidence(out,report,decisions,coverage)
        command=[sys.executable,str(SCRIPTS/'finalize_report.py'),str(out/'scrub-report.json'),'--review-evidence',str(evidence)]
        command += [part for fid,p in sources.items() for part in ('--source',fid+'='+str(p))]
        proc=subprocess.run(command,capture_output=True,text=True)
        return proc,json.loads((out/'scrub-report.json').read_text())
    def test_requested_names_and_duplicate_basename_isolation(self):
        a=self.source([['cost'],['1.25']],'a/Quarter 1.billing.csv')
        b=self.source([['cost'],['2.50']],'b/Quarter 1.billing.csv')
        out,report,proc=self.run_scrub(a,b)
        self.assertEqual(proc.returncode,0)
        names=[r['artifact'] for r in report['files']]
        self.assertEqual([Path(p).name for p in names],['Quarter 1.billing_SCRUBBED.csv']*2)
        self.assertEqual(len(set(names)),2)
        self.assertTrue(all((out/p).is_file() for p in names))
    def test_original_extension_case_is_preserved(self):
        src=self.source([['cost'],['1.25']],'Quarter 1.CSV')
        out,report,proc=self.run_scrub(src)
        self.assertEqual(proc.returncode,0)
        self.assertEqual(Path(report['files'][0]['artifact']).name,'Quarter 1_SCRUBBED.CSV')
    def test_review_decisions_reject_unsafe_or_contradictory_evidence(self):
        invalid=[
            {'person@example.invalid':{'action':'retain','reason_code':'shared_organizational_mailbox'}},
            {'r2.c1':{'action':'clear','category':'human_names','reason_code':'machine_identity'}},
            {'r2.c1':{'action':'retain','reason_code':'explicit_person_name'}},
            {'r2.c1':{'action':'clear','category':'human_made_up','reason_code':'explicit_person_name'}},
            {'r2.c1':{'action':'retain','reason_code':'machine_identity','value':'do not persist source values'}},
        ]
        for item in invalid:
            with self.subTest(case=list(item)),self.assertRaises(ScrubError):validate_decisions(item)
    def test_missing_duplicate_or_falsely_resolved_review_events_block(self):
        ledger=self.root/'review.jsonl'
        event={'reason':'ambiguous_email_identity','location':'r2.c1','count':1,'resolved':False}
        record={'review_location_index':'review.jsonl','context_review':{'review_counts':{'ambiguous_email_identity':1},'resolved_review_counts':{},'review_occurrences':1,'resolved_review_occurrences':0}}
        decisions={'r2.c1':{'action':'retain','reason_code':'shared_organizational_mailbox'}}
        ledger.write_text(json.dumps(event)+'\n')
        self.assertTrue(candidate_coverage(self.root,record,decisions))
        ledger.write_text('')
        self.assertFalse(candidate_coverage(self.root,record,decisions))
        ledger.write_text((json.dumps(event)+'\n')*2)
        record['context_review']['review_counts']['ambiguous_email_identity']=2
        record['context_review']['review_occurrences']=2
        self.assertFalse(candidate_coverage(self.root,record,decisions))
        event['resolved']=True;ledger.write_text(json.dumps(event)+'\n')
        record['context_review']={'review_counts':{'ambiguous_email_identity':1},'resolved_review_counts':{'ambiguous_email_identity':1},'review_occurrences':1,'resolved_review_occurrences':1}
        self.assertFalse(candidate_coverage(self.root,record,{}))
    def test_boolean_flags_alone_cannot_finalize(self):
        src=self.source([['cost'],['12.50']]);out,report,_=self.run_scrub(src)
        proc=subprocess.run([sys.executable,str(SCRIPTS/'finalize_report.py'),str(out/'scrub-report.json'),'--context-reviewed','--integrity-reviewed'],capture_output=True,text=True)
        self.assertNotEqual(proc.returncode,0)
        self.assertNotEqual(json.loads((out/'scrub-report.json').read_text())['overall_status'],'ready_for_manual_submission')
    def test_no_original_or_incomplete_coverage_blocks(self):
        src=self.source([['cost'],['12.50']]);out,report,_=self.run_scrub(src)
        proc,final=self.finalize(out,report,{})
        self.assertNotEqual(proc.returncode,0);self.assertEqual(final['files'][0]['submission_status'],'blocked')
        proc,final=self.finalize(out,report,{'file0001':src},coverage=False)
        self.assertNotEqual(proc.returncode,0);self.assertEqual(final['files'][0]['submission_status'],'blocked')
    def test_complete_clean_source_comparison_can_finalize(self):
        src=self.source([['ResourceId','cost'],['vm-prod-4','12.50']]);out,report,_=self.run_scrub(src)
        proc,final=self.finalize(out,report,{'file0001':src})
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        self.assertTrue(final['files'][0]['verification']['source_comparison_passed'])
    def test_unknown_contact_preserved_and_unresolved_not_ready(self):
        src=self.source([['contact','cost'],['qrx@example.invalid','12.50']]);out,report,_=self.run_scrub(src)
        self.assertGreater(report['files'][0]['context_review']['unresolved_review_occurrences'],0)
        with (out/report['files'][0]['artifact']).open(newline='') as f:self.assertEqual(list(csv.reader(f))[1][0],'qrx@example.invalid')
        proc,final=self.finalize(out,report,{'file0001':src})
        self.assertNotEqual(proc.returncode,0);self.assertEqual(final['files'][0]['submission_status'],'blocked')
    def test_exact_nonpersonal_resolution_can_finalize(self):
        src=self.source([['contact','cost'],['qrx@example.invalid','12.50']]);out,report,_=self.run_scrub(src)
        choice={'r2.c1':{'action':'retain','reason_code':'shared_organizational_mailbox'}}
        proc,final=self.finalize(out,report,{'file0001':src},{'file0001':choice})
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        self.assertEqual(final['files'][0]['submission_status'],'ready_for_manual_submission')
    def test_review_plan_mask_is_exact_and_counted(self):
        src=self.source([['owner','cost'],['qrx','12.50'],['Operations Team','5.00']]);out,report,_=self.run_scrub(src)
        plan=out/'review-plan.json';plan.write_text(json.dumps({'version':2,'source_run_id':report['run_id'],'files':{'file0001':{'decisions':{'r2.c1':{'action':'mask','spans':[{'start':0,'end':3,'category':'human_usernames'}],'reason_code':'explicit_person_identifier'}}}}}))
        corrected,result,proc=self.run_scrub(src,name='reviewed',plan=plan)
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        with (corrected/result['files'][0]['artifact']).open(newline='') as f:self.assertEqual(list(csv.reader(f)),[['owner','cost'],['XXX','12.50'],['Operations Team','5.00']])
        self.assertEqual(result['files'][0]['counts_by_category'],{'human_usernames':1})
        proc,final=self.finalize(corrected,result,{'file0001':src})
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
    def test_tampered_retained_billing_value_is_rejected(self):
        src=self.source([['ResourceId','cost'],['vm-prod-4','12.50']]);out,report,_=self.run_scrub(src)
        target=out/report['files'][0]['artifact'];target.write_text('ResourceId,cost\nvm-prod-4,999.99\n')
        proc,final=self.finalize(out,report,{'file0001':src})
        self.assertNotEqual(proc.returncode,0);self.assertFalse(final['files'][0]['verification']['source_comparison_passed'])
    def test_stale_evidence_invalidates_previous_ready_status(self):
        src=self.source([['cost'],['12.50']]);out,report,_=self.run_scrub(src)
        proc,final=self.finalize(out,report,{'file0001':src});self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        path=self.evidence(out,report);doc=json.loads(path.read_text());doc['run_id']='different-run';path.write_text(json.dumps(doc))
        proc,final=self.finalize(out,report,{'file0001':src},evidence=path)
        self.assertNotEqual(proc.returncode,0);self.assertEqual(final['files'][0]['submission_status'],'blocked')
    def test_complete_location_ledger_exceeds_compact_sample_cap(self):
        src=self.source([['email']]+[['casey.rowan@example.invalid'] for _ in range(55)])
        out,report,_=self.run_scrub(src)
        record=report['files'][0]
        events=[json.loads(line) for line in (out/record['removal_location_index']).read_text().splitlines()]
        self.assertEqual(len(events),55)
        self.assertEqual([x['location'] for x in events],[f'r{i}.c1' for i in range(2,57)])
        self.assertTrue(record['context_review']['removal_location_coverage_complete'])

if __name__=='__main__':unittest.main(verbosity=2)
