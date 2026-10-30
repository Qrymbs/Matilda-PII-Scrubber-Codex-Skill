"""Synthetic invariants for source-proven, codepoint-preserving X masks."""
from types import SimpleNamespace
import unittest
from verify_outputs import ArtifactComparison

class XMaskVerification(unittest.TestCase):
    def check(self, choices=None):
        return ArtifactComparison(SimpleNamespace(max_depth=12), {'output_format':'csv'}, choices or {})

    def test_mixed_value_preserves_every_nonpii_character(self):
        source = 'Owner casey.rowan@example.invalid; cost=1.20; vm=vm-prod-1'
        start = source.index('casey.')
        end = source.index(';')
        masked = source[:start]+'X'*(end-start)+source[end:]
        choice={'action':'mask','reason_code':'named_person_email','spans':[{'start':start,'end':end,'category':'human_email_addresses'}]}
        check = self.check({'r2.c1':choice})
        check.pair(source,masked,'description','r2.c1')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertTrue(check.result['policy_scan_passed'],check.result)
        self.assertTrue(check.result['independent_candidate_scan_passed'],check.result)
        self.assertEqual(check.actions,1)
        self.assertEqual(check.masked_characters,end-start)
        self.assertEqual(check.masked_spans,1)
        for wrong in (masked.replace('1.20','1.21'), masked[:-1], masked.replace('X','x',1), ''):
            check=self.check({'r2.c1':choice});check.pair(source,wrong,'description','r2.c1')
            self.assertFalse(check.comparison_ok,wrong)

    def test_literal_x_runs_are_not_output_only_evidence(self):
        check=self.check();check.pair('machine-value','XXXXXXXXXXXXX','resource_id','r2.c1')
        self.assertFalse(check.comparison_ok)
        self.assertIn('protected_resource_identifier_changed',check.result['errors'])
        check=self.check();check.scan('XXXX XXXX','owner','r2.c1')
        self.assertFalse(check.result['independent_candidate_scan_passed'])
        check=self.check();check.pair('XX-01','XX-01','resource_id','r2.c1')
        self.assertTrue(check.comparison_ok)
        self.assertTrue(check.result['independent_candidate_scan_passed'])

    def test_existing_duplicate_identifiers_allowed_new_collisions_rejected(self):
        check=self.check()
        for row in (2,3):check.pair('vm-001','vm-001','resource_id',f'r{row}.c1')
        self.assertTrue(check.comparison_ok)
        self.assertEqual(check.result['new_resource_key_collisions'],0)
        check.pair('vm-002','vm-001','resource_id','r4.c1')
        self.assertIn('new_resource_key_collision',check.result['errors'])
        self.assertEqual(check.result['new_resource_key_collisions'],1)
        self.assertFalse(check.result['resource_key_collision_check_passed'])

    def test_protected_name_shaped_identifier_is_not_automatically_personal(self):
        check=self.check();check.pair('Casey Rowan','Casey Rowan','hostname','r2.c1')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertTrue(check.result['independent_candidate_scan_passed'],check.result)

    def test_protected_identifier_with_embedded_human_data_stays_and_blocks(self):
        source='resource:casey.rowan@example.invalid'
        check=self.check();check.pair(source,source,'resource_id','r2.c1')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertFalse(check.result['independent_candidate_scan_passed'])
        check=self.check();check.pair(source,'X'*len(source),'resource_id','r2.c1')
        self.assertFalse(check.comparison_ok)
        choice={'action':'retain','reason_code':'machine_identity'}
        check=self.check({'r2.c1':choice});check.pair(source,source,'resource_id','r2.c1')
        self.assertFalse(check.result['independent_candidate_scan_passed'])

    def test_manual_spans_are_coordinate_specific_unicode_codepoints(self):
        source='label=Zoë 🐈; id=vm-007'
        start=source.index('Zoë');end=source.index(';')
        choice={'action':'mask','reason_code':'explicit_person_name',
                'spans':[{'start':start,'end':end,'category':'human_names'}]}
        check=self.check({'r2.c1':choice})
        check.pair(source,source[:start]+'X'*(end-start)+source[end:],'misc','r2.c1')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertEqual(check.masked_characters,5)
        check.pair(source,source[:start]+'X'*(end-start)+source[end:],'misc','r3.c1')
        self.assertFalse(check.comparison_ok)

    def test_partial_manual_mask_does_not_clear_unmasked_email(self):
        source='Casey; reese.avery@example.invalid'
        choice={'action':'mask','reason_code':'explicit_person_name',
                'spans':[{'start':0,'end':5,'category':'human_names'}]}
        check=self.check({'r2.c1':choice})
        check.pair(source,'XXXXX'+source[5:],'misc','r2.c1')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertFalse(check.result['policy_scan_passed'])
        self.assertFalse(check.result['independent_candidate_scan_passed'])

    def test_native_numeric_identity_type_is_preserved_and_review_blocked(self):
        check=self.check();check.pair(123456,123456,'employee_id','r2.c1')
        self.assertTrue(check.comparison_ok)
        self.assertFalse(check.result['independent_candidate_scan_passed'])
        for wrong in ('XXXXXX',None):
            check=self.check();check.pair(123456,wrong,'employee_id','r2.c1')
            self.assertFalse(check.comparison_ok)

    def test_schema_labels_are_immutable(self):
        check=self.check();check.schema_label('casey.rowan@example.invalid','field_0001',1,'r1.c1')
        self.assertFalse(check.comparison_ok)
        self.assertIn('schema_label_changed_unexpectedly',check.result['errors'])

    def test_mask_decision_can_resolve_only_proven_nonpersonal_residual(self):
        source='Contact: Casey Rowan; shared=admin@example.invalid; CPU=4'
        choice={'action':'mask','reason_code':'explicit_person_name',
                'spans':[{'start':9,'end':20,'category':'human_names'}]}
        output=source[:9]+'X'*11+source[20:]
        check=self.check({'r2.c1':choice});check.pair(source,output,'notes','r2.c1')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertFalse(check.result['independent_candidate_scan_passed'])
        choice['residual_reason_code']='shared_organizational_mailbox'
        check=self.check({'r2.c1':choice});check.pair(source,output,'notes','r2.c1')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertTrue(check.result['independent_candidate_scan_passed'],check.result)
        # A later occurrence has no review authority from the first occurrence.
        check.pair(source,output,'notes','r3.c1')
        self.assertFalse(check.result['independent_candidate_scan_passed'])
        # A residual decision without proof of source-derived masks cannot pass.
        check=self.check({'r2.c1':choice});check.scan(output,'notes','r2.c1')
        self.assertFalse(check.result['independent_candidate_scan_passed'])

    def test_residual_reason_never_waives_retained_confirmed_pii(self):
        source='Casey; reese.avery@example.invalid'
        choice={'action':'mask','reason_code':'explicit_person_name',
                'spans':[{'start':0,'end':5,'category':'human_names'}],
                'residual_reason_code':'shared_organizational_mailbox'}
        check=self.check({'r2.c1':choice})
        check.pair(source,'XXXXX'+source[5:],'misc','r2.c1')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertFalse(check.result['policy_scan_passed'])
        self.assertFalse(check.result['independent_candidate_scan_passed'])

    def test_container_review_cannot_waive_descendant_scans(self):
        value={'owner':{'full_name':'Casey Rowan'}}
        choice={'action':'retain','reason_code':'technical_description'}
        check=self.check({'root':choice});check.scan(value,None,'root')
        self.assertIn('review_decision_requires_scalar',check.result['errors'])
        self.assertFalse(check.result['independent_candidate_scan_passed'])
        check=self.check({'root':choice});check.pair(value,value,None,'root')
        self.assertFalse(check.comparison_ok)
        self.assertIn('retained_human_pii_found',check.result['errors'])

    def test_protected_ancestor_preserves_child_semantic_pii_evidence(self):
        source={'full_name':'Casey Rowan','employee_id':42,'cost':'1.20'}
        choices={'root.k1':{'action':'retain','reason_code':'machine_identity'},
                 'root.k2':{'action':'retain','reason_code':'machine_identity'}}
        check=self.check(choices);check.pair(source,source,'resource_id','root')
        self.assertTrue(check.comparison_ok,check.result)
        self.assertFalse(check.result['independent_candidate_scan_passed'])
        self.assertEqual(set(check.result['unresolved_candidate_locations']),{'root.k1','root.k2'})
        self.assertEqual(check.result['protected_identifiers_compared'],3)
        mutated=dict(source,full_name='X'*11)
        check=self.check();check.pair(source,mutated,'resource_id','root')
        self.assertFalse(check.comparison_ok)
        self.assertIn('protected_resource_identifier_changed',check.result['errors'])

if __name__=='__main__':unittest.main(verbosity=2)
