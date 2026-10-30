"""Synthetic behavioral regressions for confirmed/nonpersonal/unresolved policy."""
import json
import unittest
from scrub_core import ScrubContext, ScrubError, assess_value, detect_categories, detect_value, safe_field_name

PERSON='Avery Stone'
EMAIL='avery.stone@example.invalid'

class HumanEvidenceRegression(unittest.TestCase):
    def test_embedded_named_addresses_in_resource_ids_preserved_and_blocked(self):
        values=[
            'arn:aws:quicksight:us-east-1:123456789012:user/default/billing-admin/'+EMAIL,
            'arn:aws:sts::123456789012:assumed-role/devops-support/'+EMAIL,
            'AssumedRole:AROASYNTHETIC:'+EMAIL+'-delegated',
            'IAMUser:AIDASYNTHETIC:'+EMAIL,
            'support/admin/team prefix: '+EMAIL,
            'Contact ('+EMAIL+').',
            'mary.platformer@example.invalid',
            'avery.stone+support@example.invalid',
            'avery.stone.admin@example.invalid',
            'team.avery.stone@example.invalid',
            'support@example.invalid; '+EMAIL,
            'Contact '+EMAIL+', then continue.',
        ]
        for value in values:
            with self.subTest(value=value):
                self.assertIn('human_email_addresses',detect_categories(value,'ResourceId'))
                ctx=ScrubContext();self.assertEqual(ctx.scrub(value,'ResourceId','r1.c1'),value)
                self.assertIn('protected_identifier_contains_pii',ctx.review_counts)

    def test_encoded_named_addresses_mask_original_codepoints_and_keep_safe_values(self):
        for value in ['avery.stone%40example.invalid','avery%2Estone%40example.invalid','avery.stone%2540example.invalid','avery.stone%252540example.invalid','avery.stone&#64;example.invalid','avery.stone&#x40;example.invalid','avery.stone&commat;example.invalid',r'avery.stone\u0040example.invalid',r'avery.stone\x40example.invalid']:
            with self.subTest(value=value):self.assertEqual(ScrubContext().scrub(value,'Description','r1.c1'),'X'*len(value))
        value='service%40project.iam.gserviceaccount.com'
        self.assertEqual(ScrubContext().scrub(value,'ResourceId','r1.c1'),value)
        self.assertIn('encoded_contact_marker',assess_value('opaque%252525252540example.invalid','Notes')[1])

    def test_service_and_project_mailboxes_do_not_become_people(self):
        for local in ['support','admin','info','FinanceMigration','ComplianceMonitoring','IdentityCertificatesL3','MarketForecastAI','ProjectAnalyticsDev','SubscriptionFabricDev','svc_robot','CI_CD_Pipeline','AutomationMailbox']:
            value=local+'@example.invalid'
            with self.subTest(local=local):
                cats,reasons=assess_value(value,'contact')
                self.assertFalse(cats)
                self.assertEqual(ScrubContext().scrub(value,'contact','r1.c1'),value)
        self.assertFalse(assess_value('support@example.invalid','contact')[1])

    def test_unknown_alias_preserved_and_reviewed(self):
        for value in ['opaquealias@example.invalid','unmapped@example.invalid','alex.support@example.invalid','123456789@example.invalid','support+avery.stone@example.invalid']:
            with self.subTest(value=value):
                ctx=ScrubContext();self.assertEqual(ctx.scrub(value,'Email','r1.c1'),value)
                self.assertTrue(ctx.safe_report()['unresolved_review_counts'])
                self.assertEqual(ctx.changed,0)
                self.assertIsNone(detect_value(value,'Email'))

    def test_explicit_personal_email_field_resolves_opaque_alias(self):
        self.assertIn('human_email_addresses',detect_categories('opaquealias@example.invalid','Personal Email'))
        self.assertFalse(detect_categories('support@example.invalid','Personal Email'))
        self.assertIn('human_email_addresses',detect_categories('alex.support@example.invalid','Personal Email'))

    def test_function_metric_attribution_is_technical(self):
        for value in ['Invocation duration during provisioned period weighted by memory assigned to function in GB-s','Concurrency weighted by memory assigned to function over provisioned period','Ephemeral storage assigned to function during execution','Disk assigned to function','Cache assigned to function']:
            with self.subTest(value=value):
                self.assertEqual(assess_value(value,'Description'),(set(),set()))
                self.assertEqual(ScrubContext().scrub(value,'Description','r1.c1'),value)
        self.assertEqual(ScrubContext().scrub('Assigned to '+PERSON+' during onboarding.','Notes','r1.c1'),'Assigned to '+'X'*len(PERSON)+' during onboarding.')

    def test_ambiguous_owner_ids_handles_and_namespaced_tags_survive(self):
        for field,value in [('owner','astone'),('user','astone77'),('owner','123456789'),('user_owner','123456789'),('resource_tags/user:contact','opaquealias'),('aws:createdBy','IAMUser:AIDASYNTHETIC:astone')]:
            with self.subTest(field=field,value=value):
                ctx=ScrubContext();self.assertEqual(ctx.scrub(value,field,'r1.c1'),value)
                self.assertTrue(ctx.review_counts)
        for field,value in [('user_name','database-prod-01'),('user:Name','Acme resource'),('user:Project','cloud-migration'),('owner','Example Company LLC'),('contact','Operations Team')]:
            with self.subTest(field=field):self.assertEqual(ScrubContext().scrub(value,field,'r1.c1'),value)
        self.assertEqual(ScrubContext().scrub(PERSON,'user:owner','r1.c1'),'X'*len(PERSON))
        self.assertEqual(ScrubContext().scrub(PERSON,'user:full_name','r1.c1'),'X'*len(PERSON))
        self.assertEqual(ScrubContext().scrub('Avery','user:first_name','r1.c1'),'XXXXX')
        self.assertEqual(ScrubContext().scrub('opaquealias@example.invalid','user:personal_email','r1.c1'),'X'*len('opaquealias@example.invalid'))

    def test_machine_actor_sessions_preserved_named_handles_reviewed(self):
        for terminal in ['AWSCloudFormation','tf-session','i-0123456789abcdef0','svc_robot','Gitlab_Pipeline']:
            value='AssumedRole:AROASYNTHETIC:'+terminal
            with self.subTest(terminal=terminal):self.assertEqual(assess_value(value,'ResourceId'),(set(),set()))
        for terminal in ['astone','astone77','123456789']:
            value='IAMUser:AIDASYNTHETIC:'+terminal
            with self.subTest(terminal=terminal):self.assertIn('ambiguous_actor_identity',assess_value(value,'ResourceId')[1])

    def test_metadata_alias_and_profile_context(self):
        self.assertEqual(ScrubContext().scrub(PERSON,'refreshedBy','root.k1'),'X'*len(PERSON))
        self.assertEqual(assess_value('Example Corporation LLC','author'),(set(),set()))
        self.assertEqual(ScrubContext().scrub(r'C:\Users\Avery.Stone\report.xlsx','metadata','root.k1'),r'C:\Users\XXXXXXXXXXX\report.xlsx')
        for path in [r'C:\Users\Public\report.xlsx','/home/ubuntu/report','/Users/Shared/report']:
            with self.subTest(path=path):self.assertEqual(assess_value(path,'metadata'),(set(),set()))
        path='/Users/astone/report'
        self.assertEqual(assess_value(path,'metadata')[0],set())
        self.assertIn('ambiguous_person_profile_path',assess_value(path,'metadata')[1])
        self.assertIn('human_usernames',assess_value(path,'personprofile')[0])

    def test_name_lists_and_mixed_categories_preserve_delimiters_count_masked_items(self):
        self.assertEqual(ScrubContext().scrub('Avery Stone:Robin Lake','contact','r1.c1'),'X'*len(PERSON)+':'+'X'*len('Robin Lake'))
        ctx=ScrubContext();self.assertEqual(ctx.scrub('Full name: '+PERSON+'; email '+EMAIL+'; Phone: +1 (202) 555-0147','Notes','r1.c1'),'Full name: '+'X'*len(PERSON)+'; email '+'X'*len(EMAIL)+'; Phone: '+'X'*len('+1 (202) 555-0147'))
        self.assertTrue({'human_names','human_email_addresses','human_phone_numbers'}<=ctx.counts.keys())
        self.assertEqual(ctx.changed,1);self.assertEqual(ctx.leaf_values_cleared,0)
        self.assertEqual(ctx.masked_spans,3)
        self.assertFalse(ctx.review_counts)

    def test_display_name_with_shared_address_masks_name_only(self):
        for value in [PERSON+' <support@example.invalid>','"'+PERSON+'" <admin@example.invalid>']:
            with self.subTest(value=value):
                self.assertEqual(assess_value(value,'contact')[0],{'human_names'})
                self.assertEqual(ScrubContext().scrub(value,'contact','r1.c1'),value.replace(PERSON,'X'*len(PERSON)))
        value='Operations Team <support@example.invalid>'
        self.assertEqual(ScrubContext().scrub(value,'contact','r1.c1'),value)

    def test_embedded_tag_json_masks_leaf_spans_and_preserves_structure(self):
        for value in ['{"contact_name":"'+PERSON+'","resource_id":"vm1"}', '{"person":{"name":"'+PERSON+'"},"cost":10}']:
            with self.subTest(value=value):self.assertEqual(ScrubContext().scrub(value,'Tags','r1.c1'),value.replace(PERSON,'X'*len(PERSON)))
        duplicate='{"contact_name":"'+PERSON+'","contact_name":"Operations Team"}'
        duplicate_ctx=ScrubContext()
        self.assertEqual(duplicate_ctx.scrub(duplicate,'Tags','r1.c1'),duplicate)
        self.assertIn('embedded_person_context_uninspected',duplicate_ctx.review_counts)
        for value in ['{"user_name":"vm-prod-01","owner":"Operations Team"}', '{"creator":"123456789","email":"unknownalias@example.invalid"}']:
            with self.subTest(value=value):self.assertEqual(ScrubContext().scrub(value,'Tags','r1.c1'),value)
        ctx=ScrubContext();ctx.scrub('{"creator":"123456789"}','Tags','r1.c1')
        self.assertTrue(ctx.review_counts)

    def test_review_decisions_are_exact_and_value_free(self):
        decision={'r1.c1':{'action':'retain','reason_code':'shared_organizational_mailbox'},'r2.c1':{'action':'mask','spans':[{'start':0,'end':6,'category':'human_usernames'}],'reason_code':'explicit_person_identifier'}}
        ctx=ScrubContext(review_decisions=decision)
        self.assertEqual(ctx.scrub('opaquealias@example.invalid','Email','r1.c1'),'opaquealias@example.invalid')
        self.assertEqual(ctx.scrub('astone','owner','r2.c1'),'XXXXXX')
        self.assertEqual(ctx.scrub('anotheralias@example.invalid','Email','r3.c1'),'anotheralias@example.invalid')
        report=ctx.safe_report()
        self.assertEqual(report['resolved_review_occurrences'],2)
        self.assertEqual(report['unresolved_review_occurrences'],1)
        self.assertEqual(len(report['applied_review_decisions']),2)
        for value in ['opaquealias','astone','anotheralias',EMAIL,PERSON]:self.assertNotIn(value,json.dumps(report))
        with self.assertRaises(ScrubError):ctx.scrub('astone','owner','r2.c1')

    def test_document_coordinates_and_evidence_reasons_are_preserved(self):
        retain_reasons=['shared_organizational_mailbox','machine_identity','organization_or_project_label','technical_description','billing_or_infrastructure_value']
        mask_reasons=['named_person_email','explicit_person_name','explicit_person_identifier','human_author_metadata','corroborated_personal_path','personal_contact_record','personal_sensitive_record']
        for reason in retain_reasons:
            ctx=ScrubContext(review_decisions={'filename':{'action':'retain','reason_code':reason}})
            self.assertEqual(ctx.scrub('opaquealias@example.invalid','Email','filename'),'opaquealias@example.invalid')
            self.assertEqual(ctx.safe_report()['applied_review_decisions'][0]['reason_code'],reason)
        for reason in mask_reasons:
            ctx=ScrubContext(review_decisions={'filename':{'action':'mask','spans':[{'start':0,'end':len(PERSON),'category':'human_names'}],'reason_code':reason}})
            self.assertEqual(ctx.scrub(PERSON,'Full Name','filename'),'X'*len(PERSON))
            self.assertEqual(ctx.safe_report()['applied_review_decisions'][0]['reason_code'],reason)
        for location in ['s1.r1.c1','p1.k2','p1.b2.r3.c4','p1.r1','root.k2','root.p3']:
            ctx=ScrubContext(review_decisions={location:{'action':'mask','spans':[{'start':0,'end':len(PERSON),'category':'human_names'}],'reason_code':'explicit_person_name'}})
            self.assertEqual(ctx.scrub(PERSON,'Full Name',location),'X'*len(PERSON))
            self.assertTrue(ctx.removal_location_coverage_complete)

    def test_uncapped_sinks_and_explicit_incomplete_samples(self):
        ctx=ScrubContext(max_locations=1)
        for row in range(1,4):ctx.scrub('opaquealias@example.invalid','Email',f'r{row}.c1')
        self.assertFalse(ctx.safe_report()['review_location_coverage_complete'])
        reviews=[];removals=[];ctx=ScrubContext(max_locations=1,review_location_sink=reviews.append,removal_location_sink=removals.append)
        for row in range(1,4):
            ctx.scrub('opaquealias@example.invalid','Email',f'r{row}.c1')
            ctx.scrub(EMAIL,'Email',f'r{row}.c2')
        self.assertEqual(len(reviews),3);self.assertEqual(len(removals),3)
        self.assertTrue(ctx.safe_report()['review_location_coverage_complete'])
        self.assertTrue(ctx.safe_report()['removal_location_coverage_complete'])
        self.assertTrue(all(set(x)<= {'reason','location','count','resolved'} for x in reviews))
        self.assertNotIn(EMAIL,json.dumps(reviews+removals))

    def test_sink_failure_cannot_silently_drop_coverage(self):
        def broken(_):raise OSError('synthetic sink unavailable')
        with self.assertRaises(OSError):ScrubContext(review_location_sink=broken).scrub('opaquealias@example.invalid','Email','r1.c1')
        with self.assertRaises(OSError):ScrubContext(removal_location_sink=broken).scrub(EMAIL,'Email','r1.c1')

    def test_catalog_costs_source_headers_and_identifiers_remain(self):
        for field,value in [('Service ID','123-45-6789'),('SKU ID','202-555-0147'),('ResourceId','resource-prod-01'),('cost','1,234,567.890'),('Usage unit','gibibyte month')]:
            with self.subTest(field=field):self.assertEqual(assess_value(value,field),(set(),set()))
        self.assertEqual(safe_field_name('user:Project',1),'user:Project')
        self.assertEqual(safe_field_name(EMAIL,1),EMAIL)

if __name__=='__main__':unittest.main()
