"""Synthetic boundary regressions for exact source-character masking."""
import unittest
from urllib.parse import quote
from scrub_core import ScrubContext, ScrubError, mask_text
from review_support import validate_decisions

class XMaskSourceBoundaries(unittest.TestCase):
    def test_fully_percent_encoded_note_preserves_outside_email(self):
        encode=lambda text:''.join('%%%02X'%b for b in text.encode())
        before='Contact: ';pii='avery.stone@example.invalid';after='; CPU: 4'
        source=encode(before+pii+after)
        actual,categories,reviews=mask_text(source,'description')
        self.assertEqual(actual,encode(before)+'X'*len(encode(pii))+encode(after))
        self.assertEqual(categories,{'human_email_addresses'})
        self.assertFalse(reviews)
    def test_unicode_escape_boundaries_do_not_mask_preceding_space(self):
        source=r'Contact:\u0020\u0061very.stone@example.invalid; CPU: 4'
        actual,_,_=mask_text(source,'description')
        start=source.index(r'\u0061');end=source.index(';')
        self.assertEqual(actual,source[:start]+'X'*(end-start)+source[end:])
    def test_protected_nested_person_record_kept_and_blocked(self):
        source={'resource_id':{'full_name':'Avery Stone','email':'avery.stone@example.invalid'}}
        events=[];ctx=ScrubContext(review_location_sink=events.append)
        self.assertEqual(ctx.scrub(source),source)
        self.assertEqual(ctx.changed,0)
        self.assertIn('protected_identifier_contains_pii',ctx.review_counts)
        self.assertEqual(len({(e['reason'],e['location']) for e in events}),len(events))
    def test_embedded_protected_person_record_kept_and_blocked(self):
        source='{"resource_id":{"full_name":"Avery Stone"},"cost":4}'
        ctx=ScrubContext();self.assertEqual(ctx.scrub(source,'tags','r2.c1'),source)
        self.assertIn('protected_identifier_contains_pii',ctx.review_counts)
    def test_container_retention_cannot_hide_human_children(self):
        ctx=ScrubContext(review_decisions={'root':{'action':'retain','reason_code':'machine_identity'}})
        with self.assertRaises(ScrubError):ctx.scrub({'email':'avery.stone@example.invalid'},location='root')
    def test_namespaced_resource_names_remain_exact(self):
        for field in ("tags/DatabaseName","resource_tags:VirtualMachineUUID","resourceTags:resource_guid"):
            ctx=ScrubContext();source="avery.stone@example.invalid"
            self.assertEqual(ctx.scrub(source,field,"r2.c1"),source)
            self.assertIn("protected_identifier_contains_pii",ctx.review_counts)
    def test_residual_decision_is_narrow_and_value_free(self):
        valid={'r2.c1':{'action':'mask','reason_code':'named_person_email','spans':[{'start':2,'end':28,'category':'human_email_addresses'}],'residual_reason_code':'shared_organizational_mailbox'}}
        self.assertEqual(validate_decisions(valid)['r2.c1']['residual_reason_code'],'shared_organizational_mailbox')
        valid['r2.c1']['residual_reason_code']='explicit_person_name'
        with self.assertRaises(ScrubError):validate_decisions(valid)

if __name__=='__main__':unittest.main()
