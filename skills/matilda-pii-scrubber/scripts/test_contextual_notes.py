"""Fictional operational notes exercising precise masks and context decisions."""
import unittest
from scrub_core import ScrubContext, assess_value
from verify_outputs import _broader_candidate


class ContextualNotes(unittest.TestCase):
    def test_adjacent_contact_labels_do_not_swallow_later_person(self):
        text = 'Name of Server: vm-demo Purpose: File server Point of Contact: Platform Engineering Department Owner: Avery Example OS: Server Edition'
        context = ScrubContext()
        self.assertEqual(context.scrub(text, 'Annotation', 's1.r2.c2'),text.replace('Avery Example','X'*len('Avery Example')))
        self.assertEqual(context.counts['human_names'], 1)
        self.assertEqual(context.changed, 1)

    def test_point_of_contact_person_stops_at_next_technical_field(self):
        text = 'Purpose: proxy Point of Contact: Casey Example Department Owner: IT Infrastructure OS: Server Edition'
        self.assertIn('human_names', assess_value(text, 'Annotation')[0])

    def test_team_contacts_and_department_owners_preserved(self):
        text = 'Purpose: file server Point of Contact: Customer Support Department Owner: Platform Engineering OS: Server Edition'
        self.assertEqual(ScrubContext().scrub(text, 'Annotation', 'r2.c1'), text)

    def test_bare_name_and_date_requires_context_then_masks_only_name(self):
        text = 'NIC disconnected for months. Avery 4/9/24. No issues without this server.'
        categories, review = assess_value(text, 'Annotation')
        self.assertFalse(categories)
        self.assertIn('ambiguous_person_name', review)
        start=text.index('Avery')
        context = ScrubContext(review_decisions={'r2.c1': {'action':'mask', 'spans':[{'start':start,'end':start+5,'category':'human_names'}], 'reason_code':'explicit_person_name'}})
        self.assertEqual(context.scrub(text, 'Annotation', 'r2.c1'),text.replace('Avery','XXXXX'))
        self.assertEqual(context.changed, 1)

    def test_personal_use_notes_require_review_without_guessing(self):
        for field,text in [('VM','vm-demo (Morgan uses for testing database builds)'), ('Annotation','Service account for Jordan to use is print.service.')]:
            categories, reviews = assess_value(text, field)
            self.assertFalse(categories)
            self.assertIn('ambiguous_person_name', reviews)
            self.assertEqual(ScrubContext().scrub(text, field, 'r2.c1'), text)

    def test_product_and_date_notes_are_not_automatically_people(self):
        for text in ('Release 4/9/24. Stable build.', 'Windows uses for testing.', 'Version 4/9/24. Updated configuration.'):
            self.assertFalse(assess_value(text, 'Annotation')[0])
            self.assertEqual(ScrubContext().scrub(text, 'Annotation', 'r2.c1'), text)

    def test_review_counts_name_and_phone_without_double_counting_item(self):
        text = 'Prod database for Demo Jordan Example 202-555-0143'
        name='Jordan Example';phone='202-555-0143'
        context=ScrubContext(review_decisions={'r2.c1':{'action':'mask','spans':[{'start':text.index(name),'end':text.index(name)+len(name),'category':'human_names'},{'start':text.index(phone),'end':text.index(phone)+len(phone),'category':'human_phone_numbers'}],'reason_code':'personal_contact_record'}})
        self.assertEqual(context.scrub(text,'Annotation','r2.c1'),text.replace(name,'X'*len(name)).replace(phone,'X'*len(phone)))
        self.assertEqual(dict(context.counts),{'human_names':1,'human_phone_numbers':1})
        self.assertEqual(context.changed,1)

    def test_independent_scan_catches_operational_attribution_hints(self):
        for text in ('Retired NIC. Avery 4/9/24. No issues.', 'vm-demo (Morgan uses for database testing)', 'Service account for Jordan to use is print.service.'):
            self.assertTrue(_broader_candidate(text,'Annotation'))

    def test_standard_billing_labels_are_not_name_candidates(self):
        self.assertFalse(_broader_candidate('No Upfront','savings_plan_payment_option'))
        self.assertFalse(_broader_candidate('Not Applicable','line_item_operation'))
        self.assertTrue(_broader_candidate('Casey Example','savings_plan_payment_option'))
        self.assertTrue(_broader_candidate('No Upfront casey.example@example.invalid','line_item_operation'))

if __name__ == '__main__':
    unittest.main(verbosity=2)
