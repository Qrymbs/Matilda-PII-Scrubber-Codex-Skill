"""Invented boundary fixtures with independently specified expected results."""
import json
from pathlib import Path
import tempfile
import unittest

from scrub_core import ScrubContext, ScrubError, detect_pii_spans, mask_text
from scrub_documents import _scrub_item


class PersonalScalarBoundaries(unittest.TestCase):
    def assert_mask(self, source, field, expected, category):
        actual, categories, reviews = mask_text(source, field)
        self.assertEqual(actual, expected)
        self.assertEqual(categories, {category})
        self.assertNotIn('pii_span_unresolved', reviews)
        self.assertEqual(len(actual), len(source))

    def test_mixed_name_fields_keep_labels_and_technical_details(self):
        for field in ['ownername', 'fullname', 'firstname', 'author']:
            with self.subTest(field=field):
                self.assert_mask('Contact: Avery Stone; CPU: 4', field,
                                 'Contact: XXXXXXXXXXX; CPU: 4', 'human_names')

    def test_pure_personal_scalars_remain_maskable(self):
        fixtures = [
            ('Avery Stone', 'fullname', 'XXXXXXXXXXX', 'human_names'),
            ('Avery', 'firstname', 'XXXXX', 'human_names'),
            ('Élodie Núñez', 'fullname', 'XXXXXXXXXXXX', 'human_names'),
            ('AB-3456', 'employeeid', 'XXXXXXX', 'human_employee_student_patient_identifiers'),
            ('123-45-6789', 'ssn', 'XXXXXXXXXXX', 'human_government_identifiers'),
            ('202-555-0123', 'phone', 'XXXXXXXXXXXX', 'human_phone_numbers'),
            ('2001-02-03', 'birthdate', 'XXXXXXXXXX', 'human_birth_dates'),
            ('123 Example Street', 'homeaddress', 'XXXXXXXXXXXXXXXXXX', 'human_home_addresses'),
            ('$1234.50', 'salary', 'XXXXXXXX', 'human_personal_financial_data'),
            ('asthma', 'patientdiagnosis', 'XXXXXX', 'human_sensitive_personal_data'),
            ('fakeOnly42!', 'personalpassword', 'XXXXXXXXXXX', 'human_personal_credentials'),
        ]
        for source, field, expected, category in fixtures:
            with self.subTest(field=field):self.assert_mask(source, field, expected, category)

    def test_mixed_credentials_dates_and_phone_preserve_surroundings(self):
        fixtures = [
            ('user password: fakeOnly42!; CPU: 4', 'personalpassword',
             'user password: XXXXXXXXXXX; CPU: 4', 'human_personal_credentials'),
            ('DOB: 2001-02-03; CPU: 4', 'birthdate',
             'DOB: XXXXXXXXXX; CPU: 4', 'human_birth_dates'),
            ('phone: 202-555-0123; CPU: 4', 'phone',
             'phone: XXXXXXXXXXXX; CPU: 4', 'human_phone_numbers'),
        ]
        for source, field, expected, category in fixtures:
            with self.subTest(field=field):self.assert_mask(source, field, expected, category)

    def test_unbounded_mixed_personal_fields_preserved_and_flagged(self):
        fixtures = [
            ('Avery Stone; CPU: 4', 'fullname'),
            ('A123 CPU 4', 'employeeid'),
            ('salary: 1234; CPU: 4', 'salary'),
            ('123 Example Street; CPU: 4', 'homeaddress'),
            ('asthma; CPU: 4', 'patientdiagnosis'),
            ('fakeOnly42!; CPU: 4', 'personalpassword'),
            ('03 February 2001; CPU: 4', 'birthdate'),
        ]
        for source, field in fixtures:
            with self.subTest(field=field):
                actual, categories, reviews = mask_text(source, field)
                self.assertEqual(actual, source)
                self.assertEqual(categories, set())
                self.assertTrue(reviews)

    def test_unicode_and_encoded_mixed_names_exact_boundaries(self):
        self.assert_mask('Contact: Élodie Núñez; CPU: 4', 'fullname',
                         'Contact: XXXXXXXXXXXX; CPU: 4', 'human_names')
        # Encoded source offsets mask the entire representation of each name.
        source = 'Contact%3A%20%C3%89lodie%20N%C3%BA%C3%B1ez%3B%20CPU%3A%204'
        expected = 'Contact%3A%20' + 'X' * 29 + '%3B%20CPU%3A%204'
        self.assert_mask(source, 'fullname', expected, 'human_names')
        source = r'Contact: \u00c9lodie N\u00fa\u00f1ez; CPU: 4'
        expected = 'Contact: ' + 'X' * 27 + '; CPU: 4'
        self.assert_mask(source, 'fullname', expected, 'human_names')

    def test_mixed_embedded_json_and_protected_identifier(self):
        source = '{"fullname":"Contact: Avery Stone; CPU: 4","cost":1.25}'
        self.assert_mask(source, 'tags',
                         '{"fullname":"Contact: XXXXXXXXXXX; CPU: 4","cost":1.25}', 'human_names')
        source = 'Contact: Avery Stone; CPU: 4'
        ctx = ScrubContext()
        self.assertEqual(ctx.scrub(source, 'resource_id', 'r2.c1'), source)
        self.assertIn('protected_identifier_contains_pii', ctx.review_counts)


class CompleteReviewLedger(unittest.TestCase):
    def test_sample_boundary_does_not_change_ledger_counts(self):
        for count in [0, 1, 29, 30, 31, 35, 1001]:
            for resolved in [False, True]:
                with self.subTest(count=count, resolved=resolved):
                    decisions = ({f'l{i}': {'action': 'retain', 'reason_code': 'organization_or_project_label'}
                                  for i in range(1, count+1)} if resolved else {})
                    events = []
                    ctx = ScrubContext(review_decisions=decisions, review_location_sink=events.append)
                    for i in range(1, count+1):
                        self.assertEqual(_scrub_item('Created by Ari', ctx, f'l{i}'), 'Created by Ari')
                    self.assertEqual(len(events), count)
                    self.assertEqual(len({(event['reason'], event['location']) for event in events}), count)
                    self.assertEqual(ctx.review_occurrences, count)
                    self.assertEqual(ctx.resolved_review_occurrences, count if resolved else 0)
                    self.assertEqual(sum(ctx.review_counts.values()), count)
                    self.assertLessEqual(len(ctx.review_locations['ambiguous_person_name']), 30)
                    self.assertTrue(ctx.review_location_coverage_complete)

    def test_multiple_reasons_count_items_once(self):
        events = []
        ctx = ScrubContext(review_location_sink=events.append)
        for _ in range(2):
            ctx.note_review('ambiguous_person_name', 'l1', _resolved=True)
            ctx.note_review('ambiguous_email_identity', 'l1', _resolved=True)
        self.assertEqual(len(events), 2)
        self.assertEqual(ctx.review_occurrences, 1)
        self.assertEqual(ctx.resolved_review_occurrences, 1)
        self.assertEqual(sum(ctx.review_counts.values()), 2)

    def test_conflicting_resolution_fails_closed(self):
        ctx = ScrubContext()
        ctx.note_review('ambiguous_person_name', 'l1', _resolved=False)
        with self.assertRaisesRegex(ScrubError, 'review_event_resolution_conflict'):
            ctx.note_review('ambiguous_person_name', 'l1', _resolved=True)

    def test_full_ledger_clears_finalizer_coverage_after_35_decisions(self):
        from finalize_report import candidate_coverage
        decisions = {f'l{i}': {'action': 'retain', 'reason_code': 'organization_or_project_label'}
                     for i in range(1, 36)}
        events = []
        ctx = ScrubContext(review_decisions=decisions, review_location_sink=events.append)
        for location in decisions:_scrub_item('Created by Ari', ctx, location)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'review.jsonl').write_text(''.join(json.dumps(event)+'\n' for event in events))
            self.assertTrue(candidate_coverage(root,
                            {'context_review': ctx.safe_report(), 'review_location_index': 'review.jsonl'}, decisions))


if __name__ == '__main__':unittest.main()
