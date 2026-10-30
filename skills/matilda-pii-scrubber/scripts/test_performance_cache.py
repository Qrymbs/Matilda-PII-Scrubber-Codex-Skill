"""Synthetic tests: memoization cannot cache integrity or review decisions."""
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import csv
import json
import tempfile
import unittest

import verify_outputs as verify


class PureClassificationCache(unittest.TestCase):
    def check(self, decisions=None):
        return verify.ArtifactComparison(
            SimpleNamespace(max_depth=12), {'output_format': 'csv'}, decisions or {})

    def test_repeated_csv_cells_classified_once_but_late_mutation_detected(self):
        with tempfile.TemporaryDirectory(prefix='classification-cache-test-') as folder:
            source, output = Path(folder)/'source.csv', Path(folder)/'output.csv'
            rows = [['cost', 'service']] + [['1.20', 'compute-service'] for _ in range(250)]
            for path in (source, output):
                with path.open('w', newline='') as stream:
                    csv.writer(stream).writerows(rows)
            check = self.check()
            with mock.patch.object(verify, 'assess_value', wraps=verify.assess_value) as assess, \
                 mock.patch.object(verify, '_broader_candidate', wraps=verify._broader_candidate) as broader:
                check.csv(source, output)
            self.assertTrue(check.comparison_ok, check.result)
            self.assertEqual(check.result['source_values_compared'], 502)
            self.assertEqual(check.result['values_checked'], 502)
            self.assertEqual(assess.call_count, 4)
            self.assertEqual(broader.call_count, 4)
            rows[-1][0] = '1.21'
            with output.open('w', newline='') as stream:
                csv.writer(stream).writerows(rows)
            check = self.check()
            check.csv(source, output)
            self.assertEqual(check.result['source_values_compared'], 502)
            self.assertIn('retained_source_value_changed', check.result['errors'])

    def test_later_coordinate_retain_does_not_resolve_other_repetitions(self):
        choice = {'action': 'retain', 'reason_code': 'organization_or_project_label'}
        check = self.check({'r3.c1': choice})
        with mock.patch.object(verify, 'assess_value', wraps=verify.assess_value) as assess, \
             mock.patch.object(verify, '_broader_candidate', wraps=verify._broader_candidate) as broader:
            for row in range(2, 5):
                check.pair('Casey Rowan', 'Casey Rowan', 'misc', f'r{row}.c1')
        self.assertEqual(assess.call_count, 1)
        self.assertEqual(broader.call_count, 1)
        self.assertEqual(check.result['independent_candidates'], 3)
        self.assertEqual(check.result['unresolved_candidate_count'], 2)
        self.assertEqual(check.result['unresolved_candidate_locations'], ['r2.c1', 'r4.c1'])
        self.assertEqual(check.used, {'r3.c1'})

    def test_later_mask_decision_and_each_span_event_are_honored(self):
        clear = {'action': 'mask', 'spans': [{'start': 0, 'end': 11, 'category':'human_names'}],
                 'reason_code': 'explicit_person_name'}
        check = self.check({'r3.c1': clear})
        check.pair('Casey Rowan', 'Casey Rowan', 'misc', 'r2.c1')
        check.pair('Casey Rowan', 'X'*11, 'misc', 'r3.c1')
        self.assertEqual(check.actions, 1)
        self.assertEqual(check.events, {('r3.c1', 'human_names'): 1})
        self.assertEqual(check.used, {'r3.c1'})
        check = self.check({'r3.c1': clear})
        check.pair('Casey Rowan', 'Casey Rowan', 'misc', 'r2.c1')
        check.pair('Casey Rowan', 'Casey Rowan', 'misc', 'r3.c1')
        self.assertIn('review_mask_decision_not_applied', check.result['errors'])
        check = self.check()
        with mock.patch.object(verify, 'mask_text', wraps=verify.mask_text) as masking:
            for row in range(2, 52):
                source = 'casey.rowan@example.invalid'
                check.recorded_spans[f'r{row}.c1']=[{'start':0,'end':len(source),'category':'human_email_addresses'}]
                check.pair(source, 'X'*len(source), 'email', f'r{row}.c1')
        self.assertEqual(masking.call_count, 0)
        self.assertFalse(check.result['semantic_mask_review_passed'])
        self.assertEqual(check.result['unreviewed_mask_items'],50)
        self.assertEqual(check.actions, 50)
        self.assertEqual(len(check.events), 50)
        self.assertEqual(check.events[('r51.c1', 'human_email_addresses')], 1)

    def test_field_prose_and_type_context_do_not_share_classifications(self):
        check = self.check()
        with mock.patch.object(verify, 'assess_value', wraps=verify.assess_value) as assess:
            self.assertFalse(check.categories('Casey Rowan', 'misc')[0])
            self.assertIn('human_names', check.categories('Casey Rowan', 'person_name')[0])
            check.categories('cost: 1.20', 'free_text', prose=False)
            check.categories('cost: 1.20', 'free_text', prose=True)
            check.categories('1', 'cost')
            check.categories(1, 'cost')
            check.categories(True, 'cost')
        self.assertEqual(assess.call_count, 8)

    def test_cache_is_bounded_and_never_serialized_into_results(self):
        check = self.check()
        with mock.patch.object(verify, '_TEXT_CACHE_MAX_ENTRIES', 3), \
             mock.patch.object(verify, '_TEXT_CACHE_MAX_CHARACTERS', 30):
            for number in range(20):
                check.categories(str(number), 'cost')
                self.assertLessEqual(len(check._text_assessments), 3)
                self.assertLessEqual(check._text_assessment_characters, 30)
        check.categories('x' * (verify._TEXT_CACHE_MAX_ITEM_CHARACTERS + 1), 'misc')
        self.assertLessEqual(len(check._text_assessments), 3)
        self.assertNotIn('text_assessments', json.dumps(check.result))
        self.assertNotIn('compute-service', json.dumps(check.result))


if __name__ == '__main__':
    unittest.main(verbosity=2)
