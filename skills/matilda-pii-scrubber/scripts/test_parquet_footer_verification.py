"""Independent Parquet footer preservation and release-gate regressions.

All names and data are synthetic, live only in temporary fixtures, and expected
mask decisions are authored from the fixture rather than copied from its ledger.
"""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from review_support import COVERAGE_FIELDS
from verify_outputs import verify_directory

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    pa = pq = None

SCRIPTS = Path(__file__).parent
PERSON = b'Casey Rowan'


@unittest.skipUnless(pa is not None, 'pyarrow unavailable')
class ParquetFooterVerification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='parquet-footer-verification-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def source(self, name='billing.parquet', schema_metadata=None, footer=None, store_schema=True):
        path = self.root / name
        schema = pa.schema([
            pa.field('resource_id', pa.string(), nullable=False),
            pa.field('cost', pa.int64(), nullable=False),
        ], metadata=schema_metadata if schema_metadata is not None else {b'catalog': b'v1'})
        table = pa.Table.from_pylist([{'resource_id': 'vm-001', 'cost': 42}], schema=schema)
        with pq.ParquetWriter(path, schema, store_schema=store_schema) as writer:
            writer.write_table(table)
            writer.add_key_value_metadata(footer if footer is not None else {
                b'catalog': b'v2', b'safe_annotation': b'preserve-me', b'author': PERSON,
            })
        return path

    def metadata(self, path):
        with pq.ParquetFile(path) as file:
            schema = dict(file.schema_arrow.metadata or {})
            footer = {key: value for key, value in file.metadata.metadata.items()
                      if key != b'ARROW:schema'}
        return schema, footer

    def decisions(self, source, authors):
        schema, footer = self.metadata(source)
        choices = {}
        for prefix, mapping in [('root', schema), ('footer', footer)]:
            for index, (key, value) in enumerate(mapping.items(), 1):
                if (prefix, key) in authors:
                    expected = authors[(prefix, key)]
                    self.assertEqual(value, expected)
                    choices[f'{prefix}.k{index}'] = {
                        'action': 'mask', 'reason_code': 'explicit_person_name',
                        'spans': [{'start': 0, 'end': len(expected.decode('utf-8')),
                                   'category': 'human_names'}],
                    }
        self.assertEqual(len(choices), len(authors))
        return choices

    def scrub(self, source):
        out = self.root / ('run-' + str(len(list(self.root.glob('run-*')))))
        proc = subprocess.run([sys.executable, str(SCRIPTS/'scrub.py'), str(source),
                               '--output-dir', str(out)], capture_output=True, text=True)
        self.assertIn(proc.returncode, (0, 2), proc.stdout + proc.stderr)
        report = json.loads((out/'scrub-report.json').read_text())
        self.assertIsNotNone(report['files'][0]['artifact'], report)
        return out, report

    def finalize(self, out, source, choices=None):
        report = json.loads((out/'scrub-report.json').read_text())
        evidence = {'version': 2, 'run_id': report['run_id'], 'files': {'file0001': {
            **{field: True for field in COVERAGE_FIELDS},
            'unresolved_items': 0, 'decisions': choices or {},
        }}}
        proof = out/'review-evidence.json'
        proof.write_text(json.dumps(evidence))
        proc = subprocess.run([sys.executable, str(SCRIPTS/'finalize_report.py'),
                               str(out/'scrub-report.json'), '--review-evidence', str(proof),
                               '--source', 'file0001=' + str(source)],
                              capture_output=True, text=True)
        return proc, json.loads((out/'scrub-report.json').read_text())['files'][0]

    def check(self, out, source, choices):
        return verify_directory(out, sources={'file0001': source},
                                review_decisions={'file0001': choices})['files']['file0001']

    def rewrite(self, artifact, footer_change=None, schema_change=None, store_schema=True):
        table = pq.read_table(artifact)
        _, footer = self.metadata(artifact)
        if footer_change:
            footer_change(footer)
        if schema_change:
            metadata = dict(table.schema.metadata or {})
            schema_change(metadata)
            table = table.replace_schema_metadata(metadata)
        with pq.ParquetWriter(artifact, table.schema, store_schema=store_schema) as writer:
            writer.write_table(table)
            writer.add_key_value_metadata(footer)

    def test_footer_only_author_is_reviewed_and_both_metadata_views_preserved(self):
        source = self.source()
        original = source.read_bytes()
        self.assertEqual(self.metadata(source), (
            {b'catalog': b'v1'},
            {b'catalog': b'v2', b'safe_annotation': b'preserve-me', b'author': PERSON},
        ))
        choices = self.decisions(source, {('footer', b'author'): PERSON})
        out, report = self.scrub(source)
        artifact = out/report['files'][0]['artifact']
        self.assertEqual(self.metadata(artifact), (
            {b'catalog': b'v1'},
            {b'catalog': b'v2', b'safe_annotation': b'preserve-me', b'author': b'X'*11},
        ))
        self.assertEqual(pq.read_table(artifact).to_pydict(),
                         {'resource_id': ['vm-001'], 'cost': [42]})
        events = [json.loads(line) for line in
                  (out/report['files'][0]['removal_location_index']).read_text().splitlines()]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['location'], next(iter(choices)))
        self.assertEqual(events[0]['spans'], [{'start': 0, 'end': 11}])
        proc, final = self.finalize(out, source, choices)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(final['submission_status'], 'ready_for_manual_submission')
        self.assertTrue(final['verification']['source_comparison_passed'])
        self.assertTrue(final['verification']['semantic_mask_review_passed'])
        self.assertEqual(source.read_bytes(), original)

    def test_footer_mask_cannot_be_ready_without_exact_review_decision(self):
        source = self.source()
        out, _ = self.scrub(source)
        proc, final = self.finalize(out, source)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(final['submission_status'], 'blocked')
        self.assertFalse(final['verification']['semantic_mask_review_passed'])

    def test_without_embedded_arrow_schema_one_physical_author_needs_one_review(self):
        source = self.source(store_schema=False)
        original = source.read_bytes()
        with pq.ParquetFile(source) as file:
            self.assertNotIn(b'ARROW:schema', file.metadata.metadata)
        choices = self.decisions(source, {('footer', b'author'): PERSON})
        out, report = self.scrub(source)
        artifact = out/report['files'][0]['artifact']
        expected = {b'catalog': b'v2', b'safe_annotation': b'preserve-me', b'author': b'X'*11}
        self.assertEqual(self.metadata(artifact), (expected, expected))
        with pq.ParquetFile(artifact) as file:
            self.assertNotIn(b'ARROW:schema', file.metadata.metadata)
        events = [json.loads(line) for line in
                  (out/report['files'][0]['removal_location_index']).read_text().splitlines()]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['location'], next(iter(choices)))
        proc, final = self.finalize(out, source, choices)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(final['submission_status'], 'ready_for_manual_submission')
        self.assertEqual(source.read_bytes(), original)

    def test_changed_deleted_and_added_footer_metadata_are_rejected(self):
        source = self.source()
        choices = self.decisions(source, {('footer', b'author'): PERSON})
        mutations = {
            'changed': lambda metadata: metadata.__setitem__(b'catalog', b'v9'),
            'deleted': lambda metadata: metadata.pop(b'safe_annotation'),
            'added': lambda metadata: metadata.__setitem__(b'extra_annotation', b'not-in-source'),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                out, report = self.scrub(source)
                self.assertTrue(self.check(out, source, choices)['source_comparison_passed'])
                self.rewrite(out/report['files'][0]['artifact'], footer_change=mutate)
                result = self.check(out, source, choices)
                self.assertFalse(result['source_comparison_passed'], result)
                proc, final = self.finalize(out, source, choices)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertEqual(final['submission_status'], 'blocked')

    def test_schema_metadata_change_is_rejected_when_footer_stays_exact(self):
        source = self.source()
        choices = self.decisions(source, {('footer', b'author'): PERSON})
        out, report = self.scrub(source)
        artifact = out/report['files'][0]['artifact']
        footer_before = self.metadata(artifact)[1]
        self.rewrite(artifact, schema_change=lambda metadata: metadata.__setitem__(b'catalog', b'v9'))
        self.assertEqual(self.metadata(artifact)[1], footer_before)
        self.assertFalse(self.check(out, source, choices)['source_comparison_passed'])

    def test_adding_or_removing_embedded_arrow_schema_is_rejected(self):
        for stored in (True, False):
            with self.subTest(source_embeds_schema=stored):
                source = self.source(name=f'billing-{stored}.parquet', store_schema=stored)
                choices = self.decisions(source, {('footer', b'author'): PERSON})
                out, report = self.scrub(source)
                self.assertTrue(self.check(out, source, choices)['source_comparison_passed'])
                artifact = out/report['files'][0]['artifact']
                footer_before = self.metadata(artifact)[1]
                self.rewrite(artifact, store_schema=not stored)
                self.assertEqual(self.metadata(artifact)[1], footer_before)
                with pq.ParquetFile(artifact) as file:
                    self.assertEqual(b'ARROW:schema' in file.metadata.metadata, not stored)
                self.assertFalse(self.check(out, source, choices)['source_comparison_passed'])

    def test_reserved_spelling_inside_schema_or_field_metadata_cannot_change(self):
        def write_valid_envelope(path, table, footer):
            metadata = dict(footer)
            metadata[b'ARROW:schema'] = base64.b64encode(table.schema.serialize().to_pybytes())
            with pq.ParquetWriter(path, table.schema.remove_metadata(), store_schema=False) as writer:
                writer.write_table(table)
                writer.add_key_value_metadata(metadata)

        source = self.root/'inner-metadata.parquet'
        schema = pa.schema([
            pa.field('resource_id', pa.string(), nullable=False,
                     metadata={b'ARROW:schema': b'keep-field-attribute'}),
            pa.field('cost', pa.int64(), nullable=False),
        ], metadata={b'catalog': b'v1', b'ARROW:schema': b'keep-root-attribute'})
        table = pa.Table.from_pylist([{'resource_id': 'vm-001', 'cost': 42}], schema=schema)
        write_valid_envelope(source, table, {b'catalog': b'v2', b'author': PERSON})
        choices = self.decisions(source, {('footer', b'author'): PERSON})
        for location in ('schema', 'field'):
            with self.subTest(location=location):
                out, report = self.scrub(source)
                self.assertTrue(self.check(out, source, choices)['source_comparison_passed'])
                artifact = out/report['files'][0]['artifact']
                before_schema, footer = self.metadata(artifact)
                self.assertEqual(before_schema[b'ARROW:schema'], b'keep-root-attribute')
                self.assertEqual(pq.read_schema(artifact).field(0).metadata[b'ARROW:schema'],
                                 b'keep-field-attribute')
                table = pq.read_table(artifact)
                if location == 'schema':
                    metadata = dict(table.schema.metadata)
                    metadata[b'ARROW:schema'] = b'changed-root-attribute'
                    altered = table.replace_schema_metadata(metadata)
                else:
                    fields = list(table.schema)
                    fields[0] = fields[0].with_metadata({b'ARROW:schema': b'changed-field-attribute'})
                    altered = pa.Table.from_arrays(table.columns,
                        schema=pa.schema(fields, metadata=table.schema.metadata))
                write_valid_envelope(artifact, altered, footer)
                self.assertEqual(self.metadata(artifact)[1], footer)
                self.assertFalse(self.check(out, source, choices)['source_comparison_passed'])

    def test_distinct_schema_and_footer_authors_require_two_exact_reviews(self):
        schema_author, footer_author = PERSON, b'Jordan Ellis'
        source = self.source(schema_metadata={b'catalog': b'v1', b'author': schema_author},
                             footer={b'catalog': b'v2', b'author': footer_author})
        choices = self.decisions(source, {('root', b'author'): schema_author,
                                          ('footer', b'author'): footer_author})
        out, report = self.scrub(source)
        schema, footer = self.metadata(out/report['files'][0]['artifact'])
        self.assertEqual(schema[b'author'], b'X'*11)
        self.assertEqual(footer[b'author'], b'X'*12)
        one_review = {key: value for key, value in choices.items() if key.startswith('root.')}
        proc, final = self.finalize(out, source, one_review)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertFalse(final['verification']['semantic_mask_review_passed'])
        proc, final = self.finalize(out, source, choices)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(final['submission_status'], 'ready_for_manual_submission')

    def test_opaque_footer_is_preserved_and_blocks_release(self):
        source = self.source(footer={b'catalog': b'v2', b'opaque': b'\xff\x00'})
        original = source.read_bytes()
        out, report = self.scrub(source)
        self.assertEqual(self.metadata(out/report['files'][0]['artifact'])[1][b'opaque'], b'\xff\x00')
        proc, final = self.finalize(out, source)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(final['submission_status'], 'blocked')
        self.assertFalse(final['verification']['independent_candidate_scan_passed'])
        self.assertEqual(source.read_bytes(), original)

    def test_personal_email_in_protected_footer_identifier_is_retained_and_blocked(self):
        resource = b'arn:aws:iam::123456789012:user/casey.rowan@example.invalid'
        source = self.source(footer={b'catalog': b'v2', b'resource_id': resource})
        out, report = self.scrub(source)
        self.assertEqual(self.metadata(out/report['files'][0]['artifact'])[1][b'resource_id'], resource)
        proc, final = self.finalize(out, source)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(final['submission_status'], 'blocked')
        self.assertFalse(final['verification']['policy_scan_passed'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
