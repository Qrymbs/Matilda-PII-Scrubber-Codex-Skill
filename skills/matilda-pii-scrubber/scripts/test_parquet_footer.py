"""Synthetic regression coverage for distinct Parquet metadata representations."""
from __future__ import annotations

import base64
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest

from scrub_core import ScrubContext
import scrub_structured as adapter

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    pa = pq = None


@unittest.skipUnless(pa, 'pyarrow unavailable')
class ParquetFooterPreservation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-parquet-footer-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def source(self, schema_metadata, footer_metadata, embedded=True):
        schema = pa.schema([
            pa.field('resource_id', pa.string(), nullable=False),
            pa.field('cost', pa.decimal128(15, 4), nullable=False),
        ], metadata=schema_metadata)
        table = pa.Table.from_arrays([
            pa.array(['vm-001', 'vm-002']),
            pa.array([Decimal('12.3400'), Decimal('0.0001')], type=schema[1].type),
        ], schema=schema)
        source = self.root / 'original.parquet'
        actual_footer = dict(footer_metadata)
        if embedded:
            actual_footer[b'ARROW:schema'] = base64.b64encode(schema.serialize().to_pybytes())
        with pq.ParquetWriter(source, schema.remove_metadata(), store_schema=False) as writer:
            writer.write_table(table, row_group_size=1)
            if actual_footer:
                writer.add_key_value_metadata(actual_footer)
        return source

    @staticmethod
    def footer(path):
        with pq.ParquetFile(path) as file:
            return {k: v for k, v in (file.metadata.metadata or {}).items()
                    if k != b'ARROW:schema'}

    def scrub(self, source):
        original = source.read_bytes()
        output = self.root / 'masked.parquet'
        events = []
        ctx = ScrubContext(removal_location_sink=events.append)
        metrics = adapter.scrub_parquet(source, output, ctx)
        self.assertEqual(source.read_bytes(), original)
        before, after = pq.read_table(source), pq.read_table(output)
        self.assertEqual(before.schema.names, after.schema.names)
        self.assertEqual(list(before.schema), list(after.schema))
        for i in range(before.num_columns):
            self.assertTrue(before.column(i).equals(after.column(i)))
        return output, metrics, ctx, events

    def test_footer_only_author_and_safe_values_survive_with_divergent_schema(self):
        source = self.source({b'catalog': b'v1'},
                             {b'author': b'Casey Rowan', b'catalog': b'v2',
                              b'safe_annotation': b'preserve-me'})
        source_footer = self.footer(source)
        output, metrics, ctx, events = self.scrub(source)
        self.assertEqual(pq.read_schema(output).metadata, {b'catalog': b'v1'})
        self.assertEqual(self.footer(output), {b'author': b'XXXXXXXXXXX', b'catalog': b'v2',
                                               b'safe_annotation': b'preserve-me'})
        author_location = f'footer.k{list(source_footer).index(b"author") + 1}'
        self.assertEqual([event['location'] for event in events], [author_location])
        self.assertEqual(events[0]['spans'], [{'start': 0, 'end': 11}])
        self.assertEqual(ctx.changed, 1)
        self.assertFalse(metrics['incomplete'])

    def test_schema_only_key_is_not_added_to_physical_footer(self):
        source = self.source({b'catalog': b'v1', b'author': b'Casey Rowan'},
                             {b'safe_annotation': b'preserve-me'})
        output, metrics, ctx, events = self.scrub(source)
        self.assertEqual(self.footer(output), {b'safe_annotation': b'preserve-me'})
        self.assertEqual(pq.read_schema(output).metadata,
                         {b'catalog': b'v1', b'author': b'XXXXXXXXXXX'})
        self.assertEqual([event['location'] for event in events], ['root.k2'])
        self.assertEqual(ctx.changed, 1)
        self.assertFalse(metrics['incomplete'])

    def test_reserved_name_inside_embedded_metadata_is_preserved_and_inspected(self):
        note = b'Contact avery.stone@example.test; keep catalog.'
        source = self.source({b'ARROW:schema': note, b'catalog': b'v1'},
                             {b'catalog': b'v2'})
        output, metrics, ctx, events = self.scrub(source)
        expected = note.replace(b'avery.stone@example.test', b'X' * len(b'avery.stone@example.test'))
        self.assertEqual(pq.read_schema(output).metadata,
                         {b'ARROW:schema': expected, b'catalog': b'v1'})
        self.assertEqual(self.footer(output), {b'catalog': b'v2'})
        self.assertEqual([event['location'] for event in events], ['root.k1'])
        self.assertFalse(metrics['incomplete'])

    def test_duplicate_personal_metadata_has_separate_review_locations(self):
        source = self.source({b'author': b'Casey Rowan'}, {b'author': b'Casey Rowan'})
        output, metrics, ctx, events = self.scrub(source)
        self.assertEqual(pq.read_schema(output).metadata, {b'author': b'XXXXXXXXXXX'})
        self.assertEqual(self.footer(output), {b'author': b'XXXXXXXXXXX'})
        self.assertEqual({event['location'] for event in events}, {'root.k1', 'footer.k1'})
        self.assertEqual(ctx.changed, 2)
        self.assertFalse(metrics['incomplete'])

    def test_absent_embedded_schema_remains_absent(self):
        source = self.source(None, {b'author': b'Casey Rowan', b'catalog': b'v2'}, embedded=False)
        output, metrics, ctx, events = self.scrub(source)
        with pq.ParquetFile(output) as file:
            self.assertNotIn(b'ARROW:schema', file.metadata.metadata)
        self.assertEqual(self.footer(output), {b'author': b'XXXXXXXXXXX', b'catalog': b'v2'})
        self.assertEqual(pq.read_schema(output).metadata,
                         {b'author': b'XXXXXXXXXXX', b'catalog': b'v2'})
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]['location'].startswith('footer.'))
        self.assertEqual(ctx.changed, 1)
        self.assertFalse(metrics['incomplete'])

    def test_opaque_footer_value_is_preserved_and_blocks(self):
        source = self.source({b'catalog': b'v1'}, {b'opaque': b'\xff\x00', b'catalog': b'v2'})
        output, metrics, ctx, events = self.scrub(source)
        self.assertEqual(self.footer(output), self.footer(source))
        self.assertTrue(metrics['incomplete'])
        self.assertIn('retained_binary_parquet_content_uninspected', ctx.warnings)
        self.assertEqual(events, [])

    def test_protected_footer_identifier_is_preserved_with_conflict(self):
        identifier = b'arn:aws:iam::123456789012:user/avery.stone@example.test'
        source = self.source(None, {b'resource_id': identifier})
        output, metrics, ctx, events = self.scrub(source)
        self.assertEqual(self.footer(output), {b'resource_id': identifier})
        self.assertGreater(ctx.review_counts['protected_identifier_contains_pii'], 0)
        self.assertEqual(events, [])


if __name__ == '__main__':
    unittest.main()
