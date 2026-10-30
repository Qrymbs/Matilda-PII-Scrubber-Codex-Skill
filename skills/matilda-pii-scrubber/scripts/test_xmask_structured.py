"""Synthetic span-masking and structural-integrity checks for structured files."""
from __future__ import annotations
import csv
from datetime import date
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest

from scrub_core import ScrubContext, ScrubError
import scrub_structured as adapter

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    pa = pq = None


EMAIL = 'avery.stone@example.test'
MASKED_EMAIL = 'X' * len(EMAIL)


class StructuredXMask(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-xmask-structured-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_csv_surroundings_unicode_and_multiple_occurrences(self):
        source, output = self.root/'source.csv', self.root/'masked.csv'
        note = f'🔧 Call {EMAIL}; keep cost=12.30 and resource=vm-001. Contact {EMAIL}.'
        with source.open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['notes', 'cost', 'resource_id'])
            writer.writerow([note, '00012.3000', 'vm-001'])
        original = source.read_bytes()
        events = []
        ctx = ScrubContext(removal_location_sink=events.append)
        adapter.scrub_csv(source, output, ctx)
        with output.open(newline='') as stream:
            result = list(csv.reader(stream))
        self.assertEqual(result, [['notes', 'cost', 'resource_id'],
                                  [note.replace(EMAIL, MASKED_EMAIL), '00012.3000', 'vm-001']])
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(len(result[1][0]), len(note))
        self.assertEqual({item['location'] for item in events}, {'r2.c1'})
        self.assertEqual(sum(item['masked_characters'] for item in events), len(EMAIL)*2)

    def test_csv_explicit_unicode_codepoint_spans_keep_punctuation(self):
        source, output = self.root/'unicode.csv', self.root/'masked.csv'
        note = '🔧 Person=Zoë 李; machine=vm-007'
        start = note.index('Zoë 李')
        with source.open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['notes'])
            writer.writerow([note])
        ctx = ScrubContext(review_decisions={'r2.c1': {'action':'mask', 'reason_code':'explicit_person_name', 'spans':[
            {'start':start, 'end':start+len('Zoë 李'), 'category':'human_names'}]}})
        adapter.scrub_csv(source, output, ctx)
        with output.open(newline='') as stream:
            value = list(csv.reader(stream))[1][0]
        self.assertEqual(value, '🔧 Person=XXXXX; machine=vm-007')
        self.assertEqual(len(value), len(note))

    def test_csv_protected_identifiers_and_schema_labels_are_exact(self):
        source, output = self.root/'protected.csv', self.root/'masked.csv'
        resource = f'arn:aws:iam::123456789012:user/{EMAIL}'
        with source.open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['resource_id', EMAIL, 'notes'])
            writer.writerow([resource, 'nonpersonal', f'Contact {EMAIL}; cost remains.'])
        ctx = ScrubContext()
        adapter.scrub_csv(source, output, ctx)
        with output.open(newline='') as stream:
            result = list(csv.reader(stream))
        self.assertEqual(result[0], ['resource_id', EMAIL, 'notes'])
        self.assertEqual(result[1], [resource, 'nonpersonal', f'Contact {MASKED_EMAIL}; cost remains.'])
        self.assertGreater(ctx.review_counts['protected_identifier_contains_pii'], 0)
        self.assertGreater(ctx.review_counts['schema_label_contains_pii'], 0)

    def test_csv_manual_identifier_mask_is_blocked_without_output(self):
        source, output = self.root/'protected.csv', self.root/'masked.csv'
        source.write_text('resource_id\nvm-001\n')
        original = source.read_bytes()
        ctx = ScrubContext(review_decisions={'r2.c1': {'action':'mask', 'reason_code':'explicit_person_identifier', 'spans':[
            {'start':0, 'end':6, 'category':'human_usernames'}]}})
        with self.assertRaises(ScrubError) as caught:
            adapter.scrub_csv(source, output, ctx)
        self.assertEqual(caught.exception.code, "protected_identifier_mask_forbidden")
        self.assertFalse(output.exists())
        self.assertEqual(source.read_bytes(), original)

    def test_json_recurses_preserving_keys_container_and_precise_numbers(self):
        source, output = self.root/'source.json', self.root/'masked.json'
        source.write_text('{"person":{"name":"Avery Stone","employee_id":42},'
                          '"resource_id":"vm-001", "cost":12.1234567890123456789,'
                          '"notes":"Contact '+EMAIL+'; keep this text.","'+EMAIL+'":"safe"}')
        ctx = ScrubContext()
        adapter.scrub_json(source, output, ctx)
        before = json.loads(source.read_text(), parse_float=Decimal)
        after = json.loads(output.read_text(), parse_float=Decimal)
        self.assertEqual(list(after), list(before))
        self.assertEqual(after['person'], {'name':'X'*len('Avery Stone'), 'employee_id':42})
        self.assertEqual(after['cost'], before['cost'])
        self.assertEqual(after['resource_id'], before['resource_id'])
        self.assertEqual(after[EMAIL], 'safe')
        self.assertEqual(after['notes'], f'Contact {MASKED_EMAIL}; keep this text.')
        self.assertEqual(ctx.review_counts['type_masking_conflict'], 1)
        self.assertGreater(ctx.review_counts['schema_label_contains_pii'], 0)

    def test_jsonl_record_coordinates_and_blank_lines(self):
        source, output = self.root/'source.jsonl', self.root/'masked.jsonl'
        source.write_text(json.dumps({'notes':EMAIL})+'\n\n'+json.dumps({'notes':EMAIL})+'\n')
        events = []
        ctx = ScrubContext(removal_location_sink=events.append)
        metrics = adapter.scrub_json(source, output, ctx, jsonl=True)
        self.assertEqual(metrics['records'], 2)
        self.assertEqual(output.read_text().splitlines()[1], '')
        self.assertEqual([item['location'] for item in events], ['r1.k1', 'r2.k1'])

    @unittest.skipUnless(pa, 'pyarrow unavailable')
    def test_parquet_metadata_types_order_schema_and_source_preserved(self):
        source, output = self.root/'source.parquet', self.root/'masked.parquet'
        metadata = {b'format_version':b'0007', b'notes':f'Contact {EMAIL}; keep metadata.'.encode(), b'opaque':b'\xff\x00'}
        field_metadata = {b'unit':b'USD', b'owner':b'Avery Stone'}
        schema = pa.schema([pa.field('notes', pa.large_string(), nullable=False, metadata=field_metadata),
                            pa.field('cost', pa.decimal128(30, 20), nullable=False),
                            pa.field('resource_id', pa.string(), nullable=False)], metadata=metadata)
        table = pa.Table.from_arrays([pa.array([f'Contact {EMAIL}; active.', 'ordinary'], type=pa.large_string()),
                    pa.array([Decimal('12.12345678901234567890'), Decimal('0.00000000000000000001')], type=schema[1].type),
                    pa.array(['vm-001', f'/resource/{EMAIL}'])], schema=schema)
        pq.write_table(table, source)
        original = source.read_bytes()
        ctx = ScrubContext()
        metrics = adapter.scrub_parquet(source, output, ctx)
        before, after = pq.read_table(source), pq.read_table(output)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(after.schema.names, before.schema.names)
        self.assertEqual([f.nullable for f in after.schema], [f.nullable for f in before.schema])
        self.assertEqual([f.type for f in after.schema], [f.type for f in before.schema])
        self.assertTrue(after.column('cost').equals(before.column('cost')))
        self.assertTrue(after.column('resource_id').equals(before.column('resource_id')))
        self.assertEqual(after.column('notes').to_pylist(), [f'Contact {MASKED_EMAIL}; active.', 'ordinary'])
        self.assertEqual(after.schema.metadata[b'format_version'], b'0007')
        self.assertEqual(after.schema.metadata[b'opaque'], b'\xff\x00')
        self.assertEqual(after.schema.metadata[b'notes'], f'Contact {MASKED_EMAIL}; keep metadata.'.encode())
        self.assertEqual(after.schema[0].metadata, {b'unit':b'USD', b'owner':b'X'*len('Avery Stone')})
        self.assertEqual(metrics['actual_nullable_fields_changed'], 0)
        self.assertFalse(metrics['join_keys_removed'])

    @unittest.skipUnless(pa, 'pyarrow unavailable')
    def test_parquet_native_person_dates_numbers_and_binary_block_without_coercion(self):
        source, output = self.root/'typed.parquet', self.root/'masked.parquet'
        schema = pa.schema([pa.field('employee_id', pa.int64(), nullable=False),
                            pa.field('birth_date', pa.date32(), nullable=False),
                            pa.field('notes', pa.binary(), nullable=False)])
        table = pa.Table.from_arrays([pa.array([42]), pa.array([date(1990,1,2)], type=pa.date32()),
                                     pa.array([EMAIL.encode()])], schema=schema)
        pq.write_table(table, source)
        ctx = ScrubContext()
        adapter.scrub_parquet(source, output, ctx)
        after = pq.read_table(output)
        self.assertTrue(after.equals(table, check_metadata=True))
        self.assertEqual(ctx.review_counts['type_masking_conflict'], 3)
        self.assertEqual(ctx.changed, 0)

    @unittest.skipUnless(pa, 'pyarrow unavailable')
    def test_parquet_nested_metadata_and_person_containers(self):
        source, output = self.root/'nested.parquet', self.root/'masked.parquet'
        item = pa.struct([pa.field('name', pa.string(), metadata={b'notes':EMAIL.encode()}),
                          pa.field('cost', pa.decimal128(12, 4), nullable=False)])
        typ = pa.list_(pa.field('item', item, metadata={b'units':b'unchanged'}))
        table = pa.table({'contact':pa.array([[{'name':'Avery Stone', 'cost':Decimal('12.3000')}], None, []], type=typ)})
        pq.write_table(table, source)
        ctx = ScrubContext()
        adapter.scrub_parquet(source, output, ctx)
        before, after = pq.read_table(source), pq.read_table(output)
        self.assertEqual(after.column(0).to_pylist(), [[{'name':'X'*len('Avery Stone'), 'cost':Decimal('12.3000')}], None, []])
        self.assertEqual(after.schema[0].type.value_field.metadata, before.schema[0].type.value_field.metadata)
        self.assertEqual(after.schema[0].type.value_type[0].metadata, {b'notes':MASKED_EMAIL.encode()})
        self.assertEqual(after.schema[0].type.value_type[1], before.schema[0].type.value_type[1])

    @unittest.skipUnless(pa, 'pyarrow unavailable')
    def test_parquet_map_keys_preserved_and_all_occurrence_coordinates(self):
        source, output = self.root/'maps.parquet', self.root/'masked.parquet'
        value = [[(EMAIL, 'ordinary'), ('contact', EMAIL)], [('contact', EMAIL)], []]
        table = pa.table({'tags':pa.array(value, type=pa.map_(pa.string(), pa.string()))})
        pq.write_table(table, source, row_group_size=1)
        events, reviews = [], []
        ctx = ScrubContext(removal_location_sink=events.append, review_location_sink=reviews.append)
        adapter.scrub_parquet(source, output, ctx)
        self.assertEqual(pq.read_table(output).column(0).to_pylist(),
                         [[(EMAIL,'ordinary'),('contact',MASKED_EMAIL)],[('contact',MASKED_EMAIL)],[]])
        self.assertEqual([item['location'] for item in events], ['r1.c1.k2', 'r2.c1.k1'])
        self.assertTrue(any(item['reason']=='schema_label_contains_pii' and item['location']=='r1.c1.k1.k1' for item in reviews))

    @unittest.skipUnless(pa, 'pyarrow unavailable')
    def test_parquet_protected_containers_keep_child_person_evidence(self):
        source, output = self.root/'protected_nested.parquet', self.root/'masked.parquet'
        table = pa.table({'resource_id':pa.array([{'full_name':'Avery Stone','employee_id':42,'cost':12.30}]),
                          'resource_path':pa.array([[[('full_name','Avery Stone')]]],
                              type=pa.list_(pa.map_(pa.string(),pa.string())))})
        pq.write_table(table, source)
        reviews = []
        ctx = ScrubContext(review_location_sink=reviews.append,
                review_decisions={'r1.c1.k1':{'action':'retain','reason_code':'billing_or_infrastructure_value'}})
        adapter.scrub_parquet(source, output, ctx)
        self.assertTrue(pq.read_table(output).equals(pq.read_table(source), check_metadata=True))
        self.assertEqual(ctx.changed, 0)
        flagged = {item['location'] for item in reviews if item['reason']=='protected_identifier_contains_pii' and not item['resolved']}
        self.assertEqual(flagged, {'r1.c1.k1','r1.c1.k2','r1.c2.i1.k1'})

    @unittest.skipUnless(pa, 'pyarrow unavailable')
    def test_arrow_slices_nested_fixed_lists_and_dictionary_preserve_types(self):
        typ = pa.list_(pa.string(), 2)
        values = pa.array([['ordinary', 'one'], [EMAIL, 'unchanged'], [None, EMAIL]], type=typ).slice(1)
        events = []
        ctx = ScrubContext(removal_location_sink=events.append)
        result = adapter.ArrowPolicy(ctx).process(values, 'notes', lambda i:f'r{i+1}.c1')
        self.assertEqual(result.type, typ)
        self.assertEqual(result.to_pylist(), [[MASKED_EMAIL,'unchanged'],[None,MASKED_EMAIL]])
        self.assertEqual([item['location'] for item in events], ['r1.c1.i1','r2.c1.i2'])
        dictionary = pa.array([EMAIL,'ordinary',EMAIL]).dictionary_encode().cast(pa.dictionary(pa.int8(),pa.string(),ordered=True))
        masked = adapter.ArrowPolicy(ScrubContext()).process(dictionary,'notes',lambda i:f'r{i+1}.c1')
        self.assertEqual(masked.type,dictionary.type)
        self.assertEqual(masked.to_pylist(),[MASKED_EMAIL,'ordinary',MASKED_EMAIL])


if __name__ == '__main__':
    unittest.main(verbosity=2)
