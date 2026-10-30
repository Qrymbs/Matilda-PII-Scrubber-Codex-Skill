"""Independent synthetic XLS preservation, privacy and finalization checks.

These workbooks are authored from invented values, never customer examples.
Expected masks and source-byte changes are specified independently of the
adapter's parser and masking implementation wherever the fixture permits it.
"""
from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import olefile
import xlrd
import xlwt

from review_support import COVERAGE_FIELDS
from scrub_core import ScrubContext, ScrubError


SCRIPTS = Path(__file__).parent
PERSON = 'Avery Stone'
EMAIL = 'avery.stone@example.invalid'
RESOURCE = 'vm-billing-001'


def mask_decision(start, end, category='human_names'):
    return {'action': 'mask', 'reason_code': 'explicit_person_name',
            'spans': [{'start': start, 'end': end, 'category': category}]}


def append_synthetic_ole_stream(path, name, payload):
    """Add one FAT stream to a tiny xlwt fixture without reusing production code.

    The fixture has one FAT sector and a directory with spare entries. This is
    deliberately a bounded fixture writer, not a general OLE implementation.
    """
    raw = bytearray(path.read_bytes())
    assert struct.unpack_from('<H', raw, 30)[0] == 9
    assert struct.unpack_from('<I', raw, 44)[0] == 1
    fat_sector = struct.unpack_from('<I', raw, 76)[0]
    directory_sector = struct.unpack_from('<I', raw, 48)[0]
    start = len(raw) // 512 - 1
    data = payload.ljust(4096, b'\0')
    assert len(data) == 4096 and start + 8 < 128
    fat_offset = (fat_sector + 1) * 512
    for i in range(8):
        struct.pack_into('<I', raw, fat_offset + (start + i) * 4,
                         start + i + 1 if i < 7 else 0xFFFFFFFE)
    directory = (directory_sector + 1) * 512
    struct.pack_into('<I', raw, directory + 128 + 72, 2)
    encoded = (name + '\0').encode('utf-16-le')
    assert len(encoded) <= 64
    entry = struct.pack('<64sHBBIII16sIQQIQ', encoded.ljust(64, b'\0'), len(encoded),
                        2, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                        b'\0' * 16, 0, 0, 0, start, len(data))
    raw[directory + 256:directory + 384] = entry
    raw.extend(data)
    path.write_bytes(raw)


def summary_information_author(author):
    value = author.encode('cp1252') + b'\0'
    author_property = struct.pack('<II', 30, len(value)) + value
    author_property += b'\0' * (-len(author_property) % 4)
    section = (struct.pack('<II', 32 + len(author_property), 2)
               + struct.pack('<IIII', 1, 24, 4, 32)
               + struct.pack('<IhH', 2, 1252, 0) + author_property)
    return (struct.pack('<HHI16sI', 0xFFFE, 0, 0x00020006, b'\0' * 16, 1)
            + bytes.fromhex('e0859ff2f94f6810ab9108002b27b3d9')
            + struct.pack('<I', 48) + section)


def append_synthetic_mini_stream(path, name, payload):
    """Create a small SummaryInformation stream through real MiniFAT sectors."""
    raw = bytearray(path.read_bytes())
    assert 0 < len(payload) <= 512
    fat_sector = struct.unpack_from('<I', raw, 76)[0]
    directory = (struct.unpack_from('<I', raw, 48)[0] + 1) * 512
    root_sector = len(raw) // 512 - 1
    mini_fat_sector = root_sector + 1
    fat_offset = (fat_sector + 1) * 512
    struct.pack_into('<II', raw, fat_offset + root_sector * 4, 0xFFFFFFFE, 0xFFFFFFFE)
    struct.pack_into('<II', raw, 60, mini_fat_sector, 1)
    struct.pack_into('<IQ', raw, directory + 116, root_sector, 512)
    struct.pack_into('<I', raw, directory + 128 + 72, 2)
    encoded = (name + '\0').encode('utf-16-le')
    entry = struct.pack('<64sHBBIII16sIQQIQ', encoded.ljust(64, b'\0'), len(encoded),
                        2, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                        b'\0' * 16, 0, 0, 0, 0, len(payload))
    raw[directory + 256:directory + 384] = entry
    minis = (len(payload) + 63) // 64
    mini_fat = [i + 1 for i in range(minis - 1)] + [0xFFFFFFFE]
    mini_fat += [0xFFFFFFFF] * (128 - minis)
    raw.extend(payload.ljust(512, b'\0'))
    raw.extend(struct.pack('<128I', *mini_fat))
    path.write_bytes(raw)


def property_set(guid, properties):
    offset = 8 + 8 * len(properties)
    table, values = b'', b''
    for pid, value in properties:
        value += b'\0' * (-len(value) % 4)
        table += struct.pack('<II', pid, offset)
        values += value
        offset += len(value)
    section = struct.pack('<II', offset, len(properties)) + table + values
    return (struct.pack('<HHI16sI', 0xFFFE, 0, 0x00020006, b'\0' * 16, 1)
            + bytes.fromhex(guid) + struct.pack('<I', 48) + section)


def lpstr(value):
    encoded = value.encode('ascii') + b'\0'
    result = struct.pack('<I', len(encoded)) + encoded
    return result + b'\0' * (-len(result) % 4)


class NativeXlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-native-xls-')
        self.root = Path(self.temp.name)
        self.serial = 0

    def tearDown(self):
        self.temp.cleanup()

    def workbook(self, rows=None, *, owner='', extra=None):
        self.serial += 1
        path = self.root / f'billing-{self.serial}.xls'
        book = xlwt.Workbook()
        book.set_owner(owner)
        sheet = book.add_sheet('Billing')
        for r, row in enumerate(rows or [['resource_id', 'fullname', 'cost'],
                                         [RESOURCE, PERSON, 12.375]]):
            for c, value in enumerate(row):
                sheet.write(r, c, value)
        if extra:
            extra(book, sheet)
        book.save(str(path))
        return path

    def transform(self, source, decisions=None):
        from scrub_xls import scrub_xls
        output = source.with_name(source.stem + '_SCRUBBED.xls')
        before = source.read_bytes()
        context = ScrubContext(review_decisions=decisions or {})
        metrics = scrub_xls(source, output, context)
        self.assertEqual(source.read_bytes(), before, 'Original XLS must not change')
        self.assertEqual(output.suffix, '.xls')
        self.assertEqual(len(output.read_bytes()), len(before))
        return output, context, metrics

    def read_sheet(self, path, index=0):
        with xlrd.open_workbook(path, formatting_info=True) as book:
            sheet = book.sheet_by_index(index)
            return [[(sheet.cell(r, c).ctype, sheet.cell_value(r, c), sheet.cell_xf_index(r, c))
                     for c in range(sheet.ncols)] for r in range(sheet.nrows)]

    def run_scrub(self, source):
        self.serial += 1
        out = self.root / f'run-{self.serial}'
        result = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'scrub.py'),
                                 str(source), '--output-dir', str(out)],
                                capture_output=True, text=True,
                                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertIn(result.returncode, (0, 2), result.stdout + result.stderr)
        report = json.loads((out / 'scrub-report.json').read_text())
        return out, report

    def finalize(self, source, out, report, decisions):
        evidence = {'version': 2, 'run_id': report['run_id'], 'files': {
            'file0001': {**{field: True for field in COVERAGE_FIELDS},
                         'unresolved_items': 0, 'decisions': decisions}}}
        path = out / 'synthetic-review.json'
        path.write_text(json.dumps(evidence))
        result = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'finalize_report.py'),
                                 str(out / 'scrub-report.json'), '--review-evidence', str(path),
                                 '--source', 'file0001=' + str(source)],
                                capture_output=True, text=True,
                                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        return result, json.loads((out / 'scrub-report.json').read_text())

    def test_native_mask_changes_only_known_person_bytes(self):
        source = self.workbook()
        before = source.read_bytes()
        self.assertEqual(before.count(PERSON.encode()), 1)
        output, ctx, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), before.replace(PERSON.encode(), b'X' * len(PERSON)))
        self.assertFalse(metrics.get('incomplete', False), metrics)
        self.assertEqual(ctx.changed, 1)
        self.assertEqual(self.read_sheet(output)[1][1][1], 'X' * len(PERSON))
        self.assertEqual(self.read_sheet(source)[1][2], self.read_sheet(output)[1][2])

    def test_zero_pii_native_workbook_is_byte_identical(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 12.375]])
        output, ctx, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertEqual(ctx.changed, 0)
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_hidden_sheets_rows_formats_dates_and_boolean_types_are_preserved(self):
        def extra(book, sheet):
            sheet.row(1).hidden = True
            sheet.col(0).width = 6000
            sheet.write(2, 2, datetime(2026, 1, 7), xlwt.easyxf(num_format_str='YYYY-MM-DD'))
            sheet.write(3, 2, True)
            hidden = book.add_sheet('Inventory')
            hidden.visibility = 2
            hidden.write(0, 0, 'resource_id')
            hidden.write(1, 0, 'vm-hidden-002')
        source = self.workbook(extra=extra)
        output, _, metrics = self.transform(source)
        self.assertFalse(metrics.get('incomplete', False), metrics)
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(PERSON.encode(), b'X' * len(PERSON)))
        with xlrd.open_workbook(output, formatting_info=True) as book:
            self.assertEqual(book.sheet_by_index(1).visibility, 2)
            self.assertEqual(book.sheet_by_index(0).rowinfo_map[1].hidden, 1)
            self.assertEqual(book.sheet_by_index(0).colinfo_map[0].width, 6000)
            self.assertEqual(book.sheet_by_index(0).cell_type(2, 2), xlrd.XL_CELL_DATE)
            self.assertEqual(book.sheet_by_index(0).cell_type(3, 2), xlrd.XL_CELL_BOOLEAN)

    def test_utf16_bmp_mask_preserves_native_string_encoding(self):
        person = 'Мария Иванова'
        source = self.workbook([['resource_id', 'fullname'], [RESOURCE, person]])
        raw = person.encode('utf-16-le')
        self.assertEqual(source.read_bytes().count(raw), 1)
        output, _, metrics = self.transform(source, {'s1.r2.c2': mask_decision(0, len(person))})
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(raw, ('X' * len(person)).encode('utf-16-le')))
        self.assertEqual(self.read_sheet(output)[1][1][1], 'X' * len(person))
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_non_bmp_mask_is_preserved_and_blocked_without_false_change_counts(self):
        person = 'A🔑e'
        source = self.workbook([['resource_id', 'notes'], [RESOURCE, person]])
        output, ctx, metrics = self.transform(source, {'s1.r2.c2': mask_decision(0, len(person))})
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertEqual(ctx.changed, 0, 'A retained conflict is not a completed mask')
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_sst_continuation_masks_embedded_email_without_truncation(self):
        value = 'Technical context ' + ('a' * 19000) + ' contact ' + EMAIL + ' | resource ' + RESOURCE
        source = self.workbook([['resource_id', 'notes'], [RESOURCE, value]])
        with olefile.OleFileIO(source) as book:
            stream = book.openstream('Workbook').read()
        cursor, continues = 0, 0
        while cursor + 4 <= len(stream):
            code, size = struct.unpack_from('<HH', stream, cursor)
            if not code and not size:
                break
            continues += code == 0x003C
            cursor += 4 + size
        self.assertGreaterEqual(continues, 2, 'Fixture must cross multiple BIFF records')
        output, ctx, metrics = self.transform(source)
        self.assertEqual(self.read_sheet(output)[1][1][1], value.replace(EMAIL, 'X' * len(EMAIL)))
        self.assertEqual(ctx.changed, 1)
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_repeated_shared_string_masks_all_agreeing_cells_but_only_one_physical_string(self):
        source = self.workbook([['resource_id', 'fullname'], [RESOURCE, PERSON], ['vm-billing-002', PERSON]])
        self.assertEqual(source.read_bytes().count(PERSON.encode()), 1)
        output, ctx, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(PERSON.encode(), b'X' * len(PERSON)))
        self.assertEqual(ctx.changed, 2, 'Logical occurrences count separately from shared bytes')
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_shared_string_conflict_preserves_protected_reference_and_does_not_claim_masks(self):
        source = self.workbook([['resource_id', 'personal_email'], [EMAIL, EMAIL]])
        output, ctx, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertEqual(ctx.changed, 0)
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)
        self.assertEqual(self.read_sheet(output)[1][0][1], EMAIL)

    def test_conflicting_reviewed_shared_string_uses_cannot_overwrite_a_retained_label(self):
        source = self.workbook([['project_label', 'fullname'], [PERSON, PERSON]])
        decisions = {'s1.r2.c1': {'action': 'retain', 'reason_code': 'organization_or_project_label'},
                     's1.r2.c2': mask_decision(0, len(PERSON))}
        output, ctx, metrics = self.transform(source, decisions)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertEqual(ctx.changed, 0)
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_writeaccess_author_metadata_is_masked_at_its_reported_location(self):
        from scrub_xls import inspect_xls
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]], owner=PERSON)
        authors = [item for item in inspect_xls(source)['items'] if item['value'] == PERSON]
        self.assertEqual(len(authors), 1)
        location = authors[0]['location']
        self.assertNotEqual(location, 's1.r2.c1')
        output, ctx, metrics = self.transform(source, {location: mask_decision(0, len(PERSON))})
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(PERSON.encode(), b'X' * len(PERSON)))
        self.assertEqual(ctx.changed, 1)
        self.assertIn(location, ctx.locations['human_names'])
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_unused_sst_text_is_inspected_instead_of_hidden_by_cell_only_scanning(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]],
                               extra=lambda book, sheet: book.add_str(EMAIL))
        output, ctx, metrics = self.transform(source)
        self.assertNotIn(EMAIL.encode(), output.read_bytes())
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(EMAIL.encode(), b'X' * len(EMAIL)))
        self.assertEqual(ctx.changed, 1)
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_ole_summary_author_is_scrubbed_and_property_structure_preserved(self):
        from scrub_xls import inspect_xls
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        append_synthetic_ole_stream(source, '\x05SummaryInformation', summary_information_author(PERSON))
        with olefile.OleFileIO(source) as book:
            self.assertEqual(book.getproperties('\x05SummaryInformation')[4], PERSON.encode())
        items = [item for item in inspect_xls(source)['items'] if item['value'] == PERSON]
        self.assertEqual(len(items), 1)
        location = items[0]['location']
        output, _, metrics = self.transform(source, {location: mask_decision(0, len(PERSON))})
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(PERSON.encode(), b'X' * len(PERSON)))
        with olefile.OleFileIO(output) as book:
            self.assertEqual(book.getproperties('\x05SummaryInformation')[4], b'X' * len(PERSON))
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_small_ole_summary_metadata_is_scrubbed_through_minifat_mapping(self):
        from scrub_xls import inspect_xls
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        append_synthetic_mini_stream(source, '\x05SummaryInformation', summary_information_author(PERSON))
        with olefile.OleFileIO(source) as book:
            self.assertEqual(book.getproperties('\x05SummaryInformation')[4], PERSON.encode())
        items = [item for item in inspect_xls(source)['items'] if item['value'] == PERSON]
        self.assertEqual(len(items), 1)
        output, _, metrics = self.transform(source, {items[0]['location']: mask_decision(0, len(PERSON))})
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(PERSON.encode(), b'X' * len(PERSON)))
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_standard_document_summary_vectors_are_inspected_and_preserved(self):
        from scrub_xls import inspect_xls
        payload = property_set('02d5cdd59c2e1b10939708002b2cf9ae', [
            (1, struct.pack('<IhH', 2, 1252, 0)),
            (12, struct.pack('<III', 0x100C, 2, 30) + lpstr('Worksheets')
             + struct.pack('<Ii', 3, 1)),
            (13, struct.pack('<II', 0x101E, 1) + lpstr('Billing'))])
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        append_synthetic_mini_stream(source, '\x05DocumentSummaryInformation', payload)
        inspection = inspect_xls(source)
        labels = [item for item in inspection['items'] if item['value'] in ('Worksheets', 'Billing')]
        self.assertGreaterEqual(len(labels), 3)  # Sheet name plus both metadata labels.
        self.assertTrue(all(item['structural'] for item in labels))
        output, _, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_standard_compobj_identity_is_preserved_and_unknown_tail_blocks(self):
        header = bytes.fromhex('0100feff030a0000ffffffff1008020000000000c000000000000046')
        def comp_string(value):
            encoded = value.encode() + b'\0'
            return struct.pack('<I', len(encoded)) + encoded
        content = header + comp_string('Microsoft Excel Worksheet') + comp_string('Biff8') + comp_string('Excel.Sheet.8')
        for suffix, expected_complete in ((b'', True), (EMAIL.encode(), False)):
            with self.subTest(extra=bool(suffix)):
                source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
                append_synthetic_mini_stream(source, '\x01CompObj', content + suffix)
                output, _, metrics = self.transform(source)
                self.assertEqual(output.read_bytes(), source.read_bytes())
                self.assertEqual(not metrics.get('incomplete', False), expected_complete, metrics)

    def test_cp1200_lpstr_byte_count_masks_unicode_metadata_without_reencoding(self):
        from scrub_xls import inspect_xls
        encoded = (PERSON + '\0').encode('utf-16-le')
        payload = property_set('e0859ff2f94f6810ab9108002b27b3d9', [
            (1, struct.pack('<IhH', 2, 1200, 0)),
            (4, struct.pack('<II', 30, len(encoded)) + encoded)])
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        append_synthetic_mini_stream(source, '\x05SummaryInformation', payload)
        authors = [item for item in inspect_xls(source)['items'] if item['value'] == PERSON]
        self.assertEqual(len(authors), 1)
        output, _, metrics = self.transform(source, {authors[0]['location']: mask_decision(0, len(PERSON))})
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(
            PERSON.encode('utf-16-le'), ('X' * len(PERSON)).encode('utf-16-le')))
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_explicit_review_cannot_mask_structural_sheet_name(self):
        from scrub_xls import scrub_xls
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        before = source.read_bytes()
        output = self.root / 'forbidden-structural-output.xls'
        with self.assertRaisesRegex(ScrubError, 'schema_label_mask_forbidden'):
            scrub_xls(source, output, ScrubContext(review_decisions={'s1': mask_decision(0, 7)}))
        self.assertEqual(source.read_bytes(), before)
        self.assertFalse(output.exists())

    def test_numeric_author_metadata_is_inspected_and_cannot_be_waived_as_ready(self):
        from scrub_xls import inspect_xls
        payload = property_set('e0859ff2f94f6810ab9108002b27b3d9', [
            (1, struct.pack('<IhH', 2, 1252, 0)), (4, struct.pack('<Ii', 3, 123456789))])
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        append_synthetic_mini_stream(source, '\x05SummaryInformation', payload)
        values = [item for item in inspect_xls(source)['items'] if item['value'] == 123456789]
        self.assertEqual(len(values), 1, 'Typed metadata must participate in inspection')
        out, report = self.run_scrub(source)
        result, final = self.finalize(source, out, report, {})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')

    def test_unused_mini_stream_data_with_personal_text_blocks_inspection(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        append_synthetic_mini_stream(source, '\x05SummaryInformation', summary_information_author('Automation'))
        raw = bytearray(source.read_bytes())
        # The appended root mini-stream is immediately before the MiniFAT.
        raw[-1024 + 256:-1024 + 256 + len(EMAIL)] = EMAIL.encode()
        source.write_bytes(raw)
        output, _, metrics = self.transform(source)
        self.assertIn(EMAIL.encode(), output.read_bytes())
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_nonzero_physical_root_mini_stream_tail_beyond_declared_size_blocks(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        append_synthetic_mini_stream(source, '\x05SummaryInformation', summary_information_author('Automation'))
        raw = bytearray(source.read_bytes())
        directory = (struct.unpack_from('<I', raw, 48)[0] + 1) * 512
        struct.pack_into('<Q', raw, directory + 120, 128)
        raw[-1024 + 256:-1024 + 256 + len(EMAIL)] = EMAIL.encode()
        source.write_bytes(raw)
        output, _, metrics = self.transform(source)
        self.assertIn(EMAIL.encode(), output.read_bytes())
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_unreachable_active_directory_entry_with_personal_name_blocks(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        raw = bytearray(source.read_bytes())
        directory = (struct.unpack_from('<I', raw, 48)[0] + 1) * 512
        encoded = (EMAIL + '\0').encode('utf-16-le')
        entry = struct.pack('<64sHBBIII16sIQQIQ', encoded.ljust(64, b'\0'), len(encoded),
                            2, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                            b'\0' * 16, 0, 0, 0, 0xFFFFFFFE, 0)
        raw[directory + 256:directory + 384] = entry
        source.write_bytes(raw)
        with olefile.OleFileIO(source) as book:
            self.assertEqual(book.listdir(), [['Workbook']], 'Orphan entry must not be reachable')
        output, _, metrics = self.transform(source)
        self.assertIn(EMAIL.encode('utf-16-le'), output.read_bytes())
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_opaque_ole_stream_is_preserved_and_blocks_inspection(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        append_synthetic_ole_stream(source, 'PrivateData', EMAIL.encode())
        output, _, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_nonzero_metadata_tail_is_not_mistaken_for_inspected_padding(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        payload = summary_information_author('Automation') + EMAIL.encode()
        append_synthetic_ole_stream(source, '\x05SummaryInformation', payload)
        output, _, metrics = self.transform(source)
        self.assertIn(EMAIL.encode(), output.read_bytes(), 'Unknown bytes must remain intact')
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_stale_directory_name_in_an_unused_entry_blocks_inspection(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        raw = bytearray(source.read_bytes())
        directory = (struct.unpack_from('<I', raw, 48)[0] + 1) * 512
        start = directory + 256
        encoded = EMAIL.encode('utf-16-le')
        self.assertLess(len(encoded), 64)
        self.assertEqual(raw[start + 66], 0, 'Fixture entry must be unused')
        raw[start:start + len(encoded)] = encoded
        source.write_bytes(raw)
        output, _, metrics = self.transform(source)
        self.assertIn(encoded, output.read_bytes(), 'Unused directory bytes must be preserved')
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_rich_text_runs_and_fonts_survive_native_mask(self):
        def extra(book, sheet):
            bold = xlwt.Font()
            bold.bold = True
            sheet.write_rich_text(1, 1, [(PERSON[:5], bold), PERSON[5:]])
        source = self.workbook([['resource_id', 'fullname'], [RESOURCE]], extra=extra)
        output, _, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), source.read_bytes().replace(PERSON.encode(), b'X' * len(PERSON)))
        self.assertEqual(self.read_sheet(output)[1][1][1], 'X' * len(PERSON))
        self.assertFalse(metrics.get('incomplete', False), metrics)

    def test_formula_bytes_are_retained_and_the_unsupported_file_remains_blocked(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, xlwt.Formula('1+2')]])
        output, ctx, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertEqual(ctx.changed, 0)
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_unknown_biff_record_is_not_silently_cleared_by_a_ready_result(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]])
        with olefile.OleFileIO(source, write_mode=True) as book:
            stream = bytearray(book.openstream('Workbook').read())
            cursor, changed = 0, False
            while cursor + 4 <= len(stream):
                code, size = struct.unpack_from('<HH', stream, cursor)
                if code == 0x002B:  # PRINTGRIDLINES is optional, so the workbook remains readable.
                    struct.pack_into('<H', stream, cursor, 0x0FFE)
                    changed = True
                    break
                cursor += 4 + size
            self.assertTrue(changed, 'Synthetic fixture must contain target record')
            book.write_stream('Workbook', bytes(stream))
        output, _, metrics = self.transform(source)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertTrue(metrics.get('incomplete') or metrics.get('blocked'), metrics)

    def test_small_sparse_file_cannot_force_unbounded_cell_matrix_inspection(self):
        from scrub_xls import scrub_xls
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 1.25]],
                               extra=lambda book, sheet: sheet.write(65535, 255, 'technical'))
        original = source.read_bytes()
        self.assertLess(len(original), 20000, 'The sparse adversarial fixture should be small')
        output = source.with_name('blocked-output.xls')
        with self.assertRaisesRegex(ScrubError, 'xls_cell_count_limit'):
            scrub_xls(source, output, ScrubContext())
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse(output.exists())

    def test_complete_review_can_finalize_a_genuine_scrubbed_xls_as_ready(self):
        source = self.workbook()
        original = source.read_bytes()
        out, report = self.run_scrub(source)
        self.assertEqual(report['files'][0]['output_format'], 'xls')
        result, final = self.finalize(source, out, report, {'s1.r2.c2': mask_decision(0, len(PERSON))})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = final['files'][0]
        self.assertEqual(record['submission_status'], 'ready_for_manual_submission')
        self.assertTrue(record['artifact'].startswith('ready/'))
        self.assertTrue(record['artifact'].endswith('_SCRUBBED.xls'))
        self.assertTrue(record['verification']['source_comparison_passed'])
        self.assertEqual(source.read_bytes(), original)

    def test_zero_mask_xls_can_finalize_ready_after_complete_review(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, 12.375]])
        out, report = self.run_scrub(source)
        result, final = self.finalize(source, out, report, {})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = final['files'][0]
        self.assertEqual(record['submission_status'], 'ready_for_manual_submission')
        self.assertEqual((out / record['artifact']).read_bytes(), source.read_bytes())

    def test_one_restored_personal_character_cannot_pass_exact_span_verification(self):
        source = self.workbook()
        out, report = self.run_scrub(source)
        artifact = out / report['files'][0]['artifact']
        content = artifact.read_bytes()
        self.assertEqual(content.count(b'X' * len(PERSON)), 1)
        artifact.write_bytes(content.replace(b'X' * len(PERSON), b'A' + b'X' * (len(PERSON) - 1)))
        result, final = self.finalize(source, out, report, {'s1.r2.c2': mask_decision(0, len(PERSON))})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')
        self.assertFalse(final['files'][0]['verification']['source_comparison_passed'])

    def test_unrelated_row_height_tamper_fails_even_when_all_cell_values_match(self):
        source = self.workbook()
        out, report = self.run_scrub(source)
        artifact = out / report['files'][0]['artifact']
        values = self.read_sheet(artifact)
        with olefile.OleFileIO(artifact, write_mode=True) as book:
            stream = bytearray(book.openstream('Workbook').read())
            cursor, changed = 0, False
            while cursor + 4 <= len(stream):
                code, size = struct.unpack_from('<HH', stream, cursor)
                if code == 0x0208 and struct.unpack_from('<H', stream, cursor + 4)[0] == 1:
                    stream[cursor + 10] ^= 1
                    changed = True
                    break
                cursor += 4 + size
            self.assertTrue(changed, 'Fixture must contain a ROW record')
            book.write_stream('Workbook', bytes(stream))
        self.assertEqual(self.read_sheet(artifact), values)
        result, final = self.finalize(source, out, report, {'s1.r2.c2': mask_decision(0, len(PERSON))})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')
        self.assertFalse(final['files'][0]['verification']['source_comparison_passed'])

    def test_tampered_numeric_output_is_rejected_by_independent_source_comparison(self):
        source = self.workbook()
        out, report = self.run_scrub(source)
        record = report['files'][0]
        artifact = out / record['artifact']
        with olefile.OleFileIO(artifact, write_mode=True) as book:
            stream = bytearray(book.openstream('Workbook').read())
            cursor, changed = 0, False
            while cursor + 4 <= len(stream):
                code, size = struct.unpack_from('<HH', stream, cursor)
                if code == 0x027E and struct.unpack_from('<HH', stream, cursor + 4) == (1, 2):
                    stream[cursor + 10] ^= 4  # RK numeric payload; leave cell and XF indexes intact.
                    changed = True
                    break
                if code == 0x0203 and struct.unpack_from('<HH', stream, cursor + 4) == (1, 2):
                    struct.pack_into('<d', stream, cursor + 10, 999.0)
                    changed = True
                    break
                cursor += 4 + size
            self.assertTrue(changed, 'Fixture must contain a native numeric cell')
            book.write_stream('Workbook', bytes(stream))
        result, final = self.finalize(source, out, report, {'s1.r2.c2': mask_decision(0, len(PERSON))})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')
        self.assertFalse(final['files'][0]['verification']['source_comparison_passed'])

    def test_automatic_masks_still_require_exact_semantic_review_for_xls(self):
        source = self.workbook()
        out, report = self.run_scrub(source)
        result, final = self.finalize(source, out, report, {})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')
        self.assertFalse(final['files'][0]['verification']['semantic_mask_review_passed'])

    def test_claiming_complete_review_does_not_make_formula_workbook_ready(self):
        source = self.workbook([['resource_id', 'cost'], [RESOURCE, xlwt.Formula('1+2')]])
        out, report = self.run_scrub(source)
        result, final = self.finalize(source, out, report, {})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(final['files'][0]['submission_status'], 'blocked')


if __name__ == '__main__':
    unittest.main(verbosity=2)
