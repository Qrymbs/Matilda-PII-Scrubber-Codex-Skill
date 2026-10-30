"""Fictional RVTools relationship and ZIP-container regression fixtures."""
from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from lxml import etree

from scrub_core import ScrubContext, ScrubError
from scrub_ooxml import S, compare_xlsx, scrub_xlsx
from test_ooxml import package, read, xlsx_parts

PERSONAL_CONTACT = 'avery.stone@example.invalid'


def fixture(sheet_name, headers, records):
    parts = xlsx_parts()
    workbook = etree.fromstring(parts['xl/workbook.xml'].encode())
    workbook.find('.//' + S + 'sheet').set('name', sheet_name)
    parts['xl/workbook.xml'] = etree.tostring(workbook)
    root = etree.Element(S + 'worksheet', nsmap={None: S[1:-1]})
    data = etree.SubElement(root, S + 'sheetData')
    for row_index, values in enumerate([headers, *records], 1):
        row = etree.SubElement(data, S + 'row', r=str(row_index))
        for index, value in enumerate(values):
            cell = etree.SubElement(row, S + 'c', r=f'{chr(65 + index)}{row_index}')
            if value is not None:
                cell.set('t', 'inlineStr')
                etree.SubElement(etree.SubElement(cell, S + 'is'), S + 't').text = value
    parts['xl/worksheets/sheet1.xml'] = etree.tostring(root)
    return parts


def office_zip_metadata(path):
    """Give a synthetic package legal deflate option bits and zero permissions."""
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        central_offset = archive.start_dir
        for info in infos:
            struct.pack_into('<H', raw, info.header_offset + 6, 6)
            if raw[central_offset:central_offset + 4] != b'PK\x01\x02':
                raise AssertionError('synthetic central header missing')
            struct.pack_into('<H', raw, central_offset + 8, 6)
            struct.pack_into('<I', raw, central_offset + 38, 0)
            name_size, extra_size, comment_size = struct.unpack_from('<HHH', raw, central_offset + 28)
            central_offset += 46 + name_size + extra_size + comment_size
    path.write_bytes(raw)


class RVToolsPreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def transform(self, parts, decisions=None, office_metadata=False):
        source = self.root / 'source.xlsx'
        output = self.root / 'output.xlsx'
        package(source, parts)
        if office_metadata:
            office_zip_metadata(source)
        original = source.read_bytes()
        context = ScrubContext(review_decisions=decisions or {})
        metrics = scrub_xlsx(source, output, context)
        self.assertEqual(original, source.read_bytes())
        return source, output, context, metrics

    def test_personal_contact_in_vm_and_uuid_is_retained_and_blocked(self):
        headers = ['Annotation', 'SMBIOS UUID', 'VM', 'VM UUID', 'VM ID', 'VI SDK UUID']
        parts = fixture('vInfo', headers, [[PERSONAL_CONTACT] * len(headers)])
        source, output, ctx, metrics = self.transform(parts)
        self.assertEqual(metrics['source_profile'], 'rvtools')
        self.assertFalse(metrics['join_keys_removed'])
        self.assertNotIn('join_keys_removed', ctx.warnings)
        self.assertEqual(metrics['join_fields_nulled'], [])
        self.assertEqual(metrics['join_field_counts'], {})
        self.assertEqual(metrics['join_field_locations'], [])
        self.assertNotIn(PERSONAL_CONTACT, str(metrics))
        self.assertEqual(metrics['data_cells_masked'], 1)
        self.assertEqual(metrics['whole_data_cells_cleared'], 0)
        result = etree.fromstring(read(output)['xl/worksheets/sheet1.xml'])
        for coordinate in ['B2', 'C2', 'D2', 'E2', 'F2']:
            self.assertEqual(result.find('.//' + S + f'c[@r="{coordinate}"]/' + S + 'is/' + S + 't').text, PERSONAL_CONTACT)
        comparison = compare_xlsx(source, output)
        self.assertTrue(comparison['all_saved_values_match_expected_source_transform'])
        self.assertFalse(comparison['policy_scan_passed'])

    def test_annotation_changes_do_not_claim_loss_of_retained_or_empty_keys(self):
        headers = ['VM', 'VM UUID', 'Annotation']
        parts = fixture('vInfo', headers, [
            ['vm-example-01', '11111111-2222-3333-4444-555555555555', PERSONAL_CONTACT],
            [None, None, PERSONAL_CONTACT],
        ])
        source, output, ctx, metrics = self.transform(parts)
        self.assertEqual(metrics['data_cells_masked'], 2)
        self.assertFalse(metrics['join_keys_removed'])
        self.assertEqual(metrics['join_fields_nulled'], [])
        self.assertEqual(metrics['join_field_locations'], [])
        self.assertNotIn('join_keys_removed', ctx.warnings)
        result = etree.fromstring(read(output)['xl/worksheets/sheet1.xml'])
        self.assertEqual(result.find('.//' + S + 'c[@r="A2"]/' + S + 'is/' + S + 't').text, 'vm-example-01')
        self.assertTrue(compare_xlsx(source, output)['all_retained_parts_exact'])

    def test_sheet_context_and_actual_identifier_headers_are_both_required(self):
        for index, (name, headers) in enumerate([
            ('Inventory', ['VM', 'UUID']), ('vFiction', ['VM', 'UUID']),
            ('vInfo', ['Description', 'Annotation']),
        ]):
            with self.subTest(name=name):
                source, output = self.root / f'source{index}.xlsx', self.root / f'output{index}.xlsx'
                package(source, fixture(name, headers, [[PERSONAL_CONTACT] * len(headers)]))
                ctx = ScrubContext()
                metrics = scrub_xlsx(source, output, ctx)
                self.assertFalse(metrics['join_keys_removed'])
                self.assertNotIn('join_keys_removed', ctx.warnings)
                self.assertEqual(metrics['source_profile'], 'ooxml_values_and_metadata')

    def test_context_mask_cannot_mutate_protected_join_key(self):
        value = 'individual-account-record'
        decisions = {'s1.r2.c1': {'action': 'mask', 'spans': [
            {'start': 0, 'end': len(value), 'category': 'human_usernames'}],
            'reason_code': 'explicit_person_identifier'}}
        source, output = self.root/'protected.xlsx', self.root/'output.xlsx'
        package(source, fixture('vHost', ['UUID'], [[value]]))
        before = source.read_bytes()
        with self.assertRaisesRegex(ScrubError, 'protected_identifier_mask_forbidden'):
            scrub_xlsx(source, output, ScrubContext(review_decisions=decisions))
        self.assertEqual(source.read_bytes(), before)
        self.assertFalse(output.exists())

    def test_empty_cached_value_with_personal_formula_is_not_new_key_value_loss(self):
        parts = fixture('vInfo', ['VM'], [[None]])
        root = etree.fromstring(parts['xl/worksheets/sheet1.xml'])
        cell = root.find('.//' + S + 'c[@r="A2"]')
        etree.SubElement(cell, S + 'f').text = f'"{PERSONAL_CONTACT}"'
        parts['xl/worksheets/sheet1.xml'] = etree.tostring(root)
        _, _, ctx, metrics = self.transform(parts)
        self.assertEqual(metrics['whole_data_cells_cleared'], 0)
        self.assertEqual(metrics['data_cells_masked'], 0)
        self.assertTrue(metrics['review_required'])
        self.assertFalse(metrics['join_keys_removed'])
        self.assertNotIn('join_keys_removed', ctx.warnings)

    def test_zip_permissions_preserved_and_actual_flag_normalization_disclosed(self):
        source, output, _, metrics = self.transform(xlsx_parts(), office_metadata=True)
        with zipfile.ZipFile(source) as original, zipfile.ZipFile(output) as result:
            self.assertEqual([i.external_attr for i in original.infolist()], [i.external_attr for i in result.infolist()])
            changed = sum(a.flag_bits != b.flag_bits for a, b in zip(original.infolist(), result.infolist()))
        self.assertGreater(changed, 0)
        self.assertEqual(metrics['zip_entry_flags_normalized'], changed)
        self.assertTrue(metrics['zip_entry_permissions_preserved'])
        self.assertIn('ooxml_zip_entry_flags_normalized', metrics['format_limitations'])
        self.assertEqual(read(source), read(output))
        self.assertTrue(compare_xlsx(source, output)['zip_metadata_matches_allowed_transform'])

    def test_no_zip_flag_normalization_is_not_reported_as_a_limitation(self):
        _, _, _, metrics = self.transform(xlsx_parts())
        self.assertEqual(metrics['zip_entry_flags_normalized'], 0)
        self.assertNotIn('ooxml_zip_entry_flags_normalized', metrics['format_limitations'])


if __name__ == '__main__':
    unittest.main()
