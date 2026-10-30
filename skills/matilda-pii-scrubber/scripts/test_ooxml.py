"""Synthetic-only regression coverage for faithful OOXML human-PII handling."""
from __future__ import annotations
import copy
import tempfile
import unittest
from pathlib import Path
import zipfile
from lxml import etree

from scrub_core import ScrubContext, ScrubError
from scrub_ooxml import (S, W, scrub_xlsx, scrub_docx, verify_xlsx,
                         verify_docx, compare_xlsx, compare_docx)

PERSON = 'Avery Stone'
EMAIL = 'avery.stone@example.invalid'


def package(path, parts, comment=b''):
    with zipfile.ZipFile(path, 'w') as output:
        output.comment = comment
        for name, raw in parts.items():
            info = zipfile.ZipInfo(name, (2021, 2, 3, 4, 5, 6))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            output.writestr(info, raw.encode() if isinstance(raw, str) else raw)


def read(path):
    with zipfile.ZipFile(path) as source:
        return {n: source.read(n) for n in source.namelist()}


def xlsx_parts():
    return {
        '[Content_Types].xml': '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        'xl/workbook.xml': f'<workbook xmlns="{S[1:-1]}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Billing" sheetId="1" r:id="rId1" state="hidden"/></sheets></workbook>',
        'xl/_rels/workbook.xml.rels': '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        'xl/worksheets/sheet1.xml': f'<worksheet xmlns="{S[1:-1]}"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>ResourceId</t></is></c><c r="B1" t="inlineStr"><is><t>Description</t></is></c><c r="C1" t="inlineStr"><is><t>cost</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>vm-prod-01</t></is></c><c r="B2" t="inlineStr"><is><t>Routine billing for 10.0.0.1</t></is></c><c r="C2" s="1"><f>SUM(1,2)</f><v>3.0000000000000001</v></c></row></sheetData></worksheet>',
        'xl/styles.xml': f'<styleSheet xmlns="{S[1:-1]}"><numFmts count="1"><numFmt numFmtId="164" formatCode="0.0000000000000000"/></numFmts></styleSheet>',
        'docProps/core.xml': '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Automation</dc:creator></cp:coreProperties>',
    }


class OOXMLTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def transform(self, parts, kind='xlsx', ctx=None, comment=b''):
        source, output = self.root / ('source.' + kind), self.root / ('output.' + kind)
        package(source, parts, comment)
        before = source.read_bytes()
        context = ctx or ScrubContext()
        metrics = (scrub_xlsx if kind == 'xlsx' else scrub_docx)(source, output, context)
        self.assertEqual(before, source.read_bytes())
        return source, output, context, metrics

    def test_unaffected_bytes_and_formula_cache_are_exact(self):
        parts = xlsx_parts()
        parts['xl/charts/chart1.xml'] = '<chart xmlns="urn:synthetic"><cache><v>17.123456789012345678</v></cache></chart>'
        parts['customXml/item1.xml'] = '<technical value="production">Service billing overview</technical>'
        source, output, ctx, metrics = self.transform(parts)
        self.assertEqual(read(source), read(output))
        self.assertEqual(ctx.changed, 0)
        self.assertEqual(metrics['source_formula_caches'], 1)
        self.assertEqual(metrics['retained_formula_cells'], 1)
        self.assertTrue(compare_xlsx(source, output)['policy_scan_passed'])

    def test_author_refresh_and_profile_component_mask(self):
        parts = xlsx_parts()
        parts['docProps/core.xml'] = parts['docProps/core.xml'].replace('Automation', PERSON)
        parts['xl/workbook.xml'] = parts['xl/workbook.xml'].replace('<sheets>', '<ext savedPath="file:///Users/averystone/billing/"/><sheets>')
        parts['xl/pivotCache/pivotCacheDefinition1.xml'] = f'<pivotCacheDefinition xmlns="{S[1:-1]}" refreshedBy="{PERSON}" refreshedDate="42424.123456"/>'
        source, output, ctx, metrics = self.transform(parts)
        result = read(output)
        self.assertNotIn(PERSON.encode(), b''.join(result.values()))
        self.assertNotIn(b'averystone', b''.join(result.values()))
        self.assertIn(b'refreshedDate="42424.123456"', result['xl/pivotCache/pivotCacheDefinition1.xml'])
        self.assertEqual(ctx.changed, 3)
        self.assertEqual(metrics['metadata_values_masked'], 3)
        self.assertTrue(compare_xlsx(source, output)['policy_scan_passed'])

    def test_machine_authors_and_paths_preserved(self):
        parts = xlsx_parts()
        parts['customXml/item1.xml'] = '<config><author>Example Corporation LLC</author><path>C:\\Users\\Public\\billing</path><home>/home/ubuntu/billing</home><path>/srv/prod/data</path></config>'
        source, output, ctx, _ = self.transform(parts)
        self.assertEqual(read(source), read(output))
        self.assertEqual(ctx.changed, 0)
        self.assertFalse(ctx.review_counts)

    def test_unknown_alias_preserved_and_reviewed(self):
        parts = xlsx_parts()
        parts['customXml/item1.xml'] = '<config path="/Users/astone/billing"/>'
        source, output, ctx, metrics = self.transform(parts)
        self.assertEqual(read(source), read(output))
        self.assertEqual(ctx.changed, 0)
        self.assertTrue(metrics['review_required'])
        self.assertIn('unresolved_identity_review_required', verify_xlsx(output, source)['errors'])

    def test_rich_shared_string_spans_mask_without_safe_text_loss(self):
        parts = xlsx_parts()
        parts['xl/sharedStrings.xml'] = f'<sst xmlns="{S[1:-1]}" count="2" uniqueCount="2"><si><r><t>Contact {EMAIL}</t></r><r><t> plus safe text</t></r></si><si><t>{EMAIL}</t></si></sst>'
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('<c r="B2" t="inlineStr"><is><t>Routine billing for 10.0.0.1</t></is></c>', '<c r="B2" t="s"><v>0</v></c>')
        source, output, ctx, metrics = self.transform(parts)
        result = read(output)
        self.assertNotIn(EMAIL.encode(), b''.join(result.values()))
        cell = etree.fromstring(result['xl/worksheets/sheet1.xml']).xpath('//*[local-name()="c"][@r="B2"]')[0]
        self.assertEqual(cell.find(S + 'v').text, '0')
        self.assertIn(b'Contact ', result['xl/sharedStrings.xml'])
        self.assertIn(b' plus safe text', result['xl/sharedStrings.xml'])
        self.assertIn(('X' * len(EMAIL)).encode(), result['xl/sharedStrings.xml'])
        self.assertEqual(metrics['data_cells_masked'], 1)
        self.assertEqual(metrics['shared_string_storage_cleanups'], 2)
        self.assertEqual(ctx.changed, 2)  # one cell + one unreferenced value
        self.assertTrue(compare_xlsx(source, output)['policy_scan_passed'])

    def test_sparse_column_ledger_is_true_A1(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('</sheetData>', f'<row r="17"><c r="BB17" t="inlineStr"><is><t>{EMAIL}</t></is></c></row></sheetData>')
        _, _, ctx, _ = self.transform(parts)
        self.assertIn('s1.r17.c54', ctx.locations['human_email_addresses'])
        self.assertTrue(ctx.removal_location_coverage_complete)

    def test_binary_images_and_embedded_data_preserved_but_blocked(self):
        parts = xlsx_parts()
        parts['xl/media/image1.png'] = b'\x89PNG\r\n\x1a\nsynthetic opaque bytes'
        parts['xl/printerSettings/printerSettings1.bin'] = b'printer settings bytes'
        source, output, ctx, metrics = self.transform(parts)
        self.assertEqual(read(source), read(output))
        self.assertTrue(metrics['incomplete'])
        self.assertEqual(metrics['opaque_parts_retained'], 2)
        self.assertIn('retained_opaque_ooxml_content_uninspected', verify_xlsx(output, source)['errors'])
        self.assertEqual(ctx.changed, 0)

    def test_formula_literal_or_cache_with_pii_is_preserved_and_blocked(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('<f>SUM(1,2)</f><v>3.0000000000000001</v>', f'<f>"{EMAIL}"</f><v>3</v>')
        source, output, ctx, metrics = self.transform(parts)
        result = read(output)
        self.assertIn(EMAIL.encode(), b''.join(result.values()))
        self.assertEqual(metrics['retained_formula_cells'], 1)
        self.assertEqual(read(source), read(output))
        self.assertTrue(metrics['review_required'])
        self.assertFalse(compare_xlsx(source, output)['policy_scan_passed'])

    def test_custom_properties_comments_links_and_annotations_inspected(self):
        parts = xlsx_parts()
        parts['docProps/custom.xml'] = f'<Properties xmlns="urn:properties"><property name="Full Name"><lpwstr>{PERSON}</lpwstr></property></Properties>'
        parts['xl/comments/comment1.xml'] = f'<comments xmlns="{S[1:-1]}"><authors><author>Automation</author></authors><commentList><comment ref="A2" authorId="0"><text><t>{EMAIL}</t></text></comment></commentList></comments>'
        parts['xl/worksheets/_rels/sheet1.xml.rels'] = f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Target="mailto:{EMAIL}" TargetMode="External"/></Relationships>'
        parts['customXml/item1.xml'] = f'<?synthetic contact="{EMAIL}"?><!--{EMAIL}--><data safe="yes"/>'
        source, output, ctx, _ = self.transform(parts, comment=EMAIL.encode())
        self.assertNotIn(EMAIL.encode(), b''.join(read(output).values()))
        self.assertNotIn(PERSON.encode(), read(output)['docProps/custom.xml'])
        with zipfile.ZipFile(output) as z:
            self.assertEqual(z.comment, b'X' * len(EMAIL))
        self.assertTrue(compare_xlsx(source, output)['policy_scan_passed'])

    def test_readonly_comparison_detects_nonpii_value_or_feature_loss(self):
        source, output, _, _ = self.transform(xlsx_parts())
        before_source, before_output = source.read_bytes(), output.read_bytes()
        self.assertTrue(compare_xlsx(source, output)['policy_scan_passed'])
        self.assertEqual(source.read_bytes(), before_source)
        self.assertEqual(output.read_bytes(), before_output)
        changed = read(output)
        changed['xl/styles.xml'] = changed['xl/styles.xml'].replace(b'164', b'165')
        output.unlink()
        package(output, changed)
        comparison = compare_xlsx(source, output)
        self.assertFalse(comparison['policy_scan_passed'])
        self.assertEqual(comparison['unexpected_changed_parts'], 1)

    def test_dtd_is_rejected_without_destination(self):
        parts = xlsx_parts()
        parts['customXml/item1.xml'] = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
        source, output = self.root/'source.xlsx', self.root/'output.xlsx'
        package(source, parts)
        with self.assertRaises(ScrubError):
            scrub_xlsx(source, output, ScrubContext())
        self.assertFalse(output.exists())

    def test_docx_selective_spans_hidden_text_saved_paths_and_metadata(self):
        ns = W[1:-1]
        parts = {'word/document.xml': f'<w:document xmlns:w="{ns}"><w:body><w:p><w:r><w:t>Safe server vm-prod</w:t></w:r></w:p><w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>{EMAIL}</w:t></w:r><w:r><w:t> safe fragment</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>Description</w:t></w:r></w:p></w:tc></w:tr><w:tr><w:tc><w:p><w:r><w:t>{EMAIL}</w:t></w:r></w:p><w:p><w:r><w:t>remove entire cell</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>',
                 'docProps/core.xml': f'<core xmlns="urn:core"><creator>{PERSON}</creator></core>',
                 'word/settings.xml': '<settings xmlns="urn:settings" savedPath="C:\\Users\\averystone\\billing"/>'}
        source, output, ctx, metrics = self.transform(parts, 'docx')
        result = read(output)
        self.assertNotIn(EMAIL.encode(), b''.join(result.values()))
        self.assertIn(b'remove entire cell', result['word/document.xml'])
        self.assertIn(b' safe fragment', result['word/document.xml'])
        self.assertIn(b'vanish', result['word/document.xml'])
        self.assertIn(b'Safe server vm-prod', result['word/document.xml'])
        self.assertNotIn(b'averystone', result['word/settings.xml'])
        self.assertEqual(metrics['data_cells_masked'], 2)
        self.assertEqual(ctx.changed, 4)
        self.assertTrue(compare_docx(source, output)['policy_scan_passed'])

    def test_manual_context_retain_decision_is_not_global_alias(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('Routine billing for 10.0.0.1', 'opaquealias@example.invalid')
        decisions = {'s1.r2.c2': {'action': 'retain', 'reason_code': 'shared_organizational_mailbox'}}
        source, output, ctx, _ = self.transform(parts, ctx=ScrubContext(review_decisions=decisions))
        self.assertEqual(read(source), read(output))
        self.assertEqual(ctx.unresolved_review_occurrences if hasattr(ctx, 'unresolved_review_occurrences') else ctx.review_occurrences-ctx.resolved_review_occurrences, 0)
        self.assertTrue(compare_xlsx(source, output, decisions)['policy_scan_passed'])
        self.assertFalse(compare_xlsx(source, output)['policy_scan_passed'])

    def test_xml_review_locations_survive_prior_cell_clears(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('Routine billing for 10.0.0.1', EMAIL).replace('</worksheet>', '<ext alias="opaquealias@example.invalid"/></worksheet>')
        # Determine the exact neutral source location using only synthetic RAM.
        first_source, first_output, first_ctx, _ = self.transform(parts)
        location = first_ctx.review_locations['ambiguous_email_identity'][0]
        first_source.unlink(); first_output.unlink()
        decisions = {location: {'action': 'retain', 'reason_code': 'shared_organizational_mailbox'}}
        source, output, _, _ = self.transform(parts, ctx=ScrubContext(review_decisions=decisions))
        self.assertTrue(compare_xlsx(source, output, decisions)['policy_scan_passed'])

    def test_docx_schema_style_preserved_and_person_author_masked(self):
        parts = {'word/document.xml': f'<w:document xmlns:w="{W[1:-1]}"><w:body><w:p w:author="{PERSON}"><w:pPr><w:style w:val="{EMAIL}"/></w:pPr><w:r><w:t>Safe technical body</w:t></w:r></w:p></w:body></w:document>'}
        source, output, ctx, _ = self.transform(parts, 'docx')
        self.assertIn(EMAIL.encode(), b''.join(read(output).values()))
        self.assertNotIn(PERSON.encode(), b''.join(read(output).values()))
        self.assertEqual(ctx.changed, 1)
        self.assertFalse(compare_docx(source, output)['policy_scan_passed'])

    def test_namespace_personal_contact_is_retained_and_blocked(self):
        parts = xlsx_parts()
        parts['customXml/item1.xml'] = f'<config xmlns:p="https://example.invalid/owners/{EMAIL}" value="safe"/>'
        source, output, ctx, metrics = self.transform(parts)
        self.assertEqual(read(source), read(output))
        self.assertTrue(metrics['review_required'])
        self.assertFalse(verify_xlsx(output, source)['policy_scan_passed'])
        # Dynamic namespaces never become raw report labels.
        self.assertNotIn(EMAIL, repr(metrics))

    def test_unreferenced_shared_string_attribute_and_comment_clear(self):
        parts = xlsx_parts()
        parts['xl/sharedStrings.xml'] = f'<sst xmlns="{S[1:-1]}"><si author="{PERSON}"><!--{EMAIL}--><t>Technical</t></si></sst>'
        source, output, _, _ = self.transform(parts)
        self.assertNotIn(EMAIL.encode(), b''.join(read(output).values()))
        self.assertNotIn(PERSON.encode(), b''.join(read(output).values()))
        self.assertTrue(compare_xlsx(source, output)['policy_scan_passed'])

    def test_context_ambiguous_person_copies_remain_blocked_in_caches(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('Description', 'Full Name').replace('Routine billing for 10.0.0.1', PERSON)
        parts['xl/pivotCache/pivotCacheRecords1.xml'] = f'<pivotCacheRecords xmlns="{S[1:-1]}"><r><s v="{PERSON}"/><s v="vm-prod-01"/></r></pivotCacheRecords>'
        parts['xl/charts/chart1.xml'] = f'<c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:strCache><c:pt idx="0"><c:v>{PERSON}</c:v></c:pt></c:strCache></c:chart>'
        source, output, ctx, metrics = self.transform(parts)
        self.assertIn(PERSON.encode(), read(output)['xl/pivotCache/pivotCacheRecords1.xml'])
        self.assertEqual(ctx.changed, 1)
        self.assertEqual(metrics['data_cells_masked'], 1)
        self.assertEqual(metrics['metadata_values_masked'], 0)
        self.assertTrue(metrics['review_required'])
        self.assertFalse(compare_xlsx(source, output)['policy_scan_passed'])

    def test_approved_nonpersonal_duplicate_does_not_propagate_clear(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('Description', 'Full Name').replace('Routine billing for 10.0.0.1', PERSON).replace('</sheetData>', f'<row r="3"><c r="B3" t="inlineStr"><is><t>{PERSON}</t></is></c></row></sheetData>')
        parts['xl/pivotCache/pivotCacheRecords1.xml'] = f'<pivotCacheRecords xmlns="{S[1:-1]}"><r><s v="{PERSON}"/></r></pivotCacheRecords>'
        decisions = {'s1.r3.c2': {'action': 'retain', 'reason_code': 'organization_or_project_label'}}
        source, output, ctx, metrics = self.transform(parts, ctx=ScrubContext(review_decisions=decisions))
        self.assertIn(PERSON.encode(), read(output)['xl/pivotCache/pivotCacheRecords1.xml'])
        self.assertTrue(metrics['review_required'])
        self.assertEqual(ctx.changed, 1)
        self.assertFalse(compare_xlsx(source, output, decisions)['policy_scan_passed'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
