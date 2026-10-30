"""Synthetic evidence for equal-length masking and preserved Office features."""
from __future__ import annotations
from pathlib import Path
import tempfile
import unittest
from lxml import etree
from scrub_core import ScrubContext
from scrub_documents import scrub_text, scrub_pdf
from scrub_ooxml import S, W, scrub_docx, scrub_xlsx, compare_docx, compare_xlsx
from test_ooxml import EMAIL, PERSON, package, read, xlsx_parts


class XMaskOfficeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def transform(self, parts, kind='xlsx', decisions=None):
        source, output = self.root / ('source.' + kind), self.root / ('output.' + kind)
        package(source, parts)
        before = source.read_bytes()
        ctx = ScrubContext(review_decisions=decisions or {})
        metrics = (scrub_xlsx if kind == 'xlsx' else scrub_docx)(source, output, ctx)
        self.assertEqual(source.read_bytes(), before)
        return source, output, ctx, metrics

    def test_rich_word_runs_split_email_keep_runs_styles_and_unicode(self):
        prefix, suffix = '🌍 Safe\u0301 contact ', ' | keep vm-prod-001'
        first, second = EMAIL[:8], EMAIL[8:]
        parts = {'word/document.xml': f'<w:document xmlns:w="{W[1:-1]}"><w:body><w:p w:rsidR="00112233"><w:pPr><w:keepNext/></w:pPr><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">{prefix}{first}</w:t></w:r><w:r><w:rPr><w:i/><w:vanish/></w:rPr><w:delText xml:space="preserve">{second}{suffix}</w:delText></w:r></w:p></w:body></w:document>'}
        source, output, ctx, metrics = self.transform(parts, 'docx')
        original = etree.fromstring(read(source)['word/document.xml'])
        actual = etree.fromstring(read(output)['word/document.xml'])
        self.assertEqual(len(actual.findall('.//' + W + 'r')), 2)
        self.assertEqual(actual.find('.//' + W + 't').text, prefix + 'X' * len(first))
        self.assertEqual(actual.find('.//' + W + 'delText').text, 'X' * len(second) + suffix)
        for node in original.iter():
            if node.tag in {W+'t', W+'delText'}:
                node.text = actual.xpath(original.getroottree().getpath(node), namespaces={'w':W[1:-1]})[0].text
        self.assertEqual(etree.tostring(original), etree.tostring(actual))
        self.assertEqual(metrics['data_cells_masked'], 1)
        self.assertEqual(ctx.changed, 1)
        self.assertTrue(compare_docx(source, output)['policy_scan_passed'])

    def test_manual_unicode_spans_use_codepoints_across_word_runs(self):
        prefix, identity, suffix = 'Contact: ', 'A🔑e\u0301', ' | VM vm-prod'
        text = prefix + identity + suffix
        parts = {'word/document.xml': f'<w:document xmlns:w="{W[1:-1]}"><w:body><w:p><w:r><w:t>{text[:11]}</w:t></w:r><w:r><w:t>{text[11:]}</w:t></w:r></w:p></w:body></w:document>'}
        decisions = {'p1.r1': {'action': 'mask', 'spans': [
            {'start': len(prefix), 'end': len(prefix)+len(identity), 'category': 'human_names'}],
            'reason_code': 'explicit_person_name'}}
        source, output, _, _ = self.transform(parts, 'docx', decisions)
        actual = etree.fromstring(read(output)['word/document.xml'])
        masked = ''.join(actual.itertext())
        self.assertEqual(masked, prefix + 'X'*4 + suffix)
        self.assertEqual(len(masked), len(text))
        self.assertTrue(compare_docx(source, output, decisions)['policy_scan_passed'])

    def test_shared_string_copy_on_write_preserves_resource_identifier(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace(
            '<c r="A2" t="inlineStr"><is><t>vm-prod-01</t></is></c>', '<c r="A2" t="s"><v>0</v></c>').replace(
            '<c r="B2" t="inlineStr"><is><t>Routine billing for 10.0.0.1</t></is></c>', '<c r="B2" t="s"><v>0</v></c>')
        parts['xl/sharedStrings.xml'] = f'<sst xmlns="{S[1:-1]}" count="2" uniqueCount="1"><si><r><rPr><b/></rPr><t>{EMAIL[:7]}</t></r><r><rPr><i/></rPr><t>{EMAIL[7:]}</t></r></si></sst>'
        source, output, ctx, metrics = self.transform(parts)
        actual = read(output)
        sheet = etree.fromstring(actual['xl/worksheets/sheet1.xml'])
        shared = etree.fromstring(actual['xl/sharedStrings.xml'])
        strings = shared.findall(S+'si')
        self.assertEqual(sheet.find('.//' + S + 'c[@r="A2"]/' + S + 'v').text, '0')
        self.assertEqual(sheet.find('.//' + S + 'c[@r="B2"]/' + S + 'v').text, '1')
        self.assertEqual(''.join(n.text or '' for n in strings[0].iter(S+'t')), EMAIL)
        self.assertEqual(''.join(n.text or '' for n in strings[1].iter(S+'t')), 'X'*len(EMAIL))
        self.assertEqual(len(strings[0].findall(S+'r')), len(strings[1].findall(S+'r')))
        self.assertEqual(shared.get('count'), '2')
        self.assertEqual(shared.get('uniqueCount'), '2')
        self.assertEqual(metrics['data_cells_masked'], 1)
        self.assertFalse(metrics['join_keys_removed'])
        comparison = compare_xlsx(source, output)
        self.assertTrue(comparison['all_saved_values_match_expected_source_transform'])
        self.assertFalse(comparison['policy_scan_passed'])

    def test_saved_path_masks_only_profile_component(self):
        parts = xlsx_parts()
        parts['docProps/core.xml'] = parts['docProps/core.xml'].replace('Automation', PERSON)
        parts['customXml/item1.xml'] = '<config savedPath="C:\\Users\\averystone\\Team Reports\\input.xlsx"/>'
        source, output, _, _ = self.transform(parts)
        self.assertIn(b'C:\\Users\\XXXXXXXXXX\\Team Reports\\input.xlsx', read(output)['customXml/item1.xml'])
        self.assertTrue(compare_xlsx(source, output)['policy_scan_passed'])

    def test_numeric_personal_field_retains_numeric_type_and_formula(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('>cost<', '>Employee ID<').replace('<f>SUM(1,2)</f><v>3.0000000000000001</v>', '<v>123456789</v>')
        source, output, ctx, metrics = self.transform(parts)
        self.assertEqual(read(source), read(output))
        self.assertEqual(ctx.changed, 0)
        self.assertTrue(metrics['review_required'])
        self.assertFalse(compare_xlsx(source, output)['policy_scan_passed'])

    def test_schema_header_preserved_and_flagged(self):
        parts = xlsx_parts()
        parts['xl/worksheets/sheet1.xml'] = parts['xl/worksheets/sheet1.xml'].replace('>Description<', f'>{EMAIL}<')
        source, output, _, metrics = self.transform(parts)
        self.assertEqual(read(source), read(output))
        self.assertTrue(metrics['review_required'])

    def test_text_encoding_bom_newlines_and_mixed_content_preserved(self):
        original = '🌍 contact ' + EMAIL + '\r\nResource ID: vm-prod-42\rNo PII\nfinal'
        expected = original.replace(EMAIL, 'X'*len(EMAIL))
        for index, (encoding, bom) in enumerate([('utf-8', b''), ('utf-8', b'\xef\xbb\xbf'), ('utf-16-le', b'\xff\xfe'), ('utf-16-be', b'\xfe\xff')]):
            with self.subTest(encoding=encoding, bom=bom):
                source, output = self.root/f's{index}.txt', self.root/f'o{index}.txt'
                source.write_bytes(bom + original.encode(encoding))
                ctx = ScrubContext()
                metrics = scrub_text(source, output, ctx)
                self.assertEqual(output.read_bytes(), bom + expected.encode(encoding))
                self.assertTrue(metrics['encoding_and_newlines_preserved'])
                self.assertEqual(ctx.changed, 1)

    def test_text_personal_label_only_masks_value(self):
        original = 'Contact Name: Avery Stone\r\nResourceId: avery.stone@example.invalid\r\n'
        source, output = self.root/'s.txt', self.root/'o.txt'
        source.write_bytes(original.encode())
        ctx = ScrubContext()
        scrub_text(source, output, ctx)
        self.assertEqual(output.read_bytes(), original.replace(PERSON, 'X'*len(PERSON)).encode())
        self.assertTrue(ctx.review_counts)

    def test_pdf_is_faithful_blocked_copy_not_lossy_reconstruction(self):
        from reportlab.pdfgen import canvas
        source, output = self.root/'s.pdf', self.root/'o.pdf'
        pdf = canvas.Canvas(str(source))
        pdf.setAuthor(PERSON)
        pdf.drawString(40, 700, 'Safe cost 10.25 | contact ' + EMAIL)
        pdf.line(30, 680, 500, 680)
        pdf.save()
        ctx = ScrubContext()
        metrics = scrub_pdf(source, output, ctx)
        self.assertEqual(output.read_bytes(), source.read_bytes())
        self.assertTrue(metrics['incomplete'])
        self.assertTrue(metrics['layout_preserved'])
        self.assertEqual(ctx.changed, 0)
        self.assertTrue(ctx.review_counts)

if __name__ == '__main__':
    unittest.main()
