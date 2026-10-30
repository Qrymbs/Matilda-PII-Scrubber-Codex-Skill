"""Local explicit-human-PII adapters for text, Word and PDF.

Human spans become equal-length uppercase X masks. Word text runs and safe
XML features are retained. PDF bytes remain unchanged when exact safe editing
is unsupported; confirmed PII and inspection gaps block release.
"""
from __future__ import annotations

import html
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

_MAX_DOCX_XML_BYTES = 64 * 1024 * 1024
_MAX_DOCX_EXPANDED_BYTES = 256 * 1024 * 1024
_MAX_DOCX_PARTS = 20000
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

_KEY_VALUE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _./()%\-]{0,90})\s*[:=]\s*(.*?)\s*$")


def _error(code):
    try:
        from scrub_core import ScrubError
        return ScrubError(code)
    except ImportError:
        return RuntimeError(code)


def _guard_paths(src, dst):
    if src.resolve() == dst.resolve():
        raise _error("source_overwrite_forbidden")
    if dst.exists() or dst.is_symlink():
        raise _error("output_already_exists")


def _remove_failed_output(dst):
    try:
        dst.unlink(missing_ok=True)
    except OSError:
        pass


def _safe_failure(exc, code):
    # Preserve the core's typed, content-free errors only.
    try:
        from scrub_core import ScrubError
        if isinstance(exc, ScrubError):
            return exc
    except ImportError:
        if isinstance(exc, RuntimeError) and re.fullmatch(r"[a-z0-9_]+", str(exc)):
            return exc
    return _error(code)


def _text(value):
    """Null is the literal token null consistently in prose/text adapters."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _item_spans(text, field='free_text'):
    """Map contextual key/value evidence back to original Unicode offsets."""
    from scrub_core import detect_pii_spans, is_protected_resource_field
    match = _KEY_VALUE.match(text)
    if match and field == 'free_text':
        label, value = match.groups()
        if is_protected_resource_field(label):
            return detect_pii_spans(text, label)
    spans, reviews = detect_pii_spans(text, field)
    if match and field == 'free_text':
        label, value = match.groups()
        nested, reasons = detect_pii_spans(value, label)
        spans += [{**span, 'start': span['start'] + match.start(2),
                   'end': span['end'] + match.start(2)} for span in nested]
        reviews = set(reviews) | set(reasons)
    return spans, reviews


def _scrub_item(text, ctx, location):
    """Retain labels, punctuation and nonpersonal spans of an original item."""
    if not text:
        return text
    from scrub_core import is_protected_resource_field
    field = 'free_text'
    match = _KEY_VALUE.match(text)
    if match and is_protected_resource_field(match.group(1)):
        field = match.group(1)
    spans, reviews = _item_spans(text, field)
    # The core accounts for the whole source item once; contextual spans have
    # already been mapped from the value to their source positions.
    cleaned = ctx.scrub(text, field=field, location=location, spans=spans)
    for index, reason in enumerate(sorted(reviews)):
        if (reason, location) not in ctx._review_events:
            blocking = {'protected_identifier_contains_pii', 'schema_label_contains_pii',
                        'type_masking_conflict', 'formula_pii_requires_review', 'unsupported_content_uninspected'}
            ctx.note_review(reason, location, _item=index == 0,
                            _resolved=location in ctx.review_decisions and reason not in blocking)
    return cleaned


def scrub_text(src: Path, dst: Path, ctx):
    """Preserve UTF encoding/BOM and original newline bytes while masking."""
    src, dst = Path(src), Path(dst)
    _guard_paths(src, dst)
    try:
        with src.open('rb') as stream:
            prefix = stream.read(8192)
        if prefix.startswith(b'\xff\xfe'):
            encoding, bom = 'utf-16-le', b'\xff\xfe'
        elif prefix.startswith(b'\xfe\xff'):
            encoding, bom = 'utf-16-be', b'\xfe\xff'
        else:
            encoding = 'utf-8'
            bom = b'\xef\xbb\xbf' if prefix.startswith(b'\xef\xbb\xbf') else b''
            if b'\x00' in prefix:
                raise _error('text_binary_or_unsupported_encoding')
        count = 0
        with src.open('r', encoding=encoding, errors='strict', newline='') as reader:
            with dst.open('w', encoding=encoding, newline='') as writer:
                for count, line in enumerate(reader, start=1):
                    if len(line) > 16 * 1024 * 1024:
                        raise _error('text_item_size_limit')
                    # Encoding-specific readers retain the BOM as U+FEFF.
                    marker = '\ufeff' if count == 1 and bom and line.startswith('\ufeff') else ''
                    body = line[len(marker):]
                    match = re.search(r'(\r\n|\r|\n)$', body)
                    newline = match.group(0) if match else ''
                    body = body[:-len(newline)] if newline else body
                    writer.write(marker + _scrub_item(body, ctx, f'l{count}') + newline)
        return {'lines': count, 'incomplete': False, 'layout_preserved': True,
                'format_limitations': [], 'encoding_and_newlines_preserved': True}
    except UnicodeError:
        _remove_failed_output(dst)
        raise _error('text_unsupported_encoding') from None
    except Exception as exc:
        _remove_failed_output(dst)
        raise _safe_failure(exc, 'text_processing_failed') from None


def _xml(raw):
    if len(raw) > _MAX_DOCX_XML_BYTES or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise _error("docx_unsafe_or_oversize_xml")
    try:
        return ET.fromstring(raw)
    except ET.ParseError:
        raise _error("docx_malformed_xml") from None


def _person_metadata_field(name):
    local = str(name).rsplit("}", 1)[-1].lstrip("/").lower()
    return {"creator": "author", "lastmodifiedby": "last_modified_by", "author": "author",
            "initials": "person_initials"}.get(local, local)


def _word_item_text(element):
    pieces = []
    def walk(node):
        if node.tag in {_W + "t", _W + "delText", _W + "instrText"}:
            pieces.append(node.text or "")
        elif node.tag == _W + "tab":
            pieces.append("\t")
        elif node.tag in {_W + "br", _W + "cr"}:
            pieces.append("\n")
        else:
            for child in node:
                walk(child)
            if node.tag == _W + "p":
                pieces.append("\n")
    walk(element)
    return "".join(pieces).rstrip("\n")


def _replace_word_item(element, value):
    """Replace only text-node characters, preserving every original run."""
    raw = _word_item_text(element)
    if len(raw) != len(value):
        raise _error('word_text_length_changed')
    offset = 0
    def walk(node):
        nonlocal offset
        if node.tag in {_W + 't', _W + 'delText', _W + 'instrText'}:
            old = node.text or ''
            node.text = value[offset:offset + len(old)]
            offset += len(old)
        elif node.tag == _W + 'tab':
            if value[offset:offset+1] != '\t':
                raise _error('word_structural_whitespace_mask_forbidden')
            offset += 1
        elif node.tag in {_W + 'br', _W + 'cr'}:
            if offset < len(value) and value[offset:offset+1] != '\n':
                raise _error('word_structural_whitespace_mask_forbidden')
            offset += 1
        else:
            for child in node:
                walk(child)
            if node.tag == _W + 'p':
                if offset < len(value) and value[offset:offset+1] != '\n':
                    raise _error('word_structural_whitespace_mask_forbidden')
                offset += 1
    walk(element)


def _scrub_word_tree(root, ctx, part_index):
    """Inspect all stories, including hidden/deleted text, without executing fields."""
    cells = paragraphs = 0
    for table_index, table in enumerate(root.iter(_W + "tbl"), 1):
        rows = table.findall(_W + "tr")
        fields = [_word_item_text(cell) for cell in rows[0].findall(_W + "tc")] if rows else []
        for row_index, row in enumerate(rows):
            for column_index, cell in enumerate(row.findall(_W + "tc")):
                cells += 1
                raw = _word_item_text(cell)
                field = fields[column_index] if row_index and column_index < len(fields) else "free_text"
                location = f"p{part_index}.b{table_index}.r{row_index+1}.c{column_index+1}"
                cleaned = ctx.scrub(raw, field=field, location=location)
                if cleaned != raw:
                    _replace_word_item(cell, cleaned)
    for paragraph_index, paragraph in enumerate(list(root.iter(_W + "p")), 1):
        if any(parent.tag == _W + "tc" for parent in paragraph.iterancestors()):
            continue
        paragraphs += 1
        raw = _word_item_text(paragraph)
        cleaned = _scrub_item(raw, ctx, f"p{part_index}.r{paragraph_index}")
        if cleaned != raw:
            _replace_word_item(paragraph, cleaned)
    return paragraphs, cells


def scrub_docx(src: Path, dst: Path, ctx):
    """Preserve unaffected OOXML bytes; inspect body, metadata and attributes."""
    from scrub_ooxml import scrub_docx as scrub_package
    return scrub_package(src, dst, ctx)


def _pdf_image_count(page):
    """Count image XObjects without decoding/copying image pixels."""
    seen = set()
    def walk(resources):
        count = 0
        if not resources:
            return 0
        try:
            resources = resources.get_object()
            xobjects = resources.get("/XObject", {})
            xobjects = xobjects.get_object() if hasattr(xobjects, "get_object") else xobjects
            for value in xobjects.values():
                identity = (getattr(value, "idnum", id(value)), getattr(value, "generation", 0))
                if identity in seen:
                    continue
                seen.add(identity)
                obj = value.get_object()
                if obj.get("/Subtype") == "/Image":
                    count += 1
                elif obj.get("/Subtype") == "/Form":
                    count += walk(obj.get("/Resources"))
        except Exception:
            raise _error("pdf_resource_inspection_failed") from None
        return count
    count = walk(page.get("/Resources"))
    try:
        content = page.get_contents()
        if content is not None:
            count += sum(operator == b"INLINE IMAGE" for _, operator in content.operations)
    except Exception:
        raise _error("pdf_content_inspection_failed") from None
    return count


def _pdf_font():
    """Embed a trusted local Unicode font, never a font program from the source."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    import reportlab
    path = Path(reportlab.__file__).parent / "fonts" / "Vera.ttf"
    if path.is_file():
        if "ScrubberUnicode" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("ScrubberUnicode", str(path)))
        return "ScrubberUnicode"
    return "Courier"


def _pdf_safe_string(value, ctx):
    value = _text(value)
    if any(ord(ch) < 32 and ch not in "\n\t" for ch in value):
        ctx.warn("pdf_control_characters_omitted")
    return "".join(ch for ch in value if ord(ch) >= 32 or ch in "\n\t")


def scrub_pdf(src: Path, dst: Path, ctx):
    """Retain PDF objects exactly; unsupported safe masking blocks release."""
    try:
        from pypdf import PdfReader
        from scrub_core import assess_value
    except ImportError:
        raise _error('dependency_pdf_packages_missing') from None
    import shutil
    src, dst = Path(src), Path(dst)
    _guard_paths(src, dst)
    incomplete = False
    text_items = image_count = attachments = annotations = 0
    def inspect(value, field, location):
        nonlocal incomplete
        text = str(value)
        categories, reasons = assess_value(text, field)
        ctx.inspected += 1
        ctx.retained += 1
        if categories:
            reasons = set(reasons) | {'unsupported_content_uninspected'}
            incomplete = True
        for index, reason in enumerate(sorted(reasons)):
            ctx.note_review(reason, location, _item=index == 0)
    try:
        import logging
        logging.getLogger('pypdf').disabled = True
        reader = PdfReader(str(src), strict=False)
        if reader.is_encrypted:
            raise _error('pdf_encrypted')
        pages = len(reader.pages)
        if not pages or pages > 10000:
            raise _error('pdf_page_count_limit_or_empty')
        for index, (key, value) in enumerate((reader.metadata or {}).items(), 1):
            inspect(value, _person_metadata_field(key), f'root.k{index}')
        try:
            attachments = len(reader.attachments)
            fields = reader.get_fields() or {}
            for index, field in enumerate(fields.values(), 1):
                for ordinal, key in enumerate(('/V', '/DV', '/T', '/TU'), 1):
                    if key in field:
                        inspect(field[key], field.get('/T', 'free_text') if key in {'/V', '/DV'} else 'schema_label', f'root.b{index}.i{ordinal}')
            if attachments:
                incomplete = True
        except Exception:
            incomplete = True
        for page_index, page in enumerate(reader.pages, 1):
            try:
                image_count += _pdf_image_count(page)
                for annotation in page.get('/Annots', []):
                    annotations += 1
                    annotation = annotation.get_object()
                    for ordinal, key in enumerate(('/Contents', '/T', '/Subj', '/TU', '/V'), 1):
                        if key in annotation:
                            inspect(annotation[key], 'author' if key == '/T' else 'free_text', f'p{page_index}.b{annotations}.i{ordinal}')
                raw = page.extract_text() or ''
                if not raw.strip():
                    incomplete = True
                for line_index, line in enumerate(raw.splitlines(), 1):
                    text_items += 1
                    spans, reasons = _item_spans(line)
                    inspect(line, 'free_text', f'p{page_index}.l{line_index}')
                    if spans and not assess_value(line, 'free_text')[0]:
                        incomplete = True
                        ctx.note_review('unsupported_content_uninspected', f'p{page_index}.l{line_index}')
            except Exception:
                incomplete = True
        # Object streams, scripts, encodings, forms, XMP, nested resources and
        # hidden/deleted glyphs require a PDF-aware editor and complete audit.
        # An extracted-text scan cannot certify that entire retained graph.
        incomplete = True
        ctx.warn('pdf_lossless_masking_unavailable')
        ctx.note_review('unsupported_content_uninspected', 'root')
        with dst.open('xb') as writer, src.open('rb') as reader_stream:
            shutil.copyfileobj(reader_stream, writer)
        return {'source_pages': pages, 'output_pages': pages, 'text_items': text_items,
                'images_retained': image_count, 'attachments_retained': attachments,
                'annotations_retained': annotations, 'incomplete': incomplete,
                'layout_preserved': True, 'source_bytes_preserved': True,
                'format_limitations': ['pdf_lossless_masking_unavailable',
                                       'retained_pdf_objects_not_completely_inspected']}
    except Exception as exc:
        _remove_failed_output(dst)
        raise _safe_failure(exc, 'pdf_processing_failed') from None
