#!/usr/bin/env python3
"""Reopen and fully scan scrubbed artifacts locally; never change readiness status.

This verifies the scrubber's explicit human-PII policy and structural
invariants, not anonymity, source completeness, or Matilda compatibility.
Only neutral file IDs, counts and fixed error codes reach verification.json.
"""
from __future__ import annotations

import argparse
import csv
from decimal import Decimal
import gzip
import hashlib
import io
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import warnings
import zipfile
from xml.etree import ElementTree as ET

from scrub_core import ScrubContext, classify_field, safe_field_name, _GROUPS, _SAFE_LOCATION
from scrub_core import ScrubError
from source_provenance import load_provenance, require_source_match
from input_formats import SUPPORTED_SUFFIXES, admission_error
import scrub_documents as documents
import scrub_structured as structured

_FILE_ID = re.compile(r"file[0-9]{4,}")
_ORDINAL = re.compile(r"field_[0-9]{4,}_*")
_FORMATS = {"csv", "parquet", "xlsx"}
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


class VerifyError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise VerifyError(code)


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            _fail("duplicate_json_keys")
        out[key] = value
    return out


def _constant(_):
    _fail("nonstandard_json_number")


def _json(stream):
    return json.load(stream, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=Decimal)


def _xml(raw):
    if len(raw) > 64 * 1024 * 1024 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        _fail("unsafe_or_oversize_xml")
    return ET.fromstring(raw)


class Verifier:
    def __init__(self, root, report, max_bytes=2 * 1024**3, max_entries=10000, max_depth=12):
        self.root = Path(root).resolve()
        self.max_bytes, self.max_entries, self.max_depth = max_bytes, max_entries, max_depth
        self.total_expanded = 0
        self.records = {}
        self.results = {}
        self.active = set()
        self.ctx = ScrubContext()
        self.checked = 0
        files = report.get("files")
        if not isinstance(files, list) or not files or len(files) > max_entries:
            _fail("invalid_report_inventory")
        for record in files:
            file_id = record.get("file_id") if isinstance(record, dict) else None
            if not isinstance(file_id, str) or not _FILE_ID.fullmatch(file_id) or file_id in self.records:
                _fail("invalid_or_duplicate_file_id")
            self.records[file_id] = record

    def path(self, record):
        artifact = record.get("artifact")
        if not isinstance(artifact, str):
            _fail("artifact_absent")
        parts = PurePosixPath(artifact)
        if parts.is_absolute() or len(parts.parts) != 2 or parts.parts[0] not in {"artifacts", "incomplete"}:
            _fail("unsafe_artifact_reference")
        file_id = record["file_id"]
        name = parts.parts[1]
        if not re.fullmatch(re.escape(file_id) + r"\.[a-z]+(?:\.gz)?", name):
            _fail("nonneutral_artifact_name")
        path = self.root.joinpath(*parts.parts)
        if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
            _fail("artifact_not_regular_file")
        if not path.resolve().is_relative_to(self.root) or path.stat().st_size > self.max_bytes:
            _fail("artifact_path_or_size_limit")
        return path

    def label(self, value, index):
        if not isinstance(value, str):
            _fail("invalid_schema_label")
        if safe_field_name(value, index) != value and not _ORDINAL.fullmatch(value):
            _fail("unsafe_schema_label")

    def value(self, value, field=None, depth=0, prose=False):
        if depth > self.max_depth:
            _fail("value_nesting_limit")
        if value is None or value == "" or prose and value == "null":
            self.checked += 1
            return
        clean = self.ctx.scrub(value, field=field)
        if clean is None or clean != value or type(clean) is not type(value):
            _fail("retained_human_pii_found")
        if isinstance(value, bytes):
            try:
                decoded = value.decode("utf-8")
            except UnicodeError:
                _fail("retained_binary_content_uninspected")
            if self.ctx.scrub(decoded, field=field) != decoded:
                _fail("retained_human_pii_found")
        if isinstance(value, dict):
            for index, (key, item) in enumerate(value.items(), 1):
                self.label(key, index)
                self.value(item, key, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self.value(item, None, depth + 1)
        else:
            self.checked += 1

    def metric(self, record, key, actual, fallback=None):
        metrics = record.get("metrics", {})
        expected = metrics.get(key, metrics.get(fallback) if fallback else None)
        if expected is not None and (type(expected) is not int or expected != actual):
            _fail("reported_dimensions_mismatch")

    def prose(self, value):
        self.checked += 1
        if value in {"", "null"}:
            return
        if documents._scrub_item(value, self.ctx, "") != value:
            _fail("retained_prose_outside_policy")

    def csv(self, path, record):
        layout = structured.csv_layout(path)
        with path.open("r", encoding="utf-8", newline="") as stream:
            if not layout.headers:
                self.metric(record, "output_rows", 0, "rows")
                self.metric(record, "columns", 0)
                return
            reader = csv.reader(stream, delimiter=layout.delimiter, strict=True)
            for row in layout.preamble:
                next(reader)
                for value in row:
                    self.label(value, 1)
            headers = next(reader)
            if len(set(headers)) != len(headers):
                _fail("duplicate_schema_labels")
            for index, header in enumerate(headers, 1):
                self.label(header, index)
            rows = 0
            fields = [layout.field(header) for header in headers]
            for rows, row in enumerate(reader, 1):
                if len(row) != len(headers):
                    _fail("ragged_csv_output")
                for field, value in zip(fields, row):
                    self.value(value, field)
            self.metric(record, "columns", len(headers))
            self.metric(record, "output_rows", rows, "rows")

    def json(self, path, record):
        count = 0
        with path.open("r", encoding="utf-8") as stream:
            if record.get("output_format") in {"jsonl", "ndjson"}:
                for line in stream:
                    if not line.strip():
                        continue
                    if len(line) > 16 * 1024 * 1024:
                        _fail("json_item_size_limit")
                    self.value(json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=Decimal))
                    count += 1
            else:
                if path.stat().st_size > 512 * 1024 * 1024:
                    _fail("json_size_limit")
                value = _json(stream)
                self.value(value)
                count = len(value) if isinstance(value, list) else 1
        self.metric(record, "records", count)

    def parquet(self, path, record):
        import pyarrow.parquet as pq
        parquet = pq.ParquetFile(path)
        schema = parquet.schema_arrow
        def metadata_values(mapping):
            for raw_key, raw_value in (mapping or {}).items():
                if raw_key == b"ARROW:schema":
                    continue
                try:
                    key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
                    value = raw_value.decode("utf-8") if isinstance(raw_value, bytes) else str(raw_value)
                except UnicodeError:
                    _fail("retained_binary_parquet_metadata_uninspected")
                self.value(key, "free_text")
                self.value(value, documents._person_metadata_field(key))
        metadata_values(schema.metadata)
        for field in schema:
            metadata_values(field.metadata)
        metadata_values(parquet.metadata.metadata)
        for index, field in enumerate(schema, 1):
            self.label(field.name, index)
        rows = 0
        for batch in parquet.iter_batches(batch_size=10000):
            rows += batch.num_rows
            for field, column in zip(schema, batch.columns):
                for value in column.to_pylist():
                    self.value(value, field.name)
        self.metric(record, "columns", len(schema))
        self.metric(record, "output_rows", rows, "rows")

    def office(self, path):
        archive = zipfile.ZipFile(path)
        infos = archive.infolist()
        if len(infos) > self.max_entries or sum(i.file_size for i in infos) > self.max_bytes:
            archive.close()
            _fail("office_expansion_limit")
        if len({i.filename for i in infos}) != len(infos) or any(i.flag_bits & 1 for i in infos):
            archive.close()
            _fail("invalid_office_container")
        return archive

    def xml_values(self, root):
        """Check inspectable XML text/attributes; machine identifiers are allowed."""
        for element in root.iter():
            if element.text and element.text.strip():
                self.value(element.text, documents._person_metadata_field(element.tag))
            for attribute, value in element.attrib.items():
                self.value(value, documents._person_metadata_field(attribute))

    def office_xml(self, path):
        """Scan all XML; opaque retained content prevents a passing second pass."""
        opaque = False
        trees = []
        with self.office(path) as archive:
            for info in archive.infolist():
                name = info.filename
                self.value(name, "free_text")
                if name.endswith((".xml", ".rels", ".vml")):
                    root = _xml(archive.read(info))
                    self.xml_values(root)
                    trees.append((name, root))
                elif name.endswith("/"):
                    continue
                else:
                    opaque = True
        if opaque:
            _fail("retained_opaque_office_content_uninspected")
        return trees

    def xlsx(self, path, record):
        from openpyxl import load_workbook
        self.office_xml(path)
        workbook = load_workbook(path, read_only=False, data_only=False, keep_links=False)
        try:
            rows = 0
            for sheet in workbook.worksheets:
                self.value(sheet.title, "free_text")
                for item in (sheet.oddHeader, sheet.oddFooter, sheet.evenHeader, sheet.evenFooter,
                             sheet.firstHeader, sheet.firstFooter):
                    self.value(str(item), "free_text")
                all_rows = sheet.iter_rows()
                first = next(all_rows, ())
                if not first or all(cell.value is None for cell in first):
                    if sheet.max_row > 1:
                        _fail("workbook_schema_missing")
                    continue
                fields = [cell.value for cell in first]
                for index, field in enumerate(fields, 1):
                    if field is not None:
                        self.label(field, index)
                for row in all_rows:
                    rows += 1
                    if len(row) != len(fields):
                        _fail("workbook_column_mismatch")
                    for field, cell in zip(fields, row):
                        # Loading formulas does not evaluate them or follow links.
                        self.value(cell.value, "free_text" if cell.data_type == "f" else field)
                        if cell.comment:
                            self.value(cell.comment.text, "free_text")
                            self.value(cell.comment.author, "author")
                        if cell.hyperlink:
                            for attribute in ("target", "location", "display", "tooltip"):
                                self.value(getattr(cell.hyperlink, attribute, None), "free_text")
            self.metric(record, "sheets", len(workbook.worksheets))
            self.metric(record, "output_rows", rows, "rows")
        finally:
            workbook.close()

    def docx(self, path, record):
        from lxml import etree
        paragraph_count = cell_count = xml_count = 0
        # lxml is used only for ancestors; entity resolution and networking off.
        with self.office(path) as archive:
            for info in archive.infolist():
                self.value(info.filename, "free_text")
                if not info.filename.endswith((".xml", ".rels")):
                    if not info.is_dir():
                        _fail("retained_opaque_office_content_uninspected")
                    continue
                raw = archive.read(info)
                safe_root = _xml(raw)
                self.xml_values(safe_root)
                tree = etree.fromstring(raw, etree.XMLParser(resolve_entities=False, no_network=True))
                xml_count += 1
                for paragraph in tree.iter(_W + "p"):
                    if any(parent.tag == _W + "tc" for parent in paragraph.iterancestors()):
                        continue
                    paragraph_count += 1
                    self.prose(documents._word_item_text(paragraph))
                for table in tree.iter(_W + "tbl"):
                    rows = table.findall(_W + "tr")
                    fields = [documents._word_item_text(cell) for cell in rows[0].findall(_W + "tc")] if rows else []
                    for row_index, row in enumerate(rows):
                        for column, cell in enumerate(row.findall(_W + "tc")):
                            cell_count += 1
                            field = fields[column] if row_index and column < len(fields) else "free_text"
                            self.value(documents._word_item_text(cell), field, prose=True)
        self.metric(record, "paragraphs", paragraph_count)
        self.metric(record, "cells", cell_count)
        self.metric(record, "xml_parts_inspected", xml_count)

    def pdf(self, path, record):
        from pypdf import PdfReader
        reader = PdfReader(path, strict=True)
        if reader.is_encrypted or reader.attachments:
            _fail("pdf_encryption_or_attachments_found")
        root = reader.trailer["/Root"]
        if any(key in root for key in ("/AcroForm", "/Names", "/OpenAction", "/AA", "/Outlines", "/Metadata", "/OCProperties")):
            _fail("pdf_nontext_catalog_objects_found")
        for key, value in (reader.metadata or {}).items():
            value = str(value)
            if key in {"/CreationDate", "/ModDate"}:
                if not re.fullmatch(r"D:[0-9]{14}(?:[Z+\-][0-9']*)?", value):
                    _fail("unexpected_pdf_metadata")
            elif key == "/Producer":
                if value not in {"ReportLab PDF Library - www.reportlab.com", "ReportLab PDF Library - (opensource)"}:
                    _fail("unexpected_pdf_metadata")
            elif key == "/Trapped":
                if value not in {"/False", "/True", "/Unknown"}:
                    _fail("unexpected_pdf_metadata")
            elif key not in {"/Author", "/Creator", "/Title", "/Subject", "/Keywords"} or value not in {"", "anonymous", "unspecified", "untitled"}:
                _fail("unexpected_pdf_metadata")
        for page in reader.pages:
            if page.get("/Annots") or page.get("/AA") or page.get("/Metadata"):
                _fail("pdf_annotations_or_metadata_found")
            resources = page.get("/Resources", {}).get_object()
            if resources.get("/XObject") or documents._pdf_image_count(page):
                _fail("pdf_graphics_or_embedded_objects_found")
            fonts = resources.get("/Font", {}).get_object()
            for font in fonts.values():
                font = font.get_object()
                subtype = font.get("/Subtype")
                base = str(font.get("/BaseFont", "")).lstrip("/").split("+")[-1]
                if not (subtype == "/Type1" and base in {"Helvetica", "Courier"} and not font.get("/FontDescriptor") or
                        subtype == "/TrueType" and base == "BitstreamVeraSans-Roman"):
                    _fail("pdf_unexpected_font_content")
            content = page.get_contents()
            operators = {b"BT", b"ET", b"Q", b"T*", b"TL", b"Tf", b"Tj", b"Tm", b"cm", b"q", b"rg"}
            if content is not None and any(operator not in operators for _, operator in content.operations):
                _fail("pdf_unexpected_content_operator")
            for line in (page.extract_text() or "").splitlines():
                if line == "[Content removed: page has no inspectable text.]" and record.get("privacy_status") != "completed":
                    self.checked += 1
                    continue
                self.prose(line)
        self.metric(record, "output_pages", len(reader.pages))

    def text(self, path, record):
        lines = 0
        with path.open("r", encoding="utf-8", newline="") as stream:
            for lines, line in enumerate(stream, 1):
                if len(line) > 16 * 1024 * 1024 or "\r" in line or "\x00" in line:
                    _fail("text_encoding_or_item_limit")
                self.prose(line.rstrip("\n"))
        self.metric(record, "lines", lines)

    def digest(self, stream):
        digest, size = hashlib.sha256(), 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            self.total_expanded += len(chunk)
            if size > self.max_bytes or self.total_expanded > self.max_bytes * 4:
                _fail("wrapper_expansion_limit")
            digest.update(chunk)
        return digest.digest()

    def child_digest(self, child, depth):
        result = self.file(child["file_id"], depth + 1)
        if not result["policy_scan_passed"]:
            _fail("wrapped_child_verification_failed")
        with self.path(child).open("rb") as stream:
            return self.digest(stream)

    def zip(self, path, record, depth):
        children = [r for r in self.records.values() if r.get("parent_file_id") == record["file_id"]]
        expected = {self.path(r).name: r for r in children if r.get("artifact") and r.get("privacy_status") == "completed"}
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if archive.comment or len(infos) > self.max_entries or len({i.filename for i in infos}) != len(infos):
                _fail("zip_inventory_or_metadata_invalid")
            if {i.filename for i in infos} != set(expected):
                _fail("zip_members_do_not_match_report")
            for member in infos:
                if member.is_dir() or member.flag_bits & 1 or member.comment or member.extra or member.date_time != (1980, 1, 1, 0, 0, 0) or stat.S_ISLNK(member.external_attr >> 16):
                    _fail("zip_source_metadata_or_unsafe_member_found")
                if member.file_size > self.max_bytes or member.compress_size and member.file_size / member.compress_size > 1000:
                    _fail("zip_expansion_limit")
                with archive.open(member) as stream:
                    digest = self.digest(stream)
                if digest != self.child_digest(expected[member.filename], depth):
                    _fail("zip_payload_differs_from_verified_child")
        self.metric(record, "members_processed", len(children))

    def gzip(self, path, record, depth):
        with path.open("rb") as stream:
            header = stream.read(10)
        if len(header) != 10 or header[:3] != b"\x1f\x8b\x08" or header[3] != 0 or header[4:8] != b"\0\0\0\0":
            _fail("gzip_source_header_metadata_found")
        child_id = record.get("metrics", {}).get("payload_file_id")
        child = self.records.get(child_id)
        if not child or child.get("parent_file_id") != record["file_id"]:
            _fail("gzip_payload_record_missing")
        with gzip.open(path, "rb") as stream:
            digest = self.digest(stream)
        if digest != self.child_digest(child, depth):
            _fail("gzip_payload_differs_from_verified_child")

    def file(self, file_id, depth=0):
        if file_id in self.results:
            return self.results[file_id]
        result = {"reopens": False, "policy_scan_passed": False, "values_checked": 0, "errors": []}
        self.results[file_id] = result
        before = self.checked
        try:
            if depth > self.max_depth or file_id in self.active:
                _fail("wrapper_depth_or_cycle_limit")
            self.active.add(file_id)
            record = self.records[file_id]
            path = self.path(record)
            kind = record.get("output_format")
            if kind not in _FORMATS:
                _fail("unsupported_output_format")
            result["reopens"] = True
            if kind in {"csv", "tsv"}:
                self.csv(path, record)
            elif kind in {"json", "jsonl", "ndjson"}:
                self.json(path, record)
            elif kind in {"txt", "log"}:
                self.text(path, record)
            elif kind in {"zip", "gz"}:
                getattr(self, "zip" if kind == "zip" else "gzip")(path, record, depth)
            else:
                getattr(self, kind)(path, record)
            result["policy_scan_passed"] = True
        except VerifyError as exc:
            result["errors"].append(exc.code)
        except ModuleNotFoundError:
            result["reopens"] = False
            result["errors"].append("verification_dependency_unavailable")
        except Exception:
            result["reopens"] = False
            result["errors"].append("artifact_parse_or_verification_failed")
        finally:
            self.active.discard(file_id)
            result["values_checked"] = max(0, self.checked - before)
        return result


# Source comparison deliberately walks the actual pair of artifacts. It never
# obtains its answer by writing a second scrubbed file and comparing outputs.
from collections import Counter, OrderedDict
from itertools import zip_longest
import html
import math
from urllib.parse import unquote
from scrub_core import assess_value, semantic_map_field, detect_pii_spans, mask_text, is_protected_resource_field, normalize_field, span_union
from review_support import validate_decisions, _RETAIN_REASONS
import scrub_ooxml as ooxml

_MISSING = object()
_TEXT_CACHE_MAX_ENTRIES = 8192
_TEXT_CACHE_MAX_CHARACTERS = 1024 * 1024
_TEXT_CACHE_MAX_ITEM_CHARACTERS = 4096
_IDENTITY_FIELD = re.compile(r'owner|creator|createdby|modifiedby|author|contact|username|userid|actor|person|employee|refreshedby', re.I)
_MACHINE = re.compile(r'^(?:arn:|ocid1\.|https?://|[a-z][a-z0-9]*[-_:](?:prod|dev|test|stage|svc|service|vm)|(?:svc|service|system|machine)[-_:.])', re.I)
_ORGANIZATION = re.compile(r'\b(?:team|department|operations|engineering|support|service|system|application|project|organization|corporation|company|inc|llc|group)\b', re.I)
_SHARED_MAILBOX = re.compile(r'^(?:admin|administrator|billing|support|sales|info|contact|help|helpdesk|noreply|no-reply|notifications|alerts|security|operations|devops|root|postmaster|webmaster|service|team)(?:[+_-](?:alerts|team|service|notifications))?$', re.I)


def _identity_field(field):
    # Preserve semantic token boundaries: the 'actor' in 'factor' is not an actor.
    words = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', str(field or ''))
    words = re.findall(r'[a-z0-9]+', words.lower())
    return any(_IDENTITY_FIELD.fullmatch(word) for word in words) or any(
        ''.join(words[i:i+2]) in {'createdby', 'modifiedby', 'refreshedby', 'username', 'userid'}
        for i in range(len(words)-1))


def _decode_candidate(value):
    text = str(value)
    for _ in range(5):
        previous = text
        text = html.unescape(unquote(text))
        text = re.sub(r'\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))',
                      lambda m: chr(int(m.group(1) or m.group(2), 16)), text)
        if text == previous:
            break
    return text


def _broader_candidate(value, field=None):
    """Independent conservative discovery, intentionally broader than policy.

    This is not a second PII classifier: unfamiliar matches require an exact
    context decision, never an automatic removal or an inferred clearance.
    """
    if value is None or value == '' or isinstance(value, bool):
        return False
    text = _decode_candidate(value).strip()
    addresses = re.findall(r'([^\s<>:;,"\[\]()]+)@([^\s<>;,"\[\]()]+)', text)
    if addresses and any(not _SHARED_MAILBOX.fullmatch(local) for local, _ in addresses):
        return True
    if not addresses and re.search(r'@|%(?:25)*40|&#(?:64|x40);|\[at\]|\(at\)', text, re.I):
        return True
    if re.search(r'(?:[/\\](?:Users|home)[/\\])(?!Public(?:[/\\]|$)|Default(?:[/\\]|$)|shared(?:[/\\]|$))[^/\\\s]+', text, re.I):
        return True
    # A protected resource key is an identifier even when its spelling is name-like.
    # Address/profile evidence above remains reviewable inside that identifier.
    if is_protected_resource_field(field):
        return False
    if _identity_field(field):
        if not _MACHINE.search(text) and not _ORGANIZATION.search(text) and not _SHARED_MAILBOX.fullmatch(text):
            return True
    if re.search(r'\b(?:Dr|Mrs|Mr|Ms)\.\s+[A-Z]|\b(?:person|employee|contact|owner|author|user)\s*(?:name|id)?\s*[:=]\s*\S+', text):
        return True
    # Independent prose hints: these identify review candidates, not people.
    if (re.search(r'(?:^|[.!?]\s+)[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\s+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b', text)
            or re.search(r'\b[A-Z][a-z]+\s+(?i:uses?\s+(?:it\s+)?for)\b', text)
            or re.search(r'(?i:service\s+account\s+for)\s+[A-Z][a-z]+\s+(?i:to\s+use)\b', text)
            or re.search(r'(?i:point\s+of\s+contact|department\s+owner)\s*[:=]\s*\S+', text)):
        return True
    words = text.split()
    # A bare name-shaped value outside an identity field is a candidate too.
    if (2 <= len(words) <= 4 and all(w.replace('-', '').replace("'", '').isalpha() and w[0].isupper() and not w.isupper() for w in words)
            and not _ORGANIZATION.search(text)
            and text.casefold() not in {'not applicable', 'no upfront'}
            and str(field) not in {'schema_label', 'filename', 'font_typeface'}):
        return True
    return False


def _span_coverage(spans):
    """Return disjoint covered intervals and codepoint count without expansion."""
    ordered = sorted((span['start'], span['end']) for span in spans)
    merged = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return len(merged), sum(end-start for start,end in merged)


def _equal(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, float) and math.isnan(a) and math.isnan(b):
        return True
    if isinstance(a, dict):
        return len(a) == len(b) and all(_equal(k, l) and _equal(v, w) for (k,v),(l,w) in zip(a.items(),b.items()))
    if isinstance(a, (list,tuple)):
        return len(a) == len(b) and all(_equal(v,w) for v,w in zip(a,b))
    return a == b


class ArtifactComparison:
    def __init__(self, manager, record, decisions):
        self.manager, self.record, self.decisions = manager, record, decisions
        self.result = {'reopens': False, 'policy_scan_passed': True,
                       'source_comparison_passed': False, 'source_provenance_passed': False,
                       'independent_candidate_scan_passed': True,
                       'semantic_mask_review_passed': True, 'unreviewed_mask_items': 0,
                       'values_checked': 0, 'source_values_compared': 0,
                       'independent_candidates': 0, 'unresolved_candidate_count': 0,
                       'unresolved_candidate_locations': [], 'errors': []}
        self.events, self.actions, self.used, self.null_paths = Counter(), 0, set(), set()
        self.span_events = Counter()
        self.masked_spans = self.masked_characters = 0
        self._resource_outputs = {}
        self.result.update(protected_identifiers_compared=0, protected_identifiers_preserved=0,
                           new_resource_key_collisions=0, resource_key_collision_check_passed=True)
        self.comparison_ok = True
        self.candidate_locations = set()
        self.recorded_spans = {}
        self.candidate_stream = None
        self.result['independent_candidate_ledger_complete'] = False
        # Pure classifications only. Source/output equality, exact-coordinate
        # choices, occurrence counts and ledger reconciliation are never cached.
        # Both entry count and retained key characters are bounded; values live
        # only in this artifact's RAM and never enter reports or cache files.
        self._text_assessments = OrderedDict()
        self._text_assessment_characters = 0

    def error(self, code, flag=None):
        if code not in self.result['errors']:
            self.result['errors'].append(code)
        if flag:
            self.result[flag] = False
        else:
            self.comparison_ok = False

    def decision(self, loc):
        choice = self.decisions.get(loc)
        if choice:
            self.used.add(loc)
        return choice

    def _text_cache_key(self, kind, value, field, prose=False):
        if type(value) is not str or field is not None and type(field) is not str:
            return None
        if len(value) + len(field or '') > _TEXT_CACHE_MAX_ITEM_CHARACTERS:
            return None
        return kind, type(value), value, type(field), field, prose

    def _text_cache_get(self, key):
        if key is None:
            return _MISSING
        result = self._text_assessments.get(key, _MISSING)
        if result is not _MISSING:
            self._text_assessments.move_to_end(key)
        return result

    def _text_cache_put(self, key, result):
        if key is None:
            return
        weight = len(key[2]) + len(key[4] or '')
        while self._text_assessments and (
                len(self._text_assessments) >= _TEXT_CACHE_MAX_ENTRIES
                or self._text_assessment_characters + weight > _TEXT_CACHE_MAX_CHARACTERS):
            old, _ = self._text_assessments.popitem(last=False)
            self._text_assessment_characters -= len(old[2]) + len(old[4] or '')
        self._text_assessments[key] = result
        self._text_assessment_characters += weight

    def categories(self, value, field=None, prose=False):
        key = self._text_cache_key('categories', value, field, prose)
        cached = self._text_cache_get(key)
        if cached is not _MISSING:
            return cached
        found, reviews = self._uncached_categories(value, field, prose)
        result = frozenset(found), frozenset(reviews)
        self._text_cache_put(key, result)
        return result

    def broader_candidate(self, value, field=None):
        key = self._text_cache_key('broader_candidate', value, field)
        cached = self._text_cache_get(key)
        if cached is not _MISSING:
            return cached
        result = _broader_candidate(value, field)
        self._text_cache_put(key, result)
        return result

    def _uncached_categories(self, value, field=None, prose=False):
        if isinstance(value, bytes):
            try:
                value = value.decode('utf-8')
            except UnicodeError:
                return set(), {'uninspectable_binary'}
        if isinstance(value, (dict,list,tuple)):
            # Container nodes have no removable representation; every retained
            # key and scalar is independently inspected by scan/pair below.
            return set(), set()
        found, reviews = assess_value(value, field)
        _, span_reviews = detect_pii_spans(value, field=field)
        reviews = set(reviews) | set(span_reviews)
        if prose and isinstance(value, str):
            match = documents._KEY_VALUE.match(value)
            if match:
                cats, candidates = assess_value(match.group(2), match.group(1))
                found = set(found) | cats
                reviews = set(reviews) | candidates
        return set(found), set(reviews)

    def scan(self, value, field, loc, prose=False, decision=None, proven_spans=None, protected_by=None):
        self.result['values_checked'] += 1
        if value is None or value == '':
            return
        choice = decision if decision is not None else self.decision(loc)
        if is_protected_resource_field(field):
            protected_by = field
        if isinstance(value, (dict,list,tuple)):
            if choice:
                self.error('review_decision_requires_scalar')
                self.error('review_decision_requires_scalar', 'independent_candidate_scan_passed')
            if isinstance(value,dict):
                for i,(key,child) in enumerate(value.items(),1):
                    child_loc = f'{loc}.k{i}'
                    self.scan(key, 'schema_label', child_loc)
                    hint = ('personname' if classify_field(field)=='personal_container' and normalize_field(key)=='name'
                            else semantic_map_field(key))
                    self.scan(child,hint,child_loc,protected_by=protected_by)
            else:
                for i,child in enumerate(value,1):
                    self.scan(child,field,f'{loc}.i{i}',protected_by=protected_by)
            return
        if proven_spans and isinstance(value, bytes):
            try:
                value = value.decode('utf-8')
            except UnicodeError:
                self.error('retained_binary_content_uninspected', 'independent_candidate_scan_passed')
                return
        if proven_spans and isinstance(value, str):
            # These positions have already been proved against the original.
            # The exemption is positional, never an output-only X heuristic.
            chars = list(value)
            for span in proven_spans:
                start, end = span['start'], span['end']
                if not (0 <= start < end <= len(chars)) or value[start:end] != 'X' * (end-start):
                    self.error('mask_range_not_proven')
                    return
                chars[start:end] = ' ' * (end-start)
            value = ''.join(chars)
            if not value.strip():
                return
        if isinstance(value, bytes):
            try:
                value = value.decode('utf-8')
            except UnicodeError:
                self.error('retained_binary_content_uninspected', 'policy_scan_passed')
                self.error('retained_binary_content_uninspected', 'independent_candidate_scan_passed')
                return
        found, reviews = self.categories(value, field, prose)
        found, reviews = set(found), set(reviews)
        if protected_by:
            protected_found, protected_reviews = self.categories(value, protected_by, prose)
            if found or 'type_masking_conflict' in reviews:
                reviews.add('protected_identifier_contains_pii')
            elif reviews:
                reviews.add('protected_identifier_review')
            found.update(protected_found)
            reviews.update(protected_reviews)
        blocking = {'protected_identifier_contains_pii','schema_label_contains_pii',
                    'type_masking_conflict','formula_pii_requires_review','unsupported_content_uninspected'}
        resolved = bool(choice and choice['action'] == 'retain' and not (reviews & blocking))
        if (choice and choice['action']=='mask' and proven_spans and not found
                and not (reviews & blocking) and choice.get('residual_reason_code') in _RETAIN_REASONS):
            # Exact source-derived mask positions scope this decision to the
            # remaining scalar text. Confirmed PII is never waived here.
            resolved = True
        if found and not resolved:
            self.error('retained_human_pii_found', 'policy_scan_passed')
        candidate = bool(found or reviews or self.broader_candidate(value, field))
        if candidate:
            if loc not in self.candidate_locations:
                self.result['independent_candidates'] += 1
                self.candidate_locations.add(loc)
                if self.candidate_stream is not None:
                    self.candidate_stream.write(json.dumps({'location':loc, 'reason':'independent_candidate', 'resolved':resolved, 'count':1}) + '\n')
                if not resolved:
                    self.result['unresolved_candidate_count'] += 1
                    if len(self.result['unresolved_candidate_locations']) < 100:
                        self.result['unresolved_candidate_locations'].append(loc)
            if not resolved:
                self.error('independent_candidate_unresolved', 'independent_candidate_scan_passed')
    def load_mask_ledger(self):
        reference = self.record.get('removal_location_index')
        if not isinstance(reference, str):
            self.error('removal_location_ledger_missing'); return
        ledger = self.manager.safe_reference(reference)
        seen = set()
        with ledger.open(encoding='utf-8') as stream:
            for line in stream:
                if len(line) > 65536: _fail('removal_ledger_item_size_limit')
                item = json.loads(line, object_pairs_hook=_pairs)
                category, loc = item.get('category'), item.get('location')
                if (category not in _GROUPS or not isinstance(loc,str) or not _SAFE_LOCATION.fullmatch(loc)
                        or type(item.get('count')) is not int or item['count'] != 1
                        or (loc,category) in seen):
                    _fail('invalid_removal_location_event')
                seen.add((loc,category))
                spans = item.get('spans')
                if not isinstance(spans,list) or not spans: _fail('mask_span_ledger_missing')
                previous = -1
                for span in spans:
                    if (not isinstance(span,dict) or set(span)!={'start','end'}
                            or type(span['start']) is not int or type(span['end']) is not int
                            or not 0 <= span['start'] < span['end'] <= self.manager.max_bytes
                            or span['start'] <= previous):
                        _fail('invalid_mask_span_event')
                    previous = span['end']
                    self.recorded_spans.setdefault(loc,[]).append(dict(span,category=category))
                if item.get('masked_characters') != _span_coverage(spans)[1]:
                    _fail('mask_span_character_count_mismatch')

    @staticmethod
    def span_signature(spans):
        categories = {span['category'] for span in spans}
        return tuple((cat,tuple(span_union([s for s in spans if s['category']==cat]))) for cat in sorted(categories))

    def mask_spec(self, source, field=None, prose=False, choice=None, loc=None):
        """Reconstruct expected edits from recorded/reviewed offsets only.

        No masking detector or scrub transform decides the expected output.
        The ledger proves mechanical edits; separate exact decisions attest
        that those particular spans were reviewed as human information.
        """
        recorded = self.recorded_spans.get(loc, ())
        explicit = choice.get('spans', ()) if choice and choice['action']=='mask' else ()
        spans = tuple(dict(item) for item in (recorded or explicit))
        if choice and choice['action']=='retain' and spans:
            self.error('retain_decision_conflicts_with_mask_ledger')
        if recorded and explicit and self.span_signature(recorded) != self.span_signature(explicit):
            self.error('review_mask_spans_do_not_match_ledger')
        if prose:
            match = documents._KEY_VALUE.match(source) if isinstance(source,str) else None
            if match and is_protected_resource_field(match.group(1)): field=match.group(1)
        if spans and (not isinstance(source,str) or is_protected_resource_field(field)
                      or field in {'schema_label','sheet_name','xml_schema_label'}):
            self.error('review_mask_conflicts_with_preservation')
            return source, (), frozenset(), frozenset()
        if not spans: return source, (), frozenset(), frozenset()
        chars = list(source)
        for span in spans:
            if (set(span)!={'start','end','category'} or span['category'] not in _GROUPS
                    or type(span['start']) is not int or type(span['end']) is not int
                    or not 0 <= span['start'] < span['end'] <= len(source)):
                self.error('invalid_recorded_mask_span')
                return source, (), frozenset(), frozenset()
            chars[span['start']:span['end']] = 'X'*(span['end']-span['start'])
        return ''.join(chars), spans, frozenset(s['category'] for s in spans), frozenset()

    def changed(self, source, field, loc, prose=False, categories=None, spans=None):
        choice = self.decision(loc)
        expected, found_spans, found, _ = self.mask_spec(source, field, prose, choice, loc)
        spans = found_spans if spans is None else spans
        if categories is not None: found = set(categories)
        if not found or not spans or expected == source:
            self.error('unjustified_source_value_change'); return
        if not (choice and choice['action']=='mask' and
                self.span_signature(choice.get('spans',())) == self.span_signature(spans)):
            self.result['unreviewed_mask_items'] += 1
            self.error('changed_mask_requires_explicit_context_review','semantic_mask_review_passed')
        for category in found:
            self.events[(loc, category)] += 1
            for start,end in span_union([span for span in spans if span['category']==category]):
                self.span_events[(loc,start,end,category)] += 1
        count, characters = _span_coverage(spans)
        self.actions += 1
        self.masked_characters += characters
        self.masked_spans += count

    def protected_identity(self, source, output, field):
        if not is_protected_resource_field(field) or isinstance(source, (dict, list, tuple)):
            return
        self.result['protected_identifiers_compared'] += 1
        if _equal(source, output):
            self.result['protected_identifiers_preserved'] += 1
        else:
            self.error('protected_resource_identifier_changed')
            self.result['resource_key_collision_check_passed'] = False
        # Store digests, never source identifiers. Repeated original IDs are
        # permitted; two distinct original IDs mapping to one output are not.
        old = hashlib.sha256((type(source).__name__ + ':' + repr(source)).encode()).digest()
        new = hashlib.sha256((type(output).__name__ + ':' + repr(output)).encode()).digest()
        key = (str(field), new)
        previous = self._resource_outputs.setdefault(key, old)
        if previous != old:
            self.result['new_resource_key_collisions'] += 1
            self.result['resource_key_collision_check_passed'] = False
            self.error('new_resource_key_collision')

    def pair(self, source, output, field, loc, depth=0, prose=False, arrow_type=None, path=(), protected_by=None):
        if depth > self.manager.max_depth:
            _fail('value_nesting_limit')
        self.result['source_values_compared'] += 1
        choice = self.decision(loc)
        if is_protected_resource_field(field):
            protected_by = field
        self.protected_identity(source, output, protected_by or field)
        if choice and isinstance(source,(dict,list,tuple)):
            self.error('review_decision_requires_scalar')
            self.error('review_decision_requires_scalar','independent_candidate_scan_passed')
            choice = None
        if source is None or source == '':
            if not _equal(source, output):
                self.error('source_null_or_empty_value_changed')
            return
        if isinstance(source, dict) and isinstance(output, dict):
            if len(source) != len(output):
                self.error('source_object_inventory_changed')
                return
            for i, ((key, old), (new_key, new)) in enumerate(zip(source.items(), output.items()), 1):
                child_loc = f'{loc}.k{i}'
                child_type = None
                if arrow_type is not None:
                    import pyarrow as pa
                    if pa.types.is_struct(arrow_type):
                        child_type = arrow_type[i-1].type
                    else:
                        self.schema_label(key, new_key, i, child_loc)
                else:
                    self.schema_label(key, new_key, i, child_loc)
                child_field = ('personname' if classify_field(field) == 'personal_container' and normalize_field(key) == 'name' else
                               semantic_map_field(key) if arrow_type is None else key)
                self.pair(old, new, child_field, child_loc, depth + 1,
                          arrow_type=child_type, path=path+(i-1,),protected_by=protected_by)
            return
        if arrow_type is not None:
            import pyarrow as pa
            if pa.types.is_map(arrow_type) and isinstance(source, list) and isinstance(output, list):
                if len(source) != len(output):
                    self.error('source_map_entries_changed')
                    return
                for i, ((key, old), (new_key, new)) in enumerate(zip(source, output), 1):
                    if not _equal(key, new_key):
                        self.error('source_map_key_changed')
                    child_loc = f'{loc}.k{i}'
                    self.scan(key, 'schema_label', child_loc+'.k1')
                    try:
                        semantic_key = key.decode('utf-8') if isinstance(key,bytes) else key
                    except UnicodeError:
                        self.error('retained_binary_parquet_content_uninspected','independent_candidate_scan_passed')
                        semantic_key = None
                    child_field = ('personname' if classify_field(field) == 'personal_container' and normalize_field(semantic_key) == 'name' else semantic_map_field(semantic_key))
                    self.pair(old, new, child_field, child_loc, depth+1,
                              arrow_type=arrow_type.item_type, path=path+('item',),protected_by=protected_by)
                return
        if isinstance(source, (list, tuple)) and type(source) is type(output):
            if len(source) != len(output):
                self.error('source_sequence_length_changed')
                return
            child_type = getattr(arrow_type, 'value_type', None)
            for i, (old, new) in enumerate(zip(source, output), 1):
                self.pair(old, new, field, f'{loc}.i{i}', depth+1, arrow_type=child_type, path=path+('item',),protected_by=protected_by)
            return
        if protected_by:
            expected, spans, found, reviews = source, (), set(), set()
        else:
            expected, spans, found, reviews = self.mask_spec(source, field, prose, choice, loc)
        if choice and choice['action'] == 'mask' and (protected_by or field == 'schema_label' or not isinstance(source,str)):
            self.error('review_mask_conflicts_with_preservation')
        if not _equal(expected, output):
            self.error('expected_x_mask_mismatch' if expected != source else 'retained_source_value_changed')
            if choice and choice['action'] == 'mask':
                self.error('review_mask_decision_not_applied')
            if not _equal(source, output) and expected == source:
                self.error('unjustified_source_value_change')
                self.error('source_changes_do_not_match_removal_ledger')
            self.scan(output, field, loc, prose, decision=choice,protected_by=protected_by)
            return
        if not _equal(source, output):
            self.changed(source, field, loc, prose, categories=found, spans=spans)
        self.scan(output, field, loc, prose, decision=choice, proven_spans=spans,protected_by=protected_by)

    def schema_label(self, source, output, index, loc):
        self.result['source_values_compared'] += 1
        if not _equal(source, output):
            self.error('schema_label_changed_unexpectedly')
        self.scan(output, 'schema_label', loc)

    def metric(self, key, actual, fallback=None):
        metrics = self.record.get('metrics', {})
        expected = metrics.get(key, metrics.get(fallback) if fallback else None)
        if expected is not None and (type(expected) is not int or expected != actual):
            self.error('reported_dimensions_mismatch')

    def csv(self, source, output):
        layout = structured.csv_layout(source or output)
        headers, delimiter = layout.headers, layout.delimiter
        actual_layout = structured.csv_layout(output, delimiter)
        with output.open('r', encoding='utf-8', newline='') as out:
            reader = csv.reader(out, delimiter=delimiter, strict=True)
            actual_preamble = [next(reader, []) for _ in actual_layout.preamble]
            actual_headers = next(reader, [])
            if source is None:
                for row_index, row in enumerate(actual_preamble, 1):
                    for i, value in enumerate(row, 1):
                        self.scan(value, 'schema_label', f'r{row_index}.c{i}')
                for i, field in enumerate(actual_headers, 1):
                    self.scan(field, 'schema_label', f'r{actual_layout.header_row}.c{i}')
                fields = [actual_layout.field(header) for header in actual_headers]
                for row_index, row in enumerate(reader, actual_layout.header_row + 1):
                    if len(actual_headers) == 1 and row == []:
                        row = ['']
                    if len(row) != len(actual_headers):
                        _fail('ragged_csv_output')
                    for i, (field, item) in enumerate(zip(fields, row), 1):
                        self.scan(item, field, f'r{row_index}.c{i}')
                return
            if len(layout.preamble) != len(actual_preamble):
                _fail('csv_preamble_structure_changed')
            for row_index, (old_row, new_row) in enumerate(zip(layout.preamble, actual_preamble), 1):
                if len(old_row) != len(new_row):
                    _fail('csv_preamble_structure_changed')
                for i, (old, new) in enumerate(zip(old_row, new_row), 1):
                    self.pair(old, new, 'schema_label', f'r{row_index}.c{i}')
            if len(headers) != len(actual_headers):
                _fail('source_column_count_changed')
            for i, (old, new) in enumerate(zip(headers, actual_headers), 1):
                self.schema_label(old, new, i, f'r{layout.header_row}.c{i}')
            rows = 0
            fields = [layout.field(header) for header in headers]
            with source.open('r', encoding=structured._text_encoding(source), newline='') as inp:
                original = csv.reader(inp, delimiter=delimiter, strict=True)
                for _ in range(layout.header_row):next(original, None)
                for rows, (old, new) in enumerate(zip_longest(original, reader, fillvalue=_MISSING), 1):
                    if old is _MISSING or new is _MISSING:
                        _fail('source_row_count_changed')
                    # Arrow serializes a one-column null row as an empty
                    # physical line; it is still an actual cleared record.
                    if len(headers) == 1 and new == []:
                        new = ['']
                    if len(old) != len(headers) or len(new) != len(headers):
                        _fail('ragged_csv_data')
                    for i, (field, a, b) in enumerate(zip(fields, old, new), 1):
                        self.pair(a, b, field, f'r{rows+layout.header_row}.c{i}')
            self.metric('columns', len(headers))
            self.metric('output_rows', rows, 'rows')
            self.metric('header_row', layout.header_row)
            self.metric('preamble_rows', len(layout.preamble))

    def json(self, source, output):
        kind = self.record['output_format']
        def records(path):
            with path.open('r', encoding=structured._text_encoding(path)) as stream:
                if kind in {'jsonl', 'ndjson'}:
                    for line in stream:
                        if len(line) > 16 * 1024**2:
                            _fail('json_item_size_limit')
                        if line.strip():
                            yield json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=Decimal)
                else:
                    if path.stat().st_size > 512 * 1024**2:
                        _fail('json_size_limit')
                    yield _json(stream)
        if source is None:
            for i, value in enumerate(records(output), 1):
                self.scan(value, None, 'root' if kind == 'json' else f'r{i}')
            return
        count = 0
        for i, (old, new) in enumerate(zip_longest(records(source), records(output), fillvalue=_MISSING), 1):
            if old is _MISSING or new is _MISSING:
                _fail('source_record_count_changed')
            self.pair(old, new, None, 'root' if kind == 'json' else f'r{i}')
            count += len(old) if kind == 'json' and isinstance(old, list) else 1
        self.metric('records', count)

    def text(self, source, output):
        encoding = structured._text_encoding(source or output)
        def bom(path):
            with path.open('rb') as stream:
                prefix = stream.read(3)
            return next((item for item in (b'\xef\xbb\xbf',b'\xff\xfe',b'\xfe\xff') if prefix.startswith(item)), b'')
        if source is not None and (structured._text_encoding(output) != encoding or bom(source) != bom(output)):
            self.error('text_encoding_or_bom_changed')
        def split(line):
            match = re.search(r'(\r\n|\r|\n)$',line)
            ending = match.group(0) if match else ''
            return (line[:-len(ending)] if ending else line), ending
        with output.open('r', encoding=encoding, newline='') as out:
            if source is None:
                for i, value in enumerate(out, 1):
                    self.scan(split(value)[0], 'free_text', f'l{i}', prose=True)
                return
            lines = 0
            with source.open('r', encoding=encoding, newline='') as inp:
                for lines, (old, new) in enumerate(zip_longest(inp, out, fillvalue=_MISSING), 1):
                    if old is _MISSING or new is _MISSING:
                        _fail('source_line_count_changed')
                    old_body, old_ending = split(old)
                    new_body, new_ending = split(new)
                    if old_ending != new_ending:
                        self.error('text_structure_changed')
                    self.pair(old_body, new_body, 'free_text', f'l{lines}', prose=True)
            self.metric('lines', lines)

    def metadata(self, source, output, loc, *, footer=False):
        # ARROW:schema is an encoded envelope only in the physical footer. A
        # same-named key inside schema/field metadata is ordinary content.
        source = {k:v for k,v in (source or {}).items() if not footer or k != b'ARROW:schema'}
        output = {k:v for k,v in (output or {}).items() if not footer or k != b'ARROW:schema'}
        if set(output) - set(source):
            self.error('parquet_metadata_added')
        for i, (key, old) in enumerate(source.items(), 1):
            child = f'{loc}.k{i}'
            try:
                label = key.decode('utf-8') if isinstance(key, bytes) else str(key)
                value = old.decode('utf-8') if isinstance(old, bytes) else str(old)
            except UnicodeError:
                self.error('retained_binary_parquet_metadata_uninspected', 'independent_candidate_scan_passed')
                if key not in output or old != output[key]:
                    self.error('uninspectable_parquet_metadata_changed')
                continue
            if key not in output:
                self.error('parquet_metadata_key_removed')
                continue
            self.scan(label, 'schema_label', child+'.k1')
            try:
                new_value = output[key].decode('utf-8') if isinstance(output[key], bytes) else str(output[key])
            except UnicodeError:
                self.error('retained_binary_parquet_metadata_uninspected', 'independent_candidate_scan_passed')
                continue
            self.pair(value, new_value, label, child)

    def arrow_field(self, source, output, index, loc='root', path=()):
        import pyarrow as pa
        here = f'{loc}.c{index}'
        self.schema_label(source.name, output.name, index, here)
        self.metadata(source.metadata, output.metadata, here)
        if source.nullable != output.nullable:
            self.error('parquet_field_nullability_changed')
        a, b = source.type, output.type
        if pa.types.is_struct(a) and pa.types.is_struct(b):
            if len(a) != len(b):
                self.error('parquet_struct_fields_changed'); return
            for i, (old, new) in enumerate(zip(a,b),1):
                self.arrow_field(old,new,i,here,path+(i-1,))
        elif (pa.types.is_list(a) and pa.types.is_list(b) or pa.types.is_large_list(a) and pa.types.is_large_list(b)
              or pa.types.is_fixed_size_list(a) and pa.types.is_fixed_size_list(b)):
            if getattr(a,'list_size',None) != getattr(b,'list_size',None):
                self.error('parquet_list_size_changed')
            self.arrow_field(a.value_field,b.value_field,1,here,path+('item',))
        elif pa.types.is_map(a) and pa.types.is_map(b):
            if a.keys_sorted != b.keys_sorted:
                self.error('parquet_map_order_contract_changed')
            self.arrow_field(a.key_field,b.key_field,1,here,path+('key',))
            self.arrow_field(a.item_field,b.item_field,2,here,path+('item',))
        elif not a.equals(b):
            self.error('parquet_field_type_changed')
        if isinstance(a, pa.ExtensionType):
            self.error('retained_extension_parquet_content_uninspected', 'independent_candidate_scan_passed')

    def parquet(self, source, output):
        import pyarrow.parquet as pq
        actual = pq.ParquetFile(output)
        if source is None:
            for batch in actual.iter_batches(batch_size=8192):
                for i, field in enumerate(actual.schema_arrow):
                    for value in batch.column(i).to_pylist():
                        self.scan(value,field.name,'root')
            self.error('parquet_source_required_for_coordinate_scan', 'independent_candidate_scan_passed')
            return
        original = pq.ParquetFile(source)
        old_schema, new_schema = original.schema_arrow, actual.schema_arrow
        if len(old_schema) != len(new_schema):
            _fail('source_column_count_changed')
        cursor = structured.BatchCursor(actual.iter_batches(batch_size=8192))
        rows = 0
        for batch in original.iter_batches(batch_size=8192):
            aligned = cursor.take(batch.num_rows)
            for column, field in enumerate(old_schema,1):
                for offset, (old, new) in enumerate(zip(batch.column(column-1).to_pylist(), aligned.column(column-1).to_pylist()),1):
                    self.pair(old,new,field.name,f'r{rows+offset}.c{column}',arrow_type=field.type,path=(column,))
            rows += batch.num_rows
        cursor.ensure_end()
        source_footer = original.metadata.metadata or {}
        output_footer = actual.metadata.metadata or {}
        embedded_schema = b'ARROW:schema' in source_footer
        if embedded_schema != (b'ARROW:schema' in output_footer):
            self.error('parquet_arrow_schema_presence_changed')
        # Without an embedded schema, schema_arrow.metadata is only an alias of
        # the footer. Inspect/count the physical metadata once, at footer.kN.
        if embedded_schema:
            self.metadata(old_schema.metadata, new_schema.metadata, 'root')
        # The physical footer can contain keys/values absent from or different
        # from the serialized Arrow schema. Compare both independently; reading
        # schema_arrow alone can silently miss footer losses and personal data.
        self.metadata(source_footer, output_footer, 'footer', footer=True)
        for i,(old,new) in enumerate(zip(old_schema,new_schema),1):
            self.arrow_field(old,new,i,path=(i,))
        self.metric('columns',len(old_schema)); self.metric('output_rows',rows,'rows')

    def office(self, source, output, kind):
        proven = {}
        if source is not None:
            expected_package = ooxml.Package(source,kind)
            owner = self
            class ExpectedAnalysis(ooxml.Analysis):
                def expected_spans(self,value,field,location):
                    return owner.mask_spec(value,field,kind=='docx',owner.decision(location),location)[1], set()
                def apply(self,value,field,location,descriptor,kind='metadata',spans=None,
                          cache_payload=False,immutable=False):
                    # Share structure/locator traversal only. No detector can
                    # choose a mask in this reconstruction of expected bytes.
                    if descriptor.get('attribute') == 'typeface':
                        field = 'font_typeface'
                    choice = owner.decision(location)
                    wanted, exact, _, _ = owner.mask_spec(value,field,False,choice,location)
                    if immutable and wanted != value:
                        owner.error('review_mask_conflicts_with_preservation')
                        wanted, exact = value, ()
                    owner.pair(value,wanted,field,location,prose=expected_package.kind=='docx')
                    if exact and wanted != value:
                        proven[location] = exact
                    return wanted
            analysis = ExpectedAnalysis(ScrubContext(review_decisions=self.decisions),set())
            ooxml._transform(expected_package,analysis.ctx,authors=set(),analysis=analysis)
            actual = ooxml.Package(output,kind)
            wanted=set(expected_package.raw)
            properties=('date_time','compress_type','external_attr','internal_attr','create_system','extra')
            exact = (wanted==set(actual.raw)
                and expected_package.archive_comment==actual.archive_comment
                and all(expected_package.bytes_for(n)==actual.raw[n]
                        and expected_package.info[n].comment==actual.info[n].comment
                        and all(getattr(expected_package.info[n],k)==getattr(actual.info[n],k) for k in properties)
                        for n in wanted))
            if not exact:
                self.error('ooxml_unexpected_source_output_difference')
                proven = {}
            self.result['source_parts_compared']=len(expected_package.raw)
            if analysis.opaque_parts:
                self.error('retained_opaque_ooxml_content_uninspected','independent_candidate_scan_passed')
        package = ooxml.Package(output,kind)
        owner = self
        class Collector(ooxml.Analysis):
            def expected_spans(self,value,field,location):
                return (), set()
            def apply(self,value,field,location,descriptor,kind='metadata',spans=None,
                      cache_payload=False,immutable=False):
                choice = owner.decision(location)
                owner.scan(value,field,location,prose=package.kind=='docx',decision=choice,
                           proven_spans=proven.get(location))
                return value
        collector = Collector(ScrubContext(),set())
        skip = ooxml._xlsx_cells(package,collector) if kind=='xlsx' else ooxml._word_items(package,collector)
        # Shared strings referenced by cells were inspected with their actual
        # column and exact cell decision. Orphaned storage is independently
        # scanned at its own XML coordinates, even if the detector missed it.
        if kind == 'xlsx' and 'xl/sharedStrings.xml' in package.trees:
            referenced = set()
            for tree in package.trees.values():
                for cell in tree.getroot().iter(ooxml.S+'c'):
                    if cell.get('t') == 's':
                        value = cell.find(ooxml.S+'v')
                        if value is not None and value.text:
                            referenced.add(int(value.text))
            for index,item in enumerate(package.trees['xl/sharedStrings.xml'].getroot().findall(ooxml.S+'si')):
                if index not in referenced:
                    skip.difference_update(item.iter())
        source_package = ooxml.Package(source,kind) if source is not None else None
        for p,(part,tree) in enumerate(package.trees.items(),1):
            original_tree = source_package.trees.get(part) if source_package else None
            ordinals = {original_tree.getpath(n):i for i,n in enumerate(ooxml._nodes(original_tree),1)} if original_tree is not None else {}
            for index,node in enumerate(ooxml._nodes(tree),1):
                for ns_index,uri in enumerate(getattr(node,'nsmap',{}).values(),1000):
                    self.scan(uri,'schema_label',f'p{p}.k{index}.i{ns_index}')
                ordinal = ordinals.get(tree.getpath(node),index)
                loc=f'p{p}.k{ordinal}'
                if node not in skip:
                    self.scan(node.text,ooxml._xml_field(node,part),loc+'.i1',proven_spans=proven.get(loc+'.i1'))
                self.scan(node.tail,'free_text',loc+'.i2',proven_spans=proven.get(loc+'.i2'))
                for i,(key,value) in enumerate(node.attrib.items(),3):
                    context = ooxml._xml_field(node,part,key)
                    if (key == 'typeface' and node.tag in {
                            '{http://schemas.openxmlformats.org/drawingml/2006/main}latin',
                            '{http://schemas.openxmlformats.org/drawingml/2006/main}ea',
                            '{http://schemas.openxmlformats.org/drawingml/2006/main}cs',
                            '{http://schemas.openxmlformats.org/drawingml/2006/main}font'}):
                        context = 'font_typeface'
                    self.scan(value,context,loc+f'.i{i}',proven_spans=proven.get(loc+f'.i{i}'))
        # Package comments and member names are content surfaces too.
        self.scan(package.archive_comment,'free_text','root.i1',proven_spans=proven.get('root.i1'))
        for i,(name,info) in enumerate(package.info.items(),1):
            self.scan(name,'filename',f'root.k{i}.i1',proven_spans=proven.get(f'root.k{i}.i1'))
            self.scan(info.comment,'free_text',f'root.k{i}.i2',proven_spans=proven.get(f'root.k{i}.i2'))
        # review_counts includes resolved history; only outstanding questions
        # can block a reviewed workbook.
        if any(name not in package.trees and not package.info[name].is_dir() for name in package.raw):
            self.error('retained_opaque_ooxml_content_uninspected','independent_candidate_scan_passed')

    def filename(self, source, output):
        if source is None or self.record.get('parent_file_id'):
            return
        choice = self.decision('filename')
        masked, spans, found, _ = self.mask_spec(source.stem, 'filename', choice=choice, loc='filename')
        expected = masked + '_SCRUBBED' + source.suffix
        if output.name != expected:
            self.error('output_basename_does_not_match_source')
            return
        if masked != source.stem:
            self.changed(source.stem, 'filename', 'filename', categories=found, spans=spans)
        self.scan(masked, 'filename', 'filename', decision=choice, proven_spans=spans)

    def reconcile(self):
        reference=self.record.get('removal_location_index')
        if not isinstance(reference,str):
            self.error('removal_location_ledger_missing'); return
        ledger=self.manager.safe_reference(reference)
        actual, actual_spans = Counter(), Counter()
        with ledger.open('r',encoding='utf-8') as stream:
            for line in stream:
                if len(line)>65536:
                    _fail('removal_ledger_item_size_limit')
                item=json.loads(line,object_pairs_hook=_pairs)
                category,loc,count=item.get('category'),item.get('location'),item.get('count')
                if not isinstance(category,str) or not isinstance(loc,str) or type(count) is not int or count != 1:
                    _fail('invalid_removal_location_event')
                if category.startswith('human_'):
                    actual[(loc,category)]+=count
                    spans = item.get('spans')
                    if not isinstance(spans,list) or not spans:
                        self.error('mask_span_ledger_missing')
                        continue
                    for span in spans:
                        if (not isinstance(span,dict) or set(span) != {'start','end'}
                                or type(span['start']) is not int or type(span['end']) is not int
                                or not 0 <= span['start'] < span['end'] <= self.manager.max_bytes):
                            _fail('invalid_mask_span_event')
                        actual_spans[(loc,span['start'],span['end'],category)] += 1
                    if item.get('masked_characters') != _span_coverage(spans)[1]:
                        self.error('mask_span_character_count_mismatch')
        expected=Counter({key:value for key,value in self.events.items() if key[1].startswith('human_')})
        if actual != expected:
            self.error('source_changes_do_not_match_removal_ledger')
        if actual_spans != self.span_events:
            self.error('source_changes_do_not_match_mask_span_ledger')
        counts=Counter()
        for (_,category),count in expected.items():
            counts[category]+=count
        for reported in (self.record.get('counts_by_category',{}),self.record.get('context_review',{}).get('categories',{})):
            human={k:v for k,v in reported.items() if k.startswith('human_')}
            if any(type(v) is not int or v<0 for v in human.values()) or dict(counts)!=human:
                self.error('source_changes_do_not_match_reported_counts')
        context=self.record.get('context_review',{})
        if context.get('removal_location_coverage_complete') is False:
            self.error('removal_location_coverage_incomplete')
        if context.get('removed_items') != self.actions:
            self.error('source_changes_do_not_match_whole_item_actions')
        for name, value in (('masked_items',self.actions),('masked_spans',self.masked_spans),
                            ('masked_characters',self.masked_characters)):
            if type(context.get(name)) is not int or context[name] != value:
                self.error('source_changes_do_not_match_' + name)
        self.result.update(masked_items_verified=self.actions,
                           masked_spans_verified=self.masked_spans,
                           masked_characters_verified=self.masked_characters)


class SourceVerifier(Verifier):
    def __init__(self,root,report,sources=None,require_sources=True,review_decisions=None,**limits):
        super().__init__(root,report,**limits)
        self.sources=sources or {}
        self.require_sources=require_sources
        self.source_bindings = {}
        self.provenance_error = None
        try:
            self.source_bindings = load_provenance(self.root, report.get('run_id'))
            if set(self.source_bindings) - set(self.records):
                raise ScrubError('source_provenance_inventory_mismatch')
        except ScrubError as exc:
            self.provenance_error = exc.code
        supplied=review_decisions or {}
        if set(self.sources)-set(self.records) or set(supplied)-set(self.records):
            _fail('source_or_review_inventory_mismatch')
        self.decisions={}
        for fid,record in self.records.items():
            applied=record.get('context_review',{}).get('applied_review_decisions',{})
            if isinstance(applied,list):
                applied={item['location']:{k:v for k,v in item.items() if k!='location'} for item in applied}
            normalized=validate_decisions(applied or {})
            incoming=validate_decisions(supplied.get(fid,{}))
            for loc,choice in incoming.items():
                if loc in normalized and choice!=normalized[loc]:
                    _fail('review_decision_conflict')
                normalized[loc]=choice
            self.decisions[fid]=normalized

    def safe_reference(self,reference):
        if not isinstance(reference,str) or '\\' in reference:
            _fail('unsafe_artifact_reference')
        pure=PurePosixPath(reference)
        if pure.is_absolute() or '..' in pure.parts or not pure.parts:
            _fail('unsafe_artifact_reference')
        path=self.root.joinpath(*pure.parts)
        current=path
        while current!=self.root:
            if current.is_symlink():
                _fail('artifact_not_regular_file')
            current=current.parent
        if not path.is_file() or not path.resolve().is_relative_to(self.root) or path.stat().st_size>self.max_bytes:
            _fail('artifact_path_or_size_limit')
        return path

    def path(self,record):
        artifact=record.get('artifact')
        if not isinstance(artifact,str):
            _fail('artifact_absent')
        parts=PurePosixPath(artifact)
        if (len(parts.parts) not in {2,3} or parts.parts[0] not in {'artifacts','incomplete','blocked','ready'}
                or len(parts.parts)==3 and parts.parts[1]!=record['file_id']):
            _fail('unsafe_artifact_reference')
        return self.safe_reference(artifact)

    def file(self,file_id,depth=0):
        if file_id in self.results:
            return self.results[file_id]
        record=self.records[file_id]
        check=ArtifactComparison(self,record,self.decisions[file_id])
        result=check.result
        self.results[file_id]=result
        try:
            input_format = record.get('input_format')
            if not isinstance(input_format, str) or '.' + input_format not in SUPPORTED_SUFFIXES:
                _fail('unsupported_input_format')
            output=self.path(record)
            if output.suffix.lower().lstrip('.') not in _FORMATS:
                _fail('unsupported_output_format')
            check.load_mask_ledger()
            ledger_dir=self.root/'independent-candidates'
            if ledger_dir.is_symlink(): _fail('unsafe_candidate_ledger_path')
            ledger_dir.mkdir(exist_ok=True,mode=0o700)
            ledger=ledger_dir/(file_id+'.jsonl')
            if ledger.is_symlink() or (ledger.exists() and not ledger.is_file()): _fail('unsafe_candidate_ledger_path')
            fd=os.open(ledger,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0),0o600)
            check.candidate_stream=os.fdopen(fd,'w',encoding='utf-8')
            result['independent_candidate_location_index']=ledger.relative_to(self.root).as_posix()
            source=self.sources.get(file_id)
            if source is not None:
                source=Path(source)
                if source.is_symlink() or not source.is_file() or source.stat().st_size>self.max_bytes or source.resolve()==output.resolve():
                    _fail('original_source_absent_or_unsafe')
                rejection = admission_error(source)
                if rejection:
                    _fail(rejection)
                if source.suffix.lower() != '.' + input_format:
                    _fail('input_format_does_not_match_source')
                if self.provenance_error:_fail(self.provenance_error)
                try:
                    require_source_match(self.source_bindings, file_id, source, self.max_bytes)
                except ScrubError as exc:
                    _fail(exc.code)
            kind=record.get('output_format')
            if kind not in _FORMATS:
                _fail('unsupported_output_format')
            if output.suffix.lower() != '.' + kind:
                _fail('output_format_does_not_match_artifact')
            if kind != ('xlsx' if input_format == 'xls' else input_format):
                _fail('unexpected_format_conversion')
            result['reopens']=True
            if source is None:
                check.error('original_source_required')
            if record.get('parent_file_id'):
                # Ordinal association with original wrapper members is not
                # persisted by the engine. Do not invent source provenance.
                check.error('wrapped_original_source_comparison_unavailable')
            if kind in {'csv','tsv'}:
                check.csv(source,output)
            elif kind in {'json','jsonl','ndjson'}:
                check.json(source,output)
            elif kind in {'txt','log'}:
                check.text(source,output)
            elif kind=='parquet':
                check.parquet(source,output)
            elif kind in {'xlsx','docx'}:
                check.office(source,output,kind)
            else:
                check.error('wrapper_source_comparison_unavailable' if kind in {'zip','gz'} else 'pdf_source_comparison_unavailable')
                check.error('independent_format_scan_unavailable','independent_candidate_scan_passed')
                if kind in {'zip','gz'}:
                    check.error('wrapper_policy_scan_unavailable','policy_scan_passed')
                if kind=='pdf':
                    from pypdf import PdfReader
                    PdfReader(output, strict=True)
                    check.error('unsupported_pdf_content_uninspected','policy_scan_passed')
                    if source is not None and source.read_bytes() != output.read_bytes():
                        check.error('unsupported_pdf_source_bytes_changed')
                else:
                    # Reopen safely, without claiming child-source coverage.
                    if kind=='zip':
                        with zipfile.ZipFile(output) as archive:
                            if len(archive.infolist())>self.max_entries:
                                _fail('wrapper_expansion_limit')
                    else:
                        with gzip.open(output,'rb') as stream:
                            self.digest(stream)
            check.filename(source,output)
            if source is not None and kind not in {'zip','gz','pdf'}:
                check.reconcile()
            if set(check.decisions)-check.used:
                check.error('unused_review_decisions')
                check.error('unused_review_decisions','independent_candidate_scan_passed')
            if source is not None:
                # Rehash after full parsing so source drift during verification
                # cannot silently inherit earlier semantic review evidence.
                try:
                    require_source_match(self.source_bindings, file_id, source, self.max_bytes)
                except ScrubError as exc:
                    _fail(exc.code)
                result['source_provenance_passed'] = True
            result['source_comparison_passed']=bool(source is not None and check.comparison_ok)
        except VerifyError as exc:
            check.error(exc.code)
            check.error(exc.code,'policy_scan_passed')
            check.error(exc.code,'independent_candidate_scan_passed')
        except ModuleNotFoundError:
            result['reopens']=False
            check.error('verification_dependency_unavailable','policy_scan_passed')
            check.error('verification_dependency_unavailable','independent_candidate_scan_passed')
        except Exception:
            result['reopens']=False
            check.error('artifact_parse_or_source_comparison_failed','policy_scan_passed')
            check.error('artifact_parse_or_source_comparison_failed','independent_candidate_scan_passed')
        if check.candidate_stream is not None:
            check.candidate_stream.close()
            result['independent_candidate_ledger_complete'] = bool(result['reopens'] and result['source_comparison_passed'])
        result['resource_key_collision_check_passed'] = bool(
            result['source_comparison_passed'] and result['resource_key_collision_check_passed'])
        result['protected_resource_identifiers_preserved'] = bool(
            result['source_comparison_passed'] and
            result['protected_identifiers_compared'] == result['protected_identifiers_preserved'])
        return result


def verify_directory(root, sources=None, require_sources=True, review_decisions=None, **limits):
    root=Path(root)
    report_path=root/'scrub-report.json'
    if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size>64*1024**2:
        _fail('scrub_report_absent_or_unsafe')
    with report_path.open('r',encoding='utf-8') as stream:
        report=_json(stream)
    verifier=SourceVerifier(root,report,sources,require_sources,review_decisions,**limits)
    for file_id in verifier.records:
        verifier.file(file_id)
    required=('policy_scan_passed','source_comparison_passed','independent_candidate_scan_passed','semantic_mask_review_passed','source_provenance_passed')
    return {'verification_version':'4.0','all_artifacts_passed':all(all(r.get(k) is True for k in required) for r in verifier.results.values()),
            'readiness_statuses_modified':False,'context_review_still_required':True,
            'scan_scope':'actual_source_output_comparison_and_independent_retained_candidates',
            'files':verifier.results}

def main():
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    csv.field_size_limit(16 * 1024 * 1024)
    parser = argparse.ArgumentParser(description="Locally reopen and fully scan scrubbed outputs; no uploads or readiness changes.")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--source", action="append", default=[], metavar="FILE_ID=PATH")
    parser.add_argument("--max-bytes", type=int, default=2 * 1024**3)
    parser.add_argument("--max-entries", type=int, default=10000)
    parser.add_argument("--max-depth", type=int, default=12)
    args = parser.parse_args()
    try:
        if args.max_bytes < 1 or args.max_entries < 1 or args.max_depth < 1:
            _fail("invalid_verification_limits")
        sources = {}
        for pair in args.source:
            fid, separator, source = pair.partition('=')
            if not separator or not _FILE_ID.fullmatch(fid) or fid in sources or not source:
                _fail('invalid_source_argument')
            sources[fid] = Path(source)
        result = verify_directory(args.output_dir, sources=sources, max_bytes=args.max_bytes,
                                  max_entries=args.max_entries, max_depth=args.max_depth)
    except VerifyError as exc:
        result = {"verification_version": "1.0", "all_artifacts_passed": False,
                  "readiness_statuses_modified": False, "context_review_still_required": True,
                  "errors": [exc.code], "files": {}}
    except Exception:
        result = {"verification_version": "1.0", "all_artifacts_passed": False,
                  "readiness_statuses_modified": False, "context_review_still_required": True,
                  "errors": ["verification_report_processing_failed"], "files": {}}
    try:
        if not args.output_dir.is_dir():
            _fail("output_directory_missing")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="verification-", suffix=".tmp",
                                         dir=args.output_dir, delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            json.dump(result, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
        temporary.replace(args.output_dir / "verification.json")
    except Exception:
        print(json.dumps({"verification_completed": False, "error": "verification_report_write_failed"}))
        return 2
    print(json.dumps({"verification_completed": True, "all_artifacts_passed": result["all_artifacts_passed"],
                      "files_checked": len(result["files"]), "context_review_still_required": True}))
    return 0 if result["all_artifacts_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
