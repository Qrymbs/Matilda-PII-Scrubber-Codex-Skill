"""Faithful local OOXML human-PII edits and read-only verification.

Unchanged ZIP members remain byte-identical. Formulas, links and binary
objects are never executed. Corroborating author identities exist only in RAM.
Returned findings contain counts and neutral structural locations, no values.
"""
from __future__ import annotations

import copy
from collections import Counter
from decimal import Decimal
import io
from pathlib import Path, PurePosixPath
import re
import stat
import unicodedata
from urllib.parse import unquote
import zipfile

from lxml import etree
from scrub_core import (ScrubContext, ScrubError, assess_value, detect_pii_spans,
                        is_protected_resource_field)

S = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
ROLES = {'author', 'creator', 'lastmodifiedby', 'lastsavedby', 'refreshedby',
         'createdby', 'modifiedby', 'preparedby', 'approvedby'}
PROFILE = re.compile(r'(?:^|/)(?:users|home)/([^/]+)', re.I)
SYSTEM_PROFILES = {'public', 'default', 'defaultuser', 'allusers', 'shared',
                   'ubuntu', 'root', 'admin', 'administrator', 'system',
                   'service', 'svc', 'oracle', 'postgres', 'mysql'}
SAFE_PART = re.compile(
    r'(?:\[Content_Types\]\.xml|_rels/\.rels|docProps/(?:core|app|custom)\.xml|'
    r'customXml/(?:_rels/)?item(?:Props)?\d+\.xml(?:\.rels)?|'
    r'xl/(?:workbook|styles|sharedStrings|calcChain|metadata|connections)\.xml|'
    r'xl/_rels/workbook\.xml\.rels|'
    r'xl/(?:worksheets|charts|drawings|tables|pivotTables|pivotCache|theme|comments)/(?:_rels/)?'
    r'(?:sheet|chart|drawing|table|pivotTable|pivotCacheDefinition|pivotCacheRecords|theme|comment)\d+\.xml(?:\.rels)?|'
    r'xl/(?:comments|threadedComment)\d+\.xml|'
    r'word/(?:_rels/)?(?:document|styles|settings|fontTable|webSettings|numbering|comments|footnotes|endnotes|header\d+|footer\d+)\.xml(?:\.rels)?|'
    r'word/theme/theme\d+\.xml)$')
SAFE_NAMESPACES = frozenset({S[1:-1], W[1:-1],
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
    'http://schemas.openxmlformats.org/package/2006/relationships',
    'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
    'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties',
    'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties',
    'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes',
    'http://schemas.openxmlformats.org/drawingml/2006/main',
    'http://schemas.openxmlformats.org/drawingml/2006/chart',
    'http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing',
    'http://schemas.openxmlformats.org/markup-compatibility/2006',
    'http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac',
    'http://schemas.microsoft.com/office/spreadsheetml/2009/9/main',
    'http://purl.org/dc/elements/1.1/', 'http://purl.org/dc/terms/',
    'http://purl.org/dc/dcmitype/', 'http://www.w3.org/2001/XMLSchema-instance'})
SAFE_ATTRIBUTES = frozenset({'url', 'path', 'refreshedBy', 'author', 'creator',
    'lastModifiedBy', 'lastSavedBy', 'createdBy', 'modifiedBy', 'initials',
    'name', 'Target', 'TargetMode', 'Id', 'Type', 'r', 's', 't', 'val', 'id',
    'value', 'ref', 'si', 'location', 'display', 'tooltip', 'href', 'src'})

MAX_ENTRIES = 20000
MAX_PART = 64 * 1024 * 1024
RVTOOLS_SHEETS = frozenset(name.casefold() for name in '''
vInfo vCPU vMemory vDisk vNetwork vHost vCluster vDatastore vPartition vSnapshot
vTools vCD vFloppy vUSB vHealth vLicense vSource vResourcePool vRP vMultiPath
vHBA vNIC vSwitch vPort dvPort vMetaData vSC_VMK vVSwitch vDVSwitch vDPort vDVS vNVRAM
'''.split())
# Fixed schema labels only: neither source cell values nor arbitrary headers
# enter relationship-loss reports. Presence alone never counts as a loss.
RVTOOLS_JOIN_FIELDS = frozenset({'vm', 'vmname', 'vmid', 'vmuuid', 'smbiosuuid',
                                'uuid', 'visdkuuid', 'host', 'hostname', 'hostid'})


def local(name):
    return name.rsplit('}', 1)[-1] if isinstance(name, str) else 'xml_annotation'


def canon(value):
    return ''.join(c for c in unicodedata.normalize('NFKC', str(value)).casefold() if c.isalnum())


def metadata_field(name):
    key = canon(local(name))
    if key in ROLES:
        return 'author'
    if key in {'initials', 'personinitials'}:
        return 'person_initials'
    return local(name)


def _xml_field(node, part, attribute=None):
    name = attribute if attribute is not None else node.tag
    field = metadata_field(name)
    if attribute == 'typeface' and node.tag in {
            '{http://schemas.openxmlformats.org/drawingml/2006/main}'+tag
            for tag in ('latin','ea','cs','font')}:
        return 'font_typeface'
    # Schema/style/sheet names are structural labels, not person-name slots.
    if ((canon(local(name)) == 'name' and part.startswith(('xl/', 'word/', 'docProps/')))
            or attribute is not None and canon(local(node.tag)) in {'style', 'rstyle', 'pstyle', 'tblstyle'}
            or attribute is not None and canon(local(name)) in {'styleid', 'basedon', 'next'}):
        field = 'schema_label'
    if attribute is None:
        parent = node.getparent()
        if parent is not None and local(parent.tag) == 'property' and parent.get('name'):
            field = parent.get('name')
    if attribute is not None and local(node.tag) == 'absPath' and local(attribute) == 'url':
        field = 'savedPath'
    return field


def _safe_part(name, index):
    return name if SAFE_PART.fullmatch(name) else f'part_{index:05d}'


def _parse(raw):
    if len(raw) > MAX_PART:
        raise ScrubError('ooxml_xml_part_size_limit')
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True,
                                 load_dtd=False, remove_blank_text=False,
                                 remove_comments=False, remove_pis=False,
                                 huge_tree=False)
        tree = etree.parse(io.BytesIO(raw), parser)
    except Exception:
        raise ScrubError('ooxml_malformed_xml') from None
    if tree.docinfo.doctype:
        raise ScrubError('ooxml_dtd_not_supported')
    return tree


def _nodes(tree):
    root = tree.getroot()
    yield from reversed(list(root.itersiblings(preceding=True)))
    yield from root.iter()
    yield from root.itersiblings()


def _serialize(tree, raw):
    encoding = tree.docinfo.encoding or 'UTF-8'
    declared = raw.lstrip().startswith(b'<?xml') or raw.startswith((b'\xff\xfe', b'\xfe\xff'))
    options = {'encoding': encoding, 'xml_declaration': declared}
    if re.search(br'standalone\s*=', raw[:300], re.I):
        options['standalone'] = bool(tree.docinfo.standalone)
    return etree.tostring(tree, **options)


class Package:
    """Bounded package parser; mutable content never writes back to its source."""
    def __init__(self, path, kind):
        self.path = Path(path)
        self.kind = kind
        self.raw, self.trees, self.info = {}, {}, {}
        self.modified, self.omitted = set(), set()
        self.zip_entry_flags_normalized = 0
        self.archive_comment = b''
        maximum = (1024 if kind == 'xlsx' else 256) * 1024 * 1024
        try:
            with zipfile.ZipFile(self.path) as archive:
                infos = archive.infolist()
                if len(infos) > MAX_ENTRIES or sum(x.file_size for x in infos) > maximum:
                    raise ScrubError('ooxml_container_size_limit')
                seen = set()
                for info in infos:
                    path_name = PurePosixPath(info.filename.replace('\\', '/'))
                    mode = stat.S_IFMT(info.external_attr >> 16)
                    if (info.filename.casefold() in seen or path_name.is_absolute()
                            or '..' in path_name.parts or '\\' in info.filename
                            or info.flag_bits & 1
                            or mode not in {0, stat.S_IFREG, stat.S_IFDIR}):
                        raise ScrubError('ooxml_unsafe_or_encrypted_container')
                    seen.add(info.filename.casefold())
                    self.info[info.filename] = copy.copy(info)
                    self.raw[info.filename] = archive.read(info)
                    if info.filename.lower().endswith(('.xml', '.rels', '.vml')):
                        self.trees[info.filename] = _parse(self.raw[info.filename])
                self.archive_comment = archive.comment
        except ScrubError:
            raise
        except Exception:
            raise ScrubError('ooxml_unreadable_container') from None
        required = 'xl/workbook.xml' if kind == 'xlsx' else 'word/document.xml'
        if required not in self.trees:
            raise ScrubError('ooxml_main_part_missing')

    def bytes_for(self, name):
        if name in self.modified:
            return _serialize(self.trees[name], self.raw[name])
        return self.raw[name]

    def save(self, destination):
        self.zip_entry_flags_normalized = 0
        with zipfile.ZipFile(destination, 'x') as output:
            output.comment = self.archive_comment
            for name, info in self.info.items():
                if name not in self.omitted:
                    written = copy.copy(info)
                    output.writestr(written, self.bytes_for(name))
                    # zipfile supplies 0600 when external_attr is zero. Restore
                    # the actual source permission metadata before it writes
                    # the central directory; local headers have no such field.
                    written.external_attr = info.external_attr
                    self.zip_entry_flags_normalized += int(written.flag_bits != info.flag_bits)


def _authors(package, review_decisions=None):
    """Only confirmed human author identities become cross-part evidence."""
    result = set()
    for part_index, tree in enumerate(package.trees.values(), 1):
        for node_index, node in enumerate(_nodes(tree), 1):
            candidates = []
            text_location = f'p{part_index}.k{node_index}.i1'
            if canon(local(node.tag)) in ROLES and node.text:
                if (review_decisions or {}).get(text_location, {}).get('action') != 'retain':
                    candidates.append(node.text)
            for attribute_index, (key, value) in enumerate(node.attrib.items(), 3):
                location = f'p{part_index}.k{node_index}.i{attribute_index}'
                if canon(local(key)) in ROLES and (review_decisions or {}).get(location, {}).get('action') != 'retain':
                    candidates.append(value)
            for value in candidates:
                confirmed, _ = assess_value(value, 'author')
                if 'human_names' in confirmed and value.strip():
                    result.add(canon(value))
    return result


def _corroborated_field(value, field, authors):
    if isinstance(value, str):
        if canon(value) in authors:
            return 'personname' if len(value.split()) > 1 else 'personusername'
        path = unquote(value).replace('\\', '/')
        for match in PROFILE.finditer(path):
            identity = canon(match.group(1))
            if identity in authors and identity not in SYSTEM_PROFILES:
                return 'personprofile'
    return field


class Analysis:
    def __init__(self, ctx, authors):
        self.ctx, self.authors = ctx, authors
        self.changes, self.field_counts = [], Counter()
        self.data_cells = self.metadata_values = self.storage_cleanups = 0
        self.opaque_parts = self.xml_parts = self.formulas = self.cached_formulas = 0
        self.cleared_formulas = self.inspected_cells = self.sheets = self.rows = 0
        self.paragraphs = self.word_cells = self.package_comments_cleared = 0
        self.structural_review_parts = 0
        self.confirmed_values = {}
        self.retained_value_exceptions = set()
        self.rvtools_sheets = 0
        self.join_field_counts = Counter()
        self.join_field_locations = []
        self.masked_values = {}
        self.proven_values = {}
        self.protected_identifier_checks = 0
        self.protected_values = set()

    def apply(self, value, field, location, descriptor, kind='metadata', spans=None,
              cache_payload=False, immutable=False):
        """Mask confirmed spans without changing the containing item's type."""
        if value is None or value == '':
            return value
        protected = is_protected_resource_field(field)
        if protected:
            self.protected_identifier_checks += 1
            self.protected_values.add(str(value))
        proof = self.proven_values.get(location)
        if proof and value == proof['masked']:
            self.ctx.inspected += 1
            self.ctx.retained += 1
            for index, reason in enumerate(proof['reviews']):
                self.ctx.note_review(reason, location, _item=index == 0)
            return value
        # Corroboration may establish a saved *personal* profile component;
        # never apply it to a resource identifier or workbook join key.
        saved_path = canon(field) in {'savedpath', 'personprofile', 'personalprofilepath', 'corroboratedpersonprofile'}
        if kind != 'cell' and canon(field) not in {'schemalabel', 'id', 'ref', 'name'} and (not protected or saved_path):
            field = _corroborated_field(value, field, self.authors)
        if (cache_payload and str(value) in self.confirmed_values
                and (not assess_value(value, field)[0] or str(value) in self.protected_values
                     or str(value) in self.retained_value_exceptions)):
            self.ctx.inspected += 1
            self.ctx.retained += 1
            self.ctx.note_review('ambiguous_person_container', location)
            return value
        if immutable:
            self.ctx.inspected += 1
            self.ctx.retained += 1
            confirmed, reviews = assess_value(value, field)
            if confirmed or spans:
                reviews = set(reviews) | {immutable if isinstance(immutable, str) else 'formula_pii_requires_review'}
            for index, reason in enumerate(sorted(reviews)):
                self.ctx.note_review(reason, location, _item=index == 0)
            return value
        before = Counter(self.ctx.counts)
        before_reviews = Counter(self.ctx.review_counts)
        result = self.ctx.scrub(value, field=field, location=location, spans=spans)
        if result == value and type(result) is type(value):
            if self.ctx.review_decisions.get(location, {}).get('action') == 'retain':
                self.retained_value_exceptions.add(str(value))
            return value
        if not isinstance(value, str) or not isinstance(result, str) or len(result) != len(value):
            raise ScrubError('ooxml_non_length_preserving_mask_forbidden')
        if any(a != b and b != 'X' for a, b in zip(value, result)):
            raise ScrubError('ooxml_non_mask_edit_forbidden')
        categories = {k for k, n in self.ctx.counts.items() if n > before[k]}
        self.confirmed_values.setdefault(value, set()).update(categories)
        self.masked_values[location] = {'masked': result, 'reviews': [reason for reason, count in self.ctx.review_counts.items() if count > before_reviews[reason]]}
        if kind == 'cell':
            self.data_cells += 1
        else:
            self.metadata_values += 1
        self.field_counts[(descriptor.get('part', ''), descriptor.get('field', ''))] += 1
        if len(self.changes) < 200:
            self.changes.append({**descriptor, 'categories': sorted(categories)})
        return result


def _column_number(label):
    number = 0
    for char in label:
        number = number * 26 + ord(char) - 64
    return number


def _string_text_nodes(item):
    """Visible string runs only; phonetic annotations are separate metadata."""
    if item is None:
        return []
    result = []
    for child in item:
        if child.tag == S + 't':
            result.append(child)
        elif child.tag == S + 'r':
            result.extend(child.findall(S + 't'))
    return result


def _typed_xml_value(node, attribute=None):
    namespace = etree.QName(node).namespace if isinstance(node.tag, str) else None
    if namespace == 'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes':
        return local(node.tag) in {'i1','i2','i4','i8','int','ui1','ui2','ui4','ui8','uint',
                                   'r4','r8','decimal','bool','date','filetime','cy','error','clsid'}
    return namespace == S[1:-1] and local(node.tag) in {'n','b','d','e'} and attribute in {None, 'v'}


def _cell_text(cell, shared):
    typ, value = cell.get('t', 'n'), cell.find(S + 'v')
    if typ == 's':
        if value is None or value.text is None:
            return None, None
        try:
            index = int(value.text)
            if index < 0:
                raise ValueError
            item = shared[index]
        except Exception:
            raise ScrubError('ooxml_invalid_shared_string_reference') from None
        return ''.join(n.text or '' for n in _string_text_nodes(item)), index
    if typ == 'inlineStr':
        inline = cell.find(S + 'is')
        return ''.join(n.text or '' for n in _string_text_nodes(inline)) if inline is not None else '', None
    raw = value.text if value is not None else None
    if raw is None:
        return None, None
    if typ in {'str', 'e', 'd'}:
        return raw, None
    if typ == 'b':
        return raw == '1', None
    try:
        return int(raw) if re.fullmatch(r'[+-]?\d+', raw) else Decimal(raw), None
    except Exception:
        return raw, None


def _replace_text_nodes(nodes, original, masked):
    """Distribute equal-length masking over existing runs, retaining formatting."""
    if len(original) != len(masked):
        raise ScrubError('ooxml_text_length_changed')
    offset = 0
    for node in nodes:
        old = node.text or ''
        node.text = masked[offset:offset + len(old)]
        offset += len(old)
    if offset != len(original):
        raise ScrubError('ooxml_text_mapping_failed')


def _mask_cell_text(cell, original, masked):
    if cell.get('t') == 'inlineStr':
        _replace_text_nodes(_string_text_nodes(cell.find(S + 'is')), original, masked)
    else:
        value = cell.find(S + 'v')
        if value is None:
            raise ScrubError('ooxml_value_mapping_failed')
        value.text = masked


def _rvtools_join_columns(sheet_name, headers):
    if not isinstance(sheet_name, str) or sheet_name.casefold() not in RVTOOLS_SHEETS:
        return {}
    return {column: canon(header) for column, header in headers.items()
            if canon(header) in RVTOOLS_JOIN_FIELDS}


def _xlsx_cells(package, analysis):
    shared_tree = package.trees.get('xl/sharedStrings.xml')
    shared = list(shared_tree.getroot().findall(S + 'si')) if shared_tree is not None else []
    reference_edits = {index: [] for index in range(len(shared))}
    skip = set()
    for item in shared:
        skip.update(_string_text_nodes(item))
    workbook = package.trees['xl/workbook.xml'].getroot()
    relation_tree = package.trees.get('xl/_rels/workbook.xml.rels')
    targets = {}
    if relation_tree is not None:
        import posixpath
        for rel in relation_tree.getroot():
            target = rel.get('Target', '')
            if rel.get('TargetMode') != 'External':
                targets[rel.get('Id')] = posixpath.normpath(target.lstrip('/') if target.startswith('/') else 'xl/' + target)
    ordered, sheet_names = [], {}
    rid = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id'
    for sheet in workbook.iter(S + 'sheet'):
        part = targets.get(sheet.get(rid))
        if part in package.trees and package.trees[part].getroot().tag == S + 'worksheet':
            ordered.append(part)
            sheet_names[part] = sheet.get('name', '')
    ordered.extend(part for part, tree in package.trees.items()
                   if tree.getroot().tag == S + 'worksheet' and part not in ordered)
    for sheet_index, part in enumerate(ordered, 1):
        analysis.sheets += 1
        tree = package.trees[part]
        analysis.rows += len(list(tree.getroot().iter(S + 'row')))
        cells = list(tree.getroot().iter(S + 'c'))
        headers = {}
        for cell in cells:
            coordinate = cell.get('r', '')
            if re.fullmatch(r'[A-Z]+1', coordinate):
                value, _ = _cell_text(cell, shared)
                if isinstance(value, str):
                    headers[re.sub(r'\d+$', '', coordinate)] = value
        join_columns = _rvtools_join_columns(sheet_names.get(part), headers)
        if join_columns:
            analysis.rvtools_sheets += 1
        for cell in cells:
            analysis.inspected_cells += 1
            coordinate = cell.get('r', '')
            match = re.fullmatch(r'([A-Z]+)([1-9]\d*)', coordinate)
            if not match:
                raise ScrubError('ooxml_cell_coordinate_missing_or_invalid')
            column, row = match.group(1), int(match.group(2))
            value, index = _cell_text(cell, shared)
            field = headers.get(column) if row > 1 else 'schema_label'
            # RVTools aliases must never bypass the resource key protection.
            if row > 1 and column in join_columns:
                field = 'resource_id'
            location = f's{sheet_index}.r{row}.c{_column_number(column)}'
            descriptor = {'part': _safe_part(part, sheet_index), 'cell': coordinate, 'field': 'cell_value'}
            formula = cell.find(S + 'f')
            if formula is not None:
                analysis.formulas += 1
                if value is not None:
                    analysis.cached_formulas += 1
                analysis.apply(formula.text, 'free_text', location + '.i1', descriptor,
                               immutable=True)
                skip.add(formula)
            immutable = ('formula_pii_requires_review' if formula is not None else
                         'type_masking_conflict' if cell.get('t', 'n') in {'n', 'b', 'd', 'e'} else False)
            cleaned = analysis.apply(value, field, location, descriptor, 'cell', immutable=immutable)
            skip.update(_string_text_nodes(cell.find(S + 'is')))
            skip.update(cell.iter(S + 'v'))
            if index is not None:
                reference_edits[index].append((cell, part, value, cleaned))
            elif cleaned != value:
                _mask_cell_text(cell, value, cleaned)
                package.modified.add(part)
    # Shared values are edited once when all contexts agree, or copied only
    # for the references requiring a different mask. Resource copies survive.
    for index, item in enumerate(shared):
        original = ''.join(n.text or '' for n in _string_text_nodes(item))
        references = reference_edits[index]
        if not references:
            descriptor = {'part': 'xl/sharedStrings.xml', 'shared_string': index,
                          'field': 'unreferenced_shared_string'}
            masked = analysis.apply(original, 'free_text', f'root.k{index+1}', descriptor)
            if masked != original:
                _replace_text_nodes(_string_text_nodes(item), original, masked)
                package.modified.add('xl/sharedStrings.xml')
                analysis.storage_cleanups += 1
            continue
        variants = {}
        for cell, part, value, masked in references:
            variants.setdefault(masked, []).append((cell, part))
        base = original if original in variants else next(iter(variants))
        template = copy.deepcopy(item)
        if base != original:
            _replace_text_nodes(_string_text_nodes(item), original, base)
            package.modified.add('xl/sharedStrings.xml')
            analysis.storage_cleanups += 1
        for masked, owners in variants.items():
            if masked == base:
                continue
            clone = copy.deepcopy(template)
            _replace_text_nodes(_string_text_nodes(clone), original, masked)
            new_index = len(shared_tree.getroot().findall(S + 'si'))
            shared_tree.getroot().append(clone)
            skip.update(_string_text_nodes(clone))
            package.modified.add('xl/sharedStrings.xml')
            analysis.storage_cleanups += 1
            for cell, part in owners:
                cell.find(S + 'v').text = str(new_index)
                package.modified.add(part)
        if len(variants) > 1 and original in variants and assess_value(original, 'free_text')[0]:
            analysis.ctx.note_review('ambiguous_person_container', f'root.k{index+1}')
    if shared_tree is not None and 'xl/sharedStrings.xml' in package.modified:
        root = shared_tree.getroot()
        if 'uniqueCount' in root.attrib:
            root.set('uniqueCount', str(len(root.findall(S + 'si'))))
    return skip


def _word_items(package, analysis):
    from scrub_documents import _word_item_text, _replace_word_item, _item_spans
    skip = set()
    for part_index, (part, tree) in enumerate(package.trees.items(), 1):
        root = tree.getroot()
        items = []
        for table_index, table in enumerate(root.iter(W + 'tbl'), 1):
            if any(p.tag == W + 'tc' for p in table.iterancestors()):
                continue
            rows = table.findall(W + 'tr')
            headers = [_word_item_text(c) for c in rows[0].findall(W + 'tc')] if rows else []
            for row_index, row in enumerate(rows, 1):
                for column_index, cell in enumerate(row.findall(W + 'tc'), 1):
                    analysis.word_cells += 1
                    field = headers[column_index-1] if row_index > 1 and column_index <= len(headers) else 'schema_label'
                    items.append((cell, field, f'p{part_index}.b{table_index}.r{row_index}.c{column_index}', 'table_cell'))
        paragraphs = [p for p in root.iter(W + 'p') if not any(parent.tag in {W + 'tc', W + 'p'} for parent in p.iterancestors())]
        for paragraph_index, paragraph in enumerate(paragraphs, 1):
            analysis.paragraphs += 1
            items.append((paragraph, 'free_text', f'p{part_index}.r{paragraph_index}', 'paragraph'))
        for item, field, location, kind in items:
            value = _word_item_text(item)
            descriptor = {'part': _safe_part(part, part_index), 'item': location, 'field': kind}
            spans, contextual_reviews = (analysis.expected_spans(value, field, location)
                                        if hasattr(analysis, 'expected_spans') else _item_spans(value, field))
            reviewed = location in analysis.ctx.review_decisions
            proved = analysis.proven_values.get(location, {}).get('masked') == value
            if not proved:
                for index, reason in enumerate(sorted(contextual_reviews)):
                    analysis.ctx.note_review(reason, location, _item=index == 0, _resolved=reviewed)
            # Field instructions are executable document features, so retain
            # a containing item if a proposed mask would touch an instruction.
            instruction = any(node.tag == W + 'instrText' for node in item.iter())
            # A structured tab/line break cannot be replaced by a text X
            # without changing document structure. Retain and block that item.
            structural_mask = any(any(value[pos] in '\t\n' for pos in range(span['start'], span['end'])) for span in spans)
            cleaned = analysis.apply(value, field, location, descriptor, 'cell',
                                     spans=spans, immutable=('formula_pii_requires_review' if instruction else
                                             'type_masking_conflict' if structural_mask else False))
            for node in item.iter():
                if node.tag in {W + 't', W + 'delText', W + 'instrText'}:
                    skip.add(node)
            if cleaned != value:
                if not reviewed and location in analysis.masked_values:
                    analysis.masked_values[location]['reviews'] = sorted(set(analysis.masked_values[location]['reviews']) | set(contextual_reviews))
                _replace_word_item(item, cleaned)
                package.modified.add(part)
    return skip


def _package_metadata(package, analysis):
    # ZIP comments are inspectable strings; unknown bytes are preserved and
    # block release rather than being silently discarded.
    comments = [(None, package.archive_comment)] + [(name, info.comment) for name, info in package.info.items()]
    for index, (part, raw) in enumerate(comments, 1):
        if not raw:
            continue
        try:
            text = raw.decode('utf-8')
        except UnicodeError:
            analysis.opaque_parts += 1
            continue
        masked = analysis.apply(text, 'free_text', f'root.k{index}', {'part': 'package_metadata', 'field': 'zip_comment'})
        if masked != text:
            if part is None:
                package.archive_comment = masked.encode('utf-8')
            else:
                package.info[part].comment = masked.encode('utf-8')
            analysis.package_comments_cleared += 1
    for part_index, (part, tree) in enumerate(package.trees.items(), 1):
        seen_namespaces = set()
        for node_index, node in enumerate(_nodes(tree), 1):
            for uri in getattr(node, 'nsmap', {}).values():
                if uri in seen_namespaces:
                    continue
                seen_namespaces.add(uri)
                if assess_value(uri, 'free_text')[0]:
                    analysis.structural_review_parts += 1
                    analysis.ctx.note_review('ambiguous_person_container', f'p{part_index}.k{node_index}.i1')
                    analysis.ctx.warn('ooxml_structural_identity_review_required')
    for info in package.info.values():
        cursor = 0
        while cursor < len(info.extra):
            if cursor + 4 > len(info.extra):
                analysis.opaque_parts += 1
                break
            extra_type = int.from_bytes(info.extra[cursor:cursor+2], 'little')
            size = int.from_bytes(info.extra[cursor+2:cursor+4], 'little')
            cursor += 4
            if cursor + size > len(info.extra) or extra_type not in {0x0001, 0x000a, 0x5455, 0x7875}:
                analysis.opaque_parts += 1
            cursor += size
    for index, name in enumerate(package.raw, 1):
        confirmed, reviews = assess_value(name, 'free_text')
        if confirmed or reviews:
            # Renaming part URIs requires graph-wide package edits; do not
            # mutate structural identifiers or claim a clean package.
            analysis.structural_review_parts += 1
            analysis.ctx.note_review('ambiguous_person_container', f'root.p{index}')
            analysis.ctx.warn('ooxml_part_name_identity_review_required')


def _transform(package, ctx, authors=None, source_locations=None, confirmed_values=None, retained_exceptions=None, proven_values=None, analysis=None):
    if analysis is None:
        analysis = Analysis(ctx, _authors(package, ctx.review_decisions) if authors is None else authors)
    analysis.confirmed_values.update({key: set(value) for key, value in (confirmed_values or {}).items()})
    analysis.retained_value_exceptions.update(retained_exceptions or ())
    analysis.proven_values.update(proven_values or {})
    if source_locations is None:
        source_locations = {part: {tree.getpath(node): ordinal for ordinal, node in enumerate(_nodes(tree), 1)} for part, tree in package.trees.items()}
    skip = _xlsx_cells(package, analysis) if package.kind == 'xlsx' else _word_items(package, analysis)
    for part_index, (part, tree) in enumerate(package.trees.items(), 1):
        analysis.xml_parts += 1
        safe_part = _safe_part(part, part_index)
        for ordinal, node in enumerate(list(_nodes(tree)), 1):
            source_ordinal = (source_locations or {}).get(part, {}).get(tree.getpath(node), ordinal)
            location = f'p{part_index}.k{source_ordinal}'
            namespace = etree.QName(node).namespace if isinstance(node.tag, str) else None
            public_element = node.tag if namespace in SAFE_NAMESPACES else f'element_{ordinal}'
            if node not in skip and node.text:
                masked = analysis.apply(node.text, _xml_field(node, part), location + '.i1',
                    {'part': safe_part, 'element': public_element, 'field': 'xml_text'},
                    cache_payload=local(node.tag) in {'v', 's', 'n', 'b', 'e', 'd'},
                    immutable='type_masking_conflict' if _typed_xml_value(node) else False)
                if masked != node.text:
                    node.text = masked
                    package.modified.add(part)
            if node.tail:
                masked = analysis.apply(node.tail, 'free_text', location + '.i2',
                    {'part': safe_part, 'element': public_element, 'field': 'xml_tail'})
                if masked != node.tail:
                    node.tail = masked
                    package.modified.add(part)
            for attribute_index, (attribute, value) in enumerate(list(node.attrib.items()), 3):
                field = _xml_field(node, part, attribute)
                masked = analysis.apply(value, field, location + f'.i{attribute_index}',
                    {'part': safe_part, 'element': public_element,
                     'attribute': local(attribute) if local(attribute) in SAFE_ATTRIBUTES else f'attribute_{attribute_index}',
                     'field': field if local(attribute) in SAFE_ATTRIBUTES else 'xml_attribute'},
                    cache_payload=local(attribute) == 'v',
                    immutable='type_masking_conflict' if _typed_xml_value(node, local(attribute)) else False)
                if masked != value:
                    node.set(attribute, masked)
                    package.modified.add(part)
    _package_metadata(package, analysis)
    # Binary parts are faithfully retained. A full context review cannot
    # certify their pixels/executable/opaque payload using an XML-only scan.
    for name in package.raw:
        if name not in package.trees and not package.info[name].is_dir():
            analysis.opaque_parts += 1
    if analysis.opaque_parts:
        ctx.warn('retained_opaque_ooxml_content_uninspected')
    return analysis


def _metrics(package, analysis):
    unresolved = {reason: count - analysis.ctx.resolved_review_counts[reason]
                  for reason, count in analysis.ctx.review_counts.items()
                  if count > analysis.ctx.resolved_review_counts[reason]}
    limitations = ['retained_opaque_ooxml_content_uninspected'] if analysis.opaque_parts else []
    if package.zip_entry_flags_normalized:
        limitations.append('ooxml_zip_entry_flags_normalized')
    return {'xml_parts_inspected': analysis.xml_parts, 'cells_inspected': analysis.inspected_cells,
            'sheets': analysis.sheets, 'rows': analysis.rows,
            'paragraphs': analysis.paragraphs, 'cells': analysis.word_cells,
            'whole_data_cells_cleared': 0,
            'data_cells_masked': analysis.data_cells,
            'metadata_values_cleared': 0,
            'metadata_values_masked': analysis.metadata_values,
            'shared_string_storage_cleanups': analysis.storage_cleanups,
            'retained_formula_cells': analysis.formulas - analysis.cleared_formulas,
            'source_formula_cells': analysis.formulas, 'source_formula_caches': analysis.cached_formulas,
            'unaffected_xml_parts_byte_preserved': True, 'layout_preserved': True,
            'opaque_parts_retained': analysis.opaque_parts,
            'package_comments_cleared': 0,
            'package_comments_masked': analysis.package_comments_cleared,
            'zip_entry_permissions_preserved': True,
            'protected_resource_identifier_values_inspected': analysis.protected_identifier_checks,
            'protected_resource_identifiers_mutated': 0,
            'zip_entry_flags_normalized': package.zip_entry_flags_normalized,
            'incomplete': bool(analysis.opaque_parts), 'review_required': bool(unresolved),
            'unresolved_identity_counts': unresolved, 'pii_locations': analysis.changes,
            'pii_field_counts': [{'part': p, 'field': f, 'count': n} for (p, f), n in sorted(analysis.field_counts.items())],
            'format_limitations': limitations,
            'source_profile': 'rvtools' if analysis.rvtools_sheets else 'ooxml_values_and_metadata',
            'join_keys_removed': bool(analysis.join_field_counts),
            'join_fields_nulled': sorted(analysis.join_field_counts),
            'join_field_counts': dict(sorted(analysis.join_field_counts.items())),
            'join_field_locations': analysis.join_field_locations}


def _scrub(src, dst, ctx, kind):
    src, dst = Path(src), Path(dst)
    if src.resolve() == dst.resolve():
        raise ScrubError('source_output_collision')
    if dst.exists() or dst.is_symlink():
        raise ScrubError('output_already_exists')
    try:
        package = Package(src, kind)
        analysis = _transform(package, ctx)
        package.save(dst)
        return _metrics(package, analysis)
    except Exception as exc:
        try:
            dst.unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(exc, ScrubError):
            raise
        raise ScrubError('ooxml_processing_failed') from None


def scrub_xlsx(src, dst, ctx):
    return _scrub(src, dst, ctx, 'xlsx')


def scrub_docx(src, dst, ctx):
    return _scrub(src, dst, ctx, 'docx')


def scan_ooxml(path, kind='xlsx', source_path=None, review_decisions=None):
    """Read-only full scan; source-only corroboration stays inside this RAM call."""
    try:
        package = Package(path, kind)
        source = Package(source_path, kind) if source_path is not None else None
        ctx = ScrubContext(review_decisions={k: v for k, v in (review_decisions or {}).items() if v.get('action') == 'retain'})
        source_locations = {part: {tree.getpath(node): ordinal for ordinal, node in enumerate(_nodes(tree), 1)} for part, tree in source.trees.items()} if source is not None else None
        source_authors = _authors(source, review_decisions) if source is not None else None
        source_analysis = _transform(source, ScrubContext(review_decisions=review_decisions or {})) if source is not None else None
        analysis = _transform(package, ctx, source_authors, source_locations,
                              source_analysis.confirmed_values if source_analysis else None,
                              source_analysis.retained_value_exceptions if source_analysis else None,
                              source_analysis.masked_values if source_analysis else None)
        confirmed = {k: n for k, n in ctx.counts.items() if k.startswith('human_')}
        metrics = _metrics(package, analysis)
        errors = []
        if confirmed:
            errors.append('confirmed_human_pii_retained')
        if metrics['review_required']:
            errors.append('unresolved_identity_review_required')
        if analysis.opaque_parts:
            errors.append('retained_opaque_ooxml_content_uninspected')
        return {**metrics, 'reopens': True, 'policy_scan_passed': not errors,
                'confirmed_categories': confirmed, 'review_counts': dict(ctx.review_counts),
                'values_checked': ctx.inspected, 'errors': errors}
    except Exception:
        return {'reopens': False, 'policy_scan_passed': False,
                'errors': ['ooxml_scan_failed'], 'values_checked': 0}


def compare_ooxml(source, output, kind='xlsx', review_decisions=None):
    """Diagnostic scrub-transform replay; not independent release verification.

    Release gating uses verify_outputs.ArtifactComparison.office, which
    reconstructs expected edits only from recorded/reviewed span offsets.
    """
    try:
        expected = Package(source, kind)
        ctx = ScrubContext(review_decisions=review_decisions or {})
        analysis = _transform(expected, ctx)
        actual = Package(output, kind)
        wanted = set(expected.raw)
        inventory = wanted == set(actual.raw)
        wrong = [name for name in wanted & set(actual.raw) if expected.bytes_for(name) != actual.raw[name]]
        unchanged = [name for name in wanted if name not in expected.modified]
        retained_exact = inventory and all(expected.raw[name] == actual.raw[name] for name in unchanged)
        comments_exact = expected.archive_comment == actual.archive_comment and all(
            expected.info[n].comment == actual.info[n].comment for n in wanted & set(actual.raw))
        # Non-content member properties must survive. Compression offsets/CRC
        # naturally differ after PII edits and are not semantic metadata.
        properties = ('date_time', 'compress_type', 'external_attr', 'internal_attr', 'create_system', 'extra')
        member_metadata_exact = inventory and all(
            all(getattr(expected.info[n], key) == getattr(actual.info[n], key) for key in properties)
            for n in wanted)
        scan = scan_ooxml(output, kind, source_path=source, review_decisions=review_decisions)
        correct = inventory and not wrong and comments_exact and member_metadata_exact
        return {'source_output_comparison_completed': True,
                'part_inventory_matches': inventory, 'unexpected_changed_parts': len(wrong),
                'all_retained_parts_exact': retained_exact,
                'zip_metadata_matches_allowed_transform': comments_exact and member_metadata_exact,
                'all_saved_values_match_expected_source_transform': correct,
                'protected_resource_identifiers_compared': analysis.protected_identifier_checks,
                'protected_resource_identifiers_preserved': correct,
                'values_checked': scan.get('values_checked', 0),
                'policy_scan_passed': bool(scan['policy_scan_passed'] and correct),
                'errors': scan['errors'] + ([] if correct else ['ooxml_unexpected_source_output_difference']),
                'source_changes': _metrics(expected, analysis)}
    except Exception:
        return {'source_output_comparison_completed': False, 'policy_scan_passed': False,
                'errors': ['ooxml_source_comparison_failed'], 'values_checked': 0}


def verify_xlsx(path, source_path=None, review_decisions=None):
    return scan_ooxml(path, 'xlsx', source_path, review_decisions)


def verify_docx(path, source_path=None, review_decisions=None):
    return scan_ooxml(path, 'docx', source_path, review_decisions)


def compare_xlsx(source, output, review_decisions=None):
    return compare_ooxml(source, output, 'xlsx', review_decisions)


def compare_docx(source, output, review_decisions=None):
    return compare_ooxml(source, output, 'docx', review_decisions)
