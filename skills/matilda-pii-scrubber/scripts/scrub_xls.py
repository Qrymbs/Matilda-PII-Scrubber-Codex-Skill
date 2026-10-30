"""Preservation-first BIFF8 XLS inspection and in-place-length text masking.

This module never reserializes a workbook. Every changed byte belongs to an
inspected scalar character. Unknown records, opaque streams and unsupported
features remain byte-exact and explicitly prevent upload readiness.
"""
from __future__ import annotations

from collections import defaultdict
import io
from pathlib import Path
import struct

from scrub_core import ScrubContext, ScrubError, is_protected_resource_field

MAX_FILE = 512 * 1024 * 1024
MAX_RECORDS = 4000000
MAX_TEXT = 16000000
MAX_CELLS = 1000000


def _u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def _bad():
    raise ScrubError('xls_binary_structure_invalid')


class _Compound:
    """Cross-check olefile's stream bytes against bounded physical mappings."""
    def __init__(self, raw):
        import olefile
        self.raw = raw
        self.ole = olefile.OleFileIO(io.BytesIO(raw), raise_defects=olefile.DEFECT_INCORRECT)
        self.sector = self.ole.sectorsize
        if self.sector not in {512, 4096} or len(raw) % self.sector:
            _bad()
        self.nsectors = len(raw) // self.sector - 1
        self.claimed = set()
        self.streams = {}
        self.maps = {}
        self.limitations = []
        if any(raw[512:self.sector]):
            self.limitations.append('xls_header_padding_uninspected')
        if self.ole.parsing_issues:
            self.limitations.append('xls_ole_parser_defects')
        root_chain = self._chain(self.ole.root.isectStart, self.ole.fat,
                                 self.nsectors) if self.ole.root.size else []
        if len(root_chain) != (self.ole.root.size + self.sector - 1) // self.sector: _bad()
        if root_chain and self.ole.root.size % self.sector:
            offset = (root_chain[-1] + 1) * self.sector + self.ole.root.size % self.sector
            if any(raw[offset:(root_chain[-1] + 2) * self.sector]):
                self.limitations.append('xls_root_mini_stream_padding_uninspected')
        self.claimed.update(root_chain)
        mini_claimed = set()
        for path in sorted(self.ole.listdir(streams=True, storages=False)):
            name = '/'.join(path)
            stream = self.ole.openstream(path).read()
            entry = self.ole.direntries[self.ole._find(path)]
            if entry.size != len(stream):
                _bad()
            if len(stream) < self.ole.minisectorcutoff and stream:
                chain = self._chain(entry.isectStart, self.ole.minifat,
                                    self.ole.root.size // self.ole.minisectorsize)
                if mini_claimed.intersection(chain): _bad()
                mini_claimed.update(chain)
                unit = self.ole.minisectorsize
                def mapping(pos, chain=chain, root_chain=root_chain, unit=unit):
                    mini_pos = chain[pos // unit] * unit + pos % unit
                    return (root_chain[mini_pos // self.sector] + 1) * self.sector + mini_pos % self.sector
            else:
                chain = self._chain(entry.isectStart, self.ole.fat, self.nsectors) if stream else []
                if self.claimed.intersection(chain): _bad()
                self.claimed.update(chain)
                unit = self.sector
                def mapping(pos, chain=chain):
                    return (chain[pos // self.sector] + 1) * self.sector + pos % self.sector
            if len(chain) != (len(stream) + unit - 1) // unit:
                _bad()
            # Check complete stream bytes without retaining a per-byte map.
            for start in range(0, len(stream), unit):
                offset = mapping(start)
                if raw[offset:offset + min(unit, len(stream) - start)] != stream[start:start + unit]:
                    _bad()
            self.streams[name], self.maps[name] = stream, mapping
            if stream and len(stream) % unit:
                offset = mapping(len(stream) - 1) + 1
                if any(raw[offset:offset + unit - len(stream) % unit]):
                    self.limitations.append('xls_nonzero_stream_slack_uninspected')
        # Account for CFB directory, MiniFAT, FAT and DIFAT sectors. Retained
        # nonzero unallocated/orphan sectors could contain historical data.
        directory_chain = self._chain(_u32(raw, 48), self.ole.fat, self.nsectors)
        reachable = {0} | {self.ole._find(path) for path in self.ole.listdir(streams=True, storages=True)}
        directory_index = 0
        for sid in directory_chain:
            sector = raw[(sid + 1) * self.sector:(sid + 2) * self.sector]
            for start in range(0, self.sector, 128):
                entry = sector[start:start + 128]
                name_length, kind = _u16(entry, 64), entry[66]
                if kind and directory_index not in reachable:
                    self.limitations.append('xls_unreachable_directory_entry_uninspected')
                directory_index += 1
                if kind == 0:
                    if (any(entry[:67] + entry[80:116] + entry[120:]) or entry[67] not in {0, 1}
                            or any(_u32(entry, offset) not in {0, 0xffffffff} for offset in (68, 72, 76))
                            or _u32(entry, 116) not in {0, 0xfffffffe, 0xffffffff}):
                        self.limitations.append('xls_unused_directory_text_uninspected')
                    continue
                if name_length < 2 or name_length > 64 or name_length % 2: _bad()
                if entry[name_length - 2:name_length] != b'\0\0': _bad()
                if any(entry[name_length:64]): self.limitations.append('xls_directory_padding_uninspected')
                if kind == 5 and entry[:name_length - 2].decode('utf-16le') != 'Root Entry':
                    self.limitations.append('xls_root_directory_name_uninspected')
        if self.ole.root.size % self.ole.minisectorsize: _bad()
        for sid in range(self.ole.root.size // self.ole.minisectorsize):
            if sid not in mini_claimed:
                pos = sid * self.ole.minisectorsize
                offset = (root_chain[pos // self.sector] + 1) * self.sector + pos % self.sector
                if any(raw[offset:offset + self.ole.minisectorsize]):
                    self.limitations.append('xls_unused_mini_stream_content_uninspected')
        for first in (_u32(raw, 48), _u32(raw, 60)):
            if first < 0xfffffffa:
                chain = self._chain(first, self.ole.fat, self.nsectors)
                if self.claimed.intersection(chain): _bad()
                self.claimed.update(chain)
        for sid in range(self.nsectors):
            if sid >= len(self.ole.fat):
                _bad()
            if self.ole.fat[sid] in {0xfffffffc, 0xfffffffd}:
                if sid in self.claimed: _bad()
                self.claimed.add(sid)
            if sid not in self.claimed and any(raw[(sid + 1) * self.sector:(sid + 2) * self.sector]):
                self.limitations.append('xls_unallocated_content_uninspected')
        # Directory names are structural; unknown storages are not inspected.
        if self.ole.listdir(streams=False, storages=True):
            self.limitations.append('xls_opaque_storage_uninspected')

    @staticmethod
    def _chain(first, fat, limit):
        chain, seen = [], set()
        while first != 0xfffffffe:
            if first >= limit or first >= len(fat) or first in seen:
                _bad()
            seen.add(first); chain.append(first); first = fat[first]
        return chain

    def close(self):
        self.ole.close()


def _decode_units(units):
    """Join UTF-16 units while preserving each codepoint's physical bytes."""
    chars, positions, index = [], [], 0
    while index < len(units):
        value, offsets = units[index]
        if 0xd800 <= value <= 0xdbff:
            if index + 1 >= len(units) or not 0xdc00 <= units[index + 1][0] <= 0xdfff:
                _bad()
            low, low_offsets = units[index + 1]
            chars.append(chr(0x10000 + ((value - 0xd800) << 10) + low - 0xdc00))
            positions.append(tuple(offsets) + tuple(low_offsets)); index += 2
        elif 0xdc00 <= value <= 0xdfff:
            _bad()
        else:
            chars.append(chr(value)); positions.append(tuple(offsets)); index += 1
    return ''.join(chars), positions


def _simple_unicode(data, start, mapping, short=False):
    width = 1 if short else 2
    if start + width > len(data): _bad()
    count = data[start] if short else _u16(data, start)
    if not count and start + width == len(data): return '', [], len(data)
    if start + width + 1 > len(data): _bad()
    flags = data[start + width]
    if flags & ~1: _bad()
    size = 2 if flags & 1 else 1
    begin = start + width + 1
    end = begin + count * size
    if end > len(data): _bad()
    units = []
    for pos in range(begin, end, size):
        value = _u16(data, pos) if size == 2 else data[pos]
        units.append((value, tuple(mapping(pos + j) for j in range(size))))
    text, positions = _decode_units(units)
    return text, positions, end


class _SSTCursor:
    def __init__(self, chunks, mapping):
        self.chunks, self.mapping, self.index, self.pos = chunks, mapping, 0, 8

    def advance(self):
        self.index += 1; self.pos = 0
        if self.index >= len(self.chunks): _bad()

    def fixed(self, length):
        data, _ = self.chunks[self.index]
        if self.pos == len(data): self.advance(); data, _ = self.chunks[self.index]
        if self.pos + length > len(data): _bad()
        out = data[self.pos:self.pos + length]; self.pos += length
        return out

    def skip(self, length):
        while length:
            data, _ = self.chunks[self.index]
            if self.pos == len(data): self.advance(); continue
            size = min(length, len(data) - self.pos)
            self.pos += size; length -= size

    def string(self):
        head = self.fixed(3); count, flags = _u16(head, 0), head[2]
        if flags & ~0x0d: _bad()
        runs = _u16(self.fixed(2), 0) if flags & 8 else 0
        phonetic = _u32(self.fixed(4), 0) if flags & 4 else 0
        units = []
        while len(units) < count:
            data, base = self.chunks[self.index]
            if self.pos == len(data):
                self.advance(); flags2 = self.fixed(1)[0]
                if flags2 & ~1: _bad()
                flags = (flags & ~1) | flags2
                data, base = self.chunks[self.index]
            size = 2 if flags & 1 else 1
            if self.pos + size > len(data): _bad()
            value = _u16(data, self.pos) if size == 2 else data[self.pos]
            units.append((value, tuple(self.mapping(base + self.pos + j) for j in range(size))))
            self.pos += size
        self.skip(runs * 4 + phonetic)
        value, offsets = _decode_units(units)
        return {'value': value, 'char_bytes': offsets, 'phonetic': bool(phonetic)}


# Records whose payload is numeric/bit fields, indices, formatting or layout.
# Unknown records fail closed. Text-bearing and variable structures are handled
# separately below; this is intentionally a data-export subset of BIFF8.
_FIXED = {
    0x00e1: {2}, 0x00c1: {2}, 0x00e2: {0}, 0x0042: {2}, 0x0161: {2},
    0x009c: {2}, 0x0019: {2}, 0x0012: {2}, 0x0063: {2}, 0x0013: {2},
    0x01af: {2}, 0x01bc: {2}, 0x0040: {2}, 0x008d: {2}, 0x003d: {18},
    0x0022: {2}, 0x000e: {2}, 0x01b7: {2}, 0x00da: {2}, 0x00e0: {20},
    0x0160: {2}, 0x000d: {2}, 0x000c: {2}, 0x000f: {2}, 0x0011: {2},
    0x0010: {8}, 0x005f: {2}, 0x0080: {8}, 0x0225: {4}, 0x0081: {2},
    0x0200: {14}, 0x002a: {2}, 0x002b: {2}, 0x0082: {2}, 0x0083: {2},
    0x0084: {2}, 0x0026: {8}, 0x0027: {8}, 0x0028: {8}, 0x0029: {8},
    0x00a1: {34}, 0x00dd: {2}, 0x0208: {16}, 0x023e: {10, 18},
    0x0203: {14}, 0x027e: {10}, 0x0205: {8}, 0x0201: {6}, 0x007d: {12},
    0x0055: {2}, 0x0099: {2}, 0x00a0: {4}, 0x0041: {10},
}


def inspect_xls(path):
    """Return private in-memory scalar/physical evidence; never persist it."""
    try:
        return _inspect_xls(Path(path))
    except ScrubError:
        raise
    except Exception:
        raise ScrubError('xls_unreadable_or_unsupported_structure') from None


def _inspect_xls(path):
    import xlrd
    if path.stat().st_size > MAX_FILE: raise ScrubError('xls_file_size_limit')
    raw = path.read_bytes()
    if len(raw) > MAX_FILE: raise ScrubError('xls_file_size_limit')
    compound = _Compound(raw)
    try:
        names = [name for name in ('Workbook', 'Book') if name in compound.streams]
        if len(names) != 1: raise ScrubError('xls_workbook_stream_required')
        name = names[0]; data = compound.streams[name]; mapping = compound.maps[name]
        limitations = list(compound.limitations)
        allowed_streams = {name, '\x05SummaryInformation', '\x05DocumentSummaryInformation', '\x01CompObj'}
        if set(compound.streams) - allowed_streams:
            limitations.append('xls_opaque_stream_uninspected')
        result = {'raw': raw, 'streams': compound.streams, 'items': [],
                  'sheets': [], 'cells': [], 'limitations': limitations}
        metadata_counter = 0
        def item(value, positions, field='text', structural=False, location=None, source_descriptor=None):
            nonlocal metadata_counter
            if location is None:
                metadata_counter += 1; location = f'root.p{metadata_counter}'
            result['items'].append({'location': location, 'field': field, 'value': value,
                'structural': structural, 'protected': structural or is_protected_resource_field(field),
                'char_bytes': positions,
                **({'source_descriptor': source_descriptor} if source_descriptor is not None else {})})
        records, pos = [], 0
        while pos + 4 <= len(data):
            if data[pos:pos + 4] == b'\0' * 4:
                if any(data[pos:]): limitations.append('xls_trailing_workbook_content_uninspected')
                break
            code, length = struct.unpack_from('<HH', data, pos)
            if length > 8224 or pos + 4 + length > len(data): _bad()
            records.append((code, data[pos + 4:pos + 4 + length], pos, pos + 4))
            pos += 4 + length
            if len(records) > MAX_RECORDS: raise ScrubError('xls_record_count_limit')
        if any(data[pos:]): limitations.append('xls_trailing_workbook_content_uninspected')
        if not records or records[0][0] != 0x0809: _bad()
        if _u16(records[0][1], 0) != 0x0600: raise ScrubError('xls_biff8_required')
        sst, sheet_offsets, bindings, consumed = [], [], {}, set()
        worksheet = 0; seen_sst = False; total_text = 0
        grid_bounds = defaultdict(lambda: [0, 0])
        for index, (code, payload, record_offset, base) in enumerate(records):
            if index in consumed: continue
            localmap = lambda offset, base=base: mapping(base + offset)
            def biff_item(value, positions, field='text', structural=False, location=None):
                item(value, positions, field, structural, location,
                     {'kind': 'biff_record', 'record_id': code, 'workbook_offset': record_offset})
            if worksheet and code == 0x0200:
                if len(payload) != 14: _bad()
                row_end, col_end = _u32(payload, 4), _u16(payload, 10)
                if row_end > 65536 or col_end > 256: _bad()
                grid_bounds[worksheet][0] = max(grid_bounds[worksheet][0], row_end)
                grid_bounds[worksheet][1] = max(grid_bounds[worksheet][1], col_end)
                if sum(rows * cols for rows, cols in grid_bounds.values()) > MAX_CELLS:
                    raise ScrubError('xls_cell_count_limit')
            if worksheet and code in {0x00fd, 0x0203, 0x027e, 0x0205, 0x0201, 0x0006, 0x0204, 0x00d6, 0x00bd, 0x00be}:
                if len(payload) < 6: _bad()
                row, col = _u16(payload, 0), _u16(payload, 2)
                if code in {0x00bd, 0x00be}: col = _u16(payload, len(payload) - 2)
                if col > 255: _bad()
                grid_bounds[worksheet][0] = max(grid_bounds[worksheet][0], row + 1)
                grid_bounds[worksheet][1] = max(grid_bounds[worksheet][1], col + 1)
                if sum(rows * cols for rows, cols in grid_bounds.values()) > MAX_CELLS:
                    raise ScrubError('xls_cell_count_limit')
            if code == 0x0809:
                if len(payload) != 16 or _u16(payload, 0) != 0x0600: _bad()
                kind = _u16(payload, 2)
                if kind == 0x10: worksheet += 1; sheet_offsets.append(record_offset)
                elif kind != 0x05 or index != 0: limitations.append('xls_unsupported_substream')
            elif code == 0x000a:
                if payload: _bad()
            elif code == 0x00fc:
                if seen_sst or len(payload) < 8: _bad()
                seen_sst = True; chunks = [(payload, base)]; following = index + 1
                while following < len(records) and records[following][0] == 0x003c:
                    chunks.append((records[following][1], records[following][3])); consumed.add(following); following += 1
                unique = _u32(payload, 4)
                if unique > MAX_TEXT: _bad()
                cursor = _SSTCursor(chunks, mapping)
                for _ in range(unique):
                    string = cursor.string(); total_text += len(string['value'])
                    if total_text > MAX_TEXT: raise ScrubError('xls_text_size_limit')
                    sst.append(string)
                    if string['phonetic']: limitations.append('xls_phonetic_text_uninspected')
                if cursor.index != len(chunks) - 1 or cursor.pos != len(chunks[-1][0]): _bad()
            elif code == 0x00fd:
                if len(payload) != 10 or worksheet == 0: _bad()
                row, col, xf, string_id = struct.unpack('<HHHI', payload)
                key = (worksheet, row, col)
                if key in bindings: _bad()
                bindings[key] = string_id
            elif code == 0x0085:
                if len(payload) < 8: _bad()
                text, positions, end = _simple_unicode(payload, 6, localmap, short=True)
                if end != len(payload): _bad()
                if payload[5] != 0: limitations.append('xls_nonworksheet_sheet_uninspected')
                biff_item(text, positions, 'sheet_name', True, f's{len(result["sheets"]) + 1}')
                result['sheets'].append({'name': text, 'offset': _u32(payload, 0), 'visibility': payload[4]})
            elif code in {0x0014, 0x0015}:
                if not payload: continue
                text, positions, end = _simple_unicode(payload, 0, localmap)
                if end != len(payload): _bad()
                biff_item(text, positions, 'text')
            elif code == 0x005c:
                if len(payload) != 112: _bad()
                # BIFF8 Unicode form and the widespread xlwt padded ANSI form.
                if _u16(payload, 0) <= 54 and payload[2] in {0, 1}:
                    text, positions, end = _simple_unicode(payload, 0, localmap)
                    if any(byte not in {0, 32} for byte in payload[end:]):
                        limitations.append('xls_writeaccess_padding_uninspected')
                else:
                    clean = payload.rstrip(b' \0')
                    text = clean.decode('cp1252')
                    positions = [(localmap(j),) for j in range(len(clean))]
                biff_item(text, positions, 'author')
            elif code == 0x0031:
                if len(payload) < 16: _bad()
                text, positions, end = _simple_unicode(payload, 14, localmap, short=True)
                if end != len(payload): _bad()
                biff_item(text, positions, 'schema_label', True)
            elif code == 0x041e:
                if len(payload) < 5: _bad()
                text, positions, end = _simple_unicode(payload, 2, localmap)
                if end != len(payload): _bad()
                biff_item(text, positions, 'schema_label', True)
            elif code == 0x0293:
                if len(payload) < 4: _bad()
                if not _u16(payload, 0) & 0x8000:
                    text, positions, end = _simple_unicode(payload, 2, localmap)
                    if end != len(payload): _bad()
                    biff_item(text, positions, 'schema_label', True)
                elif len(payload) != 4: _bad()
            elif code in {0x0006, 0x0207, 0x04bc, 0x0221, 0x0236}:
                limitations.append('xls_formula_content_uninspected')
            elif code == 0x002f:
                raise ScrubError('xls_encrypted_workbook')
            elif code in _FIXED:
                if len(payload) not in _FIXED[code]: _bad()
            elif code == 0x013d:
                if len(payload) % 2: _bad()
            elif code in {0x001a, 0x001b}:
                if len(payload) < 2 or len(payload) != 2 + _u16(payload, 0) * 6: _bad()
            elif code == 0x0092:
                if len(payload) < 2 or len(payload) != 2 + _u16(payload, 0) * 4: _bad()
            elif code == 0x00e5:
                if len(payload) < 2 or len(payload) != 2 + _u16(payload, 0) * 8: _bad()
            elif code in {0x00bd, 0x00be}:
                stride = 6 if code == 0x00bd else 2
                if len(payload) < 6 or (len(payload) - 6) % stride: _bad()
            elif code == 0x00ff:
                if len(payload) < 2 or (len(payload) - 2) % 8: _bad()
            elif code in {0x020b, 0x00d7}:
                prefix, stride = (16, 4) if code == 0x020b else (4, 2)
                if len(payload) < prefix or (len(payload) - prefix) % stride: _bad()
            elif code == 0x001d:
                if len(payload) < 9 or len(payload) != 9 + _u16(payload, 7) * 6: _bad()
            else:
                limitations.append('xls_unknown_record_uninspected')
        if [s['offset'] for s in result['sheets']] != sheet_offsets: _bad()
        for sheet in result['sheets']:
            del sheet['offset']
        # xlrd is a second parser for visible/hidden cell semantics and styles.
        book = xlrd.open_workbook(file_contents=raw, formatting_info=True, logfile=io.StringIO())
        try:
            if book.biff_version != 80 or book.nsheets != len(result['sheets']): _bad()
            used = set()
            for si, sheet in enumerate(book.sheets(), 1):
                info = result['sheets'][si - 1]
                if sheet.name != info['name'] or sheet.visibility != info['visibility']: _bad()
                info.update(nrows=sheet.nrows, ncols=sheet.ncols)
                if sum(value.get('nrows', 0) * value.get('ncols', 0) for value in result['sheets']) > MAX_CELLS:
                    raise ScrubError('xls_cell_count_limit')
                headers = sheet.row_values(0) if sheet.nrows else []
                for ri in range(sheet.nrows):
                    for ci in range(sheet.ncols):
                        cell = sheet.cell(ri, ci); location = f's{si}.r{ri + 1}.c{ci + 1}'
                        field = 'schema_label' if ri == 0 else headers[ci] if ci < len(headers) else None
                        positions = []
                        if cell.ctype == xlrd.XL_CELL_TEXT:
                            key = (si, ri, ci)
                            if key not in bindings:
                                limitations.append('xls_inline_or_formula_text_uninspected')
                            else:
                                sid = bindings[key]
                                if sid >= len(sst) or sst[sid]['value'] != cell.value: _bad()
                                positions = sst[sid]['char_bytes']; used.add(sid)
                        entry = {'location': location, 'field': field, 'value': cell.value,
                                 'ctype': cell.ctype, 'xf_index': cell.xf_index}
                        result['cells'].append(entry)
                        item(cell.value, positions, field, ri == 0, location)
            for sid, string in enumerate(sst):
                if sid not in used:
                    item(string['value'], string['char_bytes'], 'text', False, f'root.i{sid + 1}')
        finally:
            book.release_resources()
        for metadata in ('\x05SummaryInformation', '\x05DocumentSummaryInformation'):
            if metadata in compound.streams:
                _properties(compound.streams[metadata], compound.maps[metadata], metadata, item, limitations)
        if '\x01CompObj' in compound.streams:
            _compobj(compound.streams['\x01CompObj'], compound.maps['\x01CompObj'], item, limitations)
        result['limitations'] = sorted(set(limitations))
        return result
    finally:
        compound.close()


def _properties(data, mapping, name, add, limitations):
    if len(data) < 48 or data[:2] != b'\xfe\xff' or _u16(data, 2) not in {0, 1}: _bad()
    sets = _u32(data, 24)
    if sets not in {1, 2} or len(data) < 28 + sets * 20: _bad()
    summary_guid = bytes.fromhex('e0859ff2f94f6810ab9108002b27b3d9')
    document_guid = bytes.fromhex('02d5cdd59c2e1b10939708002b2cf9ae')
    expected = summary_guid if name == '\x05SummaryInformation' else document_guid
    sections = []
    header_end = 28 + sets * 20
    for section in range(sets):
        start = _u32(data, 44 + section * 20)
        if start < header_end or start + 8 > len(data): _bad()
        size = _u32(data, start)
        if size < 8 or start + size > len(data): _bad()
        sections.append((start, start + size))
    position = header_end
    for start, end in sorted(sections):
        if start < position: _bad()
        if any(data[position:start]): limitations.append('xls_metadata_padding_uninspected')
        position = end
    if any(data[position:]): limitations.append('xls_metadata_padding_uninspected')
    for section in range(sets):
        start, section_end = sections[section]
        size, count = _u32(data, start), _u32(data, start + 4)
        if size < 8 or start + size > len(data) or count > 100000 or 8 + count * 8 > size: _bad()
        fmtid = data[28 + section * 20:44 + section * 20]
        if section != 0 or fmtid != expected:
            limitations.append('xls_custom_property_section_uninspected')
            continue
        props = [(_u32(data, start + 8 + i * 8), _u32(data, start + 12 + i * 8)) for i in range(count)]
        if len({p for p, _ in props}) != len(props) or len({o for _, o in props}) != len(props): _bad()
        for _, offset in props:
            if offset < 8 + count * 8 or offset + 4 > size: _bad()
        if not any(pid == 1 for pid, _ in props):
            limitations.append('xls_metadata_codepage_missing')
            continue
        codepage = 1252
        for pid, offset in props:
            if pid == 1:
                if _u32(data, start + offset) != 2 or offset + 6 > size: _bad()
                codepage = _u16(data, start + offset + 4)
        fields = ({2: 'text', 3: 'text', 4: 'author', 5: 'text', 6: 'comments',
                   7: 'path', 8: 'lastmodifiedby', 9: 'text', 18: 'text'}
                  if name == '\x05SummaryInformation' else {12: 'schema_label', 13: 'sheet_name', 14: 'author', 15: 'company'})
        ordered = sorted(props, key=lambda value: value[1])
        table_end = start + 8 + count * 8
        first_property = start + ordered[0][1] if ordered else section_end
        if any(data[table_end:first_property]): limitations.append('xls_metadata_padding_uninspected')
        for index, (pid, offset) in enumerate(ordered):
            end = ordered[index + 1][1] if index + 1 < len(ordered) else size
            begin = start + offset; bound = start + end
            if pid == 0:
                limitations.append('xls_custom_property_dictionary_uninspected'); continue
            kind = _u32(data, begin)
            def property_item(value, positions, field, structural=False):
                add(value, positions, field, structural, source_descriptor={
                    'kind': 'ole_property', 'stream': name.lstrip('\x05'),
                    'section': section + 1, 'property_id': pid, 'property_type': kind})
            value_end = _property_value(data, begin + 4, bound, kind, codepage,
                                        mapping, property_item, fields.get(pid, 'text'), limitations)
            if any(data[value_end:bound]):
                limitations.append('xls_metadata_padding_uninspected')


def _property_value(data, pos, bound, kind, codepage, mapping, add, field, limitations, depth=0):
    if depth > 2: _bad()
    structural = field in {'schema_label', 'sheet_name'}
    if kind in {0x101e, 0x101f, 0x100c}:
        if pos + 4 > bound: _bad()
        count = _u32(data, pos); pos += 4
        if count > 100000: _bad()
        for _ in range(count):
            child_kind = kind & 0xfff
            if child_kind == 12:
                if pos + 4 > bound: _bad()
                child_kind = _u32(data, pos); pos += 4
            before = pos
            pos = _property_value(data, pos, bound, child_kind, codepage, mapping, add, field, limitations, depth + 1)
            if pos < before or pos > bound: _bad()
        return pos
    if kind in {30, 31}:
        if pos + 4 > bound: _bad()
        count = _u32(data, pos); pos += 4
        wide = kind == 31 or codepage == 1200
        length = count * 2 if kind == 31 else count
        if wide and length % 2 or pos + length > bound: _bad()
        value_end = pos + length; payload = data[pos:value_end]
        if count == 0:
            text, positions = '', []
        elif wide:
            if not payload.endswith(b'\0\0'): _bad()
            units = [(_u16(payload, at), (mapping(pos + at), mapping(pos + at + 1)))
                     for at in range(0, len(payload) - 2, 2)]
            text, positions = _decode_units(units)
        else:
            if not payload.endswith(b'\0'): _bad()
            if codepage not in {1252, 28591, 20127, 65001}:
                limitations.append('xls_metadata_codepage_uninspected'); return bound
            encoding = {1252: 'cp1252', 28591: 'latin1', 20127: 'ascii', 65001: 'utf-8'}[codepage]
            text = payload[:-1].decode(encoding); positions = []; at = pos
            for char in text:
                width = len(char.encode(encoding)); positions.append(tuple(mapping(at + j) for j in range(width))); at += width
            if codepage == 65001 and any(len(p) != 1 for p in positions):
                limitations.append('xls_multibyte_metadata_uninspected'); positions = []
        add(text, positions, field, structural)
    elif kind in {0, 1}:
        value_end = pos
        add(None, [], field, structural)
    elif kind in {2, 3, 4, 5, 6, 7, 10, 11, 16, 17, 18, 19, 20, 21, 64}:
        import math
        fmt = {2: 'h', 3: 'i', 4: 'f', 5: 'd', 6: 'q', 7: 'd', 10: 'I', 11: 'h',
               16: 'b', 17: 'B', 18: 'H', 19: 'I', 20: 'q', 21: 'Q', 64: 'Q'}[kind]
        value_end = pos + struct.calcsize(fmt)
        if value_end > bound: _bad()
        value = struct.unpack_from('<' + fmt, data, pos)[0]
        if kind == 11:
            if value not in {-1, 0}: _bad()
            value = bool(value)
        if isinstance(value, float) and not math.isfinite(value):
            limitations.append('xls_nonfinite_metadata_uninspected')
        else:
            add(value, [], field, structural)
    else:
        limitations.append('xls_metadata_type_uninspected'); return bound
    padded = (value_end + 3) // 4 * 4
    if padded > bound: _bad()
    if any(data[value_end:padded]): limitations.append('xls_metadata_padding_uninspected')
    return padded


def _compobj(data, mapping, add, limitations):
    """Inspect standard Excel application identity strings; preserve all bytes."""
    if len(data) < 32: _bad()
    # The reserved header is opaque by specification. Recognize only the
    # standard Excel class forms, otherwise keep the file blocked.
    known = {bytes.fromhex('0100feff030a0000ffffffff') + bytes.fromhex(guid)
             for guid in ('1008020000000000c000000000000046', '2008020000000000c000000000000046')}
    if data[:28] not in known:
        limitations.append('xls_compobj_header_uninspected')
    pos = 28
    component = 0
    def string(wide=False, clipboard=False, maximum=100000):
        nonlocal pos, component
        component += 1
        descriptor = {'kind': 'ole_compobj', 'component': component}
        if pos + 4 > len(data): _bad()
        count = _u32(data, pos); pos += 4
        if clipboard and count in {0xfffffffe, 0xffffffff}:
            if pos + 4 > len(data): _bad()
            pos += 4; return 0
        if count > maximum: _bad()
        if count == 0:
            add('', [], 'schema_label', True, source_descriptor=descriptor); return 0
        length = count * (2 if wide else 1)
        if pos + length > len(data): _bad()
        payload = data[pos:pos + length]
        if wide:
            if not payload.endswith(b'\0\0'): _bad()
            units = [(_u16(payload, at), (mapping(pos + at), mapping(pos + at + 1)))
                     for at in range(0, length - 2, 2)]
            text, positions = _decode_units(units)
        else:
            if not payload.endswith(b'\0'): _bad()
            if any(byte >= 128 for byte in payload):
                limitations.append('xls_compobj_ansi_codepage_uninspected')
            text = payload[:-1].decode('latin1')
            positions = [(mapping(pos + at),) for at in range(length - 1)]
        add(text, positions, 'schema_label', True, source_descriptor=descriptor); pos += length
        return count
    string(); string(clipboard=True, maximum=400)
    if pos == len(data): return
    count = string(maximum=40)
    if not count:
        if any(data[pos:]): limitations.append('xls_compobj_tail_uninspected')
        return
    if pos == len(data): return
    if pos + 4 > len(data): _bad()
    marker = _u32(data, pos); pos += 4
    if marker != 0x71b239f4:
        if marker or any(data[pos:]): limitations.append('xls_compobj_tail_uninspected')
        return
    string(wide=True); string(wide=True, clipboard=True, maximum=400); string(wide=True)
    if any(data[pos:]): limitations.append('xls_compobj_tail_uninspected')


def scrub_xls(src, dst, ctx):
    """Create a native XLS copy, masking only compatible inspected spans."""
    src, dst = Path(src), Path(dst)
    if src.resolve() == dst.resolve(): raise ScrubError('source_output_collision')
    if dst.exists(): raise ScrubError('output_already_exists')
    if dst.suffix.lower() != '.xls': raise ScrubError('xls_requires_native_output')
    inspection = inspect_xls(src)
    limitations = set(inspection['limitations']); proposed = []; groups = defaultdict(list)
    for index, entry in enumerate(inspection['items']):
        preview = ScrubContext(review_decisions=ctx.review_decisions)
        desired = preview.scrub(entry['value'], field=entry['field'], location=entry['location'])
        proposed.append(desired)
        if entry['char_bytes']:
            groups[tuple(entry['char_bytes'])].append(index)
    blocked = set()
    for indices in groups.values():
        if len({proposed[index] for index in indices}) > 1:
            blocked.update(indices); limitations.add('xls_shared_string_mask_conflict')
    for index, entry in enumerate(inspection['items']):
        value, desired = entry['value'], proposed[index]
        if value == desired: continue
        if (not isinstance(value, str) or not isinstance(desired, str) or len(value) != len(desired)
                or len(entry['char_bytes']) != len(value)
                or any(len(entry['char_bytes'][n]) not in {1, 2}
                       for n, (before, after) in enumerate(zip(value, desired)) if before != after)):
            blocked.add(index); limitations.add('xls_character_width_mask_conflict')
    output = bytearray(inspection['raw']); patches = {}
    for index, entry in enumerate(inspection['items']):
        location, value, field = entry['location'], entry['value'], entry['field']
        if index in blocked:
            decision = ctx.review_decisions.pop(location, None)
            try: ctx.scrub(value, field=field, location=location, spans=[])
            finally:
                if decision is not None: ctx.review_decisions[location] = decision
            ctx.note_review('unsupported_content_uninspected', location)
            continue
        desired = ctx.scrub(value, field=field, location=location)
        if desired != value:
            for n, (before, after) in enumerate(zip(value, desired)):
                if before == after: continue
                if after != 'X': raise ScrubError('xls_non_x_replacement_refused')
                offsets = entry['char_bytes'][n]; encoded = b'X' if len(offsets) == 1 else b'X\0'
                for offset, byte in zip(offsets, encoded):
                    if offset in patches and patches[offset] != byte: raise ScrubError('xls_overlapping_mask_conflict')
                    patches[offset] = byte
    for offset, byte in patches.items(): output[offset] = byte
    for code in sorted(limitations): ctx.warn(code)
    dst.write_bytes(output)
    # Reopen all native structures; no derived values-only representation.
    after = inspect_xls(dst)
    if after['limitations'] != inspection['limitations'] or len(after['items']) != len(inspection['items']):
        dst.unlink(); raise ScrubError('xls_roundtrip_inspection_changed')
    rows = sum(max(0, sheet['nrows'] - 1) for sheet in inspection['sheets'])
    return {'sheets': len(inspection['sheets']), 'rows': rows, 'input_rows': rows, 'output_rows': rows,
            'output_extension': '.xls', 'native_xls_preserved': True, 'reconstructed_values_only': False,
            'formula_inspection_complete': 'xls_formula_content_uninspected' not in limitations,
            'incomplete': bool(limitations), 'format_limitations': sorted(limitations),
            'join_keys_removed': False, 'mandatory_fields_nulled': False}
