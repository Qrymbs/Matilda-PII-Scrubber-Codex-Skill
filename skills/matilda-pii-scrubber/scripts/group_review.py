#!/usr/bin/env python3
"""Group CSV/TSV review coordinates using transient source values; never clear findings."""
from __future__ import annotations
import argparse
from collections import defaultdict
import csv
import json
import os
from pathlib import Path
import re

from review_support import read_json
from scrub_core import ScrubError
from scrub_structured import csv_layout, _text_encoding
from source_provenance import load_provenance, require_source_match


def ledger_path(root, reference):
    if not isinstance(reference, str):
        raise ScrubError('review_ledger_unavailable')
    path = root / reference
    if Path(reference).is_absolute() or '..' in Path(reference).parts:
        raise ScrubError('unsafe_review_ledger')
    if root.is_symlink() or any(p.is_symlink() for p in [path, *path.parents] if p == root or root in p.parents):
        raise ScrubError('unsafe_review_ledger')
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ScrubError('unsafe_review_ledger')
    return path


def group_file(root, record, source, verification):
    if record.get('input_format') != 'csv':
        return {'file_id': record['file_id'], 'grouping_supported': False,
                'reason': 'manual_format_specific_review_required'}
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise ScrubError('original_source_absent_or_unsafe')
    locations = defaultdict(set)
    references = [(record.get('review_location_index'), 'initial_candidate'),
                  (record.get('removal_location_index'), 'mask_review')]
    independent = verification.get('files', {}).get(record['file_id'], {})
    references.append((independent.get('independent_candidate_location_index'), 'independent_candidate'))
    for reference, kind in references:
        with ledger_path(root, reference).open(encoding='utf-8') as stream:
            for line in stream:
                event = json.loads(line)
                loc = event.get('location')
                if not isinstance(loc, str) or not re.fullmatch(r'r\d+\.c\d+|filename', loc):
                    raise ScrubError('unsupported_review_coordinate')
                locations[loc].add(kind)
    layout = csv_layout(source)
    header, delimiter = layout.headers, layout.delimiter
    groups = defaultdict(list)
    found = set()
    with source.open(encoding=_text_encoding(source), newline='') as stream:
        for row_index, row in enumerate(csv.reader(stream, delimiter=delimiter, strict=True), 1):
            expected_width = len(layout.preamble[row_index-1]) if row_index < layout.header_row else len(header)
            if len(row) != expected_width:
                raise ScrubError('ragged_csv_rows')
            for column_index, value in enumerate(row, 1):
                location = f'r{row_index}.c{column_index}'
                if location in locations:
                    # Raw equality keys live only in RAM. Different columns and
                    # header/data contexts never share a group. Neighboring fields
                    # still need review at each occurrence; no blanket exemption.
                    context = 'metadata' if row_index < layout.header_row else 'schema' if row_index == layout.header_row else 'data'
                    groups[(context, column_index, value, tuple(sorted(locations[location])))].append(location)
                    found.add(location)
    remaining = set(locations) - found
    if remaining - {'filename'}:
        raise ScrubError('review_coordinate_not_in_source')
    output = []
    for index, ((context, column, _value, reasons), coordinates) in enumerate(groups.items(), 1):
        output.append({'group_id': f'g{index}', 'column': column,
                       'context': context, 'review_kinds': list(reasons),
                       'occurrences': len(coordinates), 'representative_location': coordinates[0],
                       'locations': coordinates, 'decision': 'pending_context_review'})
    if 'filename' in remaining:
        output.append({'group_id': f'g{len(output)+1}', 'context': 'filename',
                       'review_kinds': sorted(locations['filename']), 'occurrences': 1,
                       'representative_location': 'filename', 'locations': ['filename'],
                       'decision': 'pending_context_review'})
    return {'file_id': record['file_id'], 'grouping_supported': True,
            'candidate_locations': len(locations), 'groups': output}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--source', action='append', default=[], metavar='FILE_ID=PATH')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); os.umask(0o077)
    try:
        report = read_json(args.report); root = args.report.parent
        verification = read_json(root / 'verification.json')
        sources = {}
        for pair in args.source:
            fid, sep, path = pair.partition('=')
            if not sep or not re.fullmatch(r'file\d{4,}', fid) or fid in sources or not path:
                raise ScrubError('invalid_source_argument')
            sources[fid] = path
        required = {r['file_id'] for r in report['files'] if r['input_format'] == 'csv'}
        if set(sources) != required:
            raise ScrubError('source_inventory_mismatch')
        bindings = load_provenance(root, report.get('run_id'))
        for file_id, source in sources.items():
            require_source_match(bindings, file_id, source)
        results = [group_file(root, r, sources.get(r['file_id']), verification) for r in report['files']]
        for file_id, source in sources.items():
            require_source_match(bindings, file_id, source)
        payload = {'version': 1, 'run_id': report['run_id'], 'readiness_modified': False,
                   'source_values_included': False,
                   'instruction': 'Review every occurrence in context; groups are suggestions, never decisions. Expand actual resolutions to exact coordinates in current-run review evidence.',
                   'files': results}
        if args.output.exists() or args.output.is_symlink():
            raise ScrubError('output_already_exists')
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(payload, stream, indent=2); stream.write('\n')
        args.output.chmod(0o600)
        print(json.dumps({'status': 'grouped_for_review', 'files': len(results), 'readiness_modified': False}))
        return 0
    except (ScrubError, ValueError, OSError, KeyError, TypeError) as exc:
        print(json.dumps({'error': getattr(exc, 'code', 'review_grouping_failed')}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
