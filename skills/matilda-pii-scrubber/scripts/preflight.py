#!/usr/bin/env python3
"""Synthetic processing AND finalization in this interpreter; no customer inputs."""
from __future__ import annotations
import argparse
import base64
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zlib

SCRIPTS = Path(__file__).resolve().parent
FORMATS = ('csv', 'xlsx', 'xls', 'parquet')
# Entirely synthetic, fixed expected values; never populated from customer data.
PERSON = 'Avery Stone'
RESOURCE = 'vm-preflight-001'
# A tiny synthetic BIFF8 workbook generated once with test-only xlwt 1.3.0.
# It contains only the same two headers and values as the other fixtures.
# Standard-library decoding adds no XLS preflight dependency for team installs.
XLS_FIXTURE = 'eNrtWE1ME0EU/mbb0h9LabGYgAlpSERBSCBevMACUTlJUA8aYwILXbChtGQtJHgRxR5NTDxpvJBw8YJ68Sd60JsHE4weTExMWo0nTyaaeICub153TVEONFH8yXyb+ebtmzc7rzvz3nT2xWqssHS3qYgf0AsPSnYQNRU6QSXo3kRB7bYtRbcOULEV/ikEAzSRNT48qn3ul3Mo57sIDXe8T4mBd1TOYAZD2YyZ2EYMsA+GkD70EAvcJE0EjexVPfM4807m22z5mLmPNVeYe8i2IE5jVR9qP+is4lNaC7dFIJ97n/u8YU03GvBMruILV0XZ1od+K2Wk/86GZm8Yy6B5GzQzpmWkC4jTBC7ji50APruR+iSh9NurFyD91416/yb6a5oXWIA9ygs8jzA+eGSLF4eMnLGGAZLAZQdgmeeys9a4OZJKUqKdmE2nM8a0SdE7N905Y5kT6dTk2VxnV1c32fbPmdZ84kSOgjYkkzYHeXRDkNfy4g8TJ1HHcoxDIEppfO3Wp5dHx4b1EdYscGIvp/890mPYuCh7UOcIt2jfuZ15P/MlfupulpuY47RwqW4dbnCEI4tsc5lbW2mcA4xX+t4KeR/J+Y/HHjTn3+ttJK8MFs/HV17rS2ih7ShJ/eW1iA7RIW5cl3iou7VwUsVb5saf0kZAizq+284eV4d1hFiMMZfv5NsRjr3YxF6wvebYC7aXU9mr1eMev56+io00BAUFBQUFBQUFBYU/AuH8cfc4Bw2fczzwO9911qmU1GeS/xbHkaUrRwfTw8hQbWG+qvWzCz7hPktssY/7vVDiJI1uYQpj7MdU1euXjnei8vdsuWP014VQteOXqvHzN4//DTiazXY='


def run(arguments):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, *map(str, arguments)], capture_output=True,
                          text=True, env=env, timeout=120)


def fixture(path, kind):
    row = {'resource_id': RESOURCE, 'fullname': PERSON}
    if kind == 'csv':
        with path.open('w', encoding='utf-8', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(row); writer.writerow(row.values())
    elif kind == 'parquet':
        import pyarrow as pa
        import pyarrow.parquet as pq
        pq.write_table(pa.table({key: [value] for key, value in row.items()}), path)
    elif kind == 'xlsx':
        from openpyxl import Workbook
        book = Workbook(); book.active.append(list(row)); book.active.append(list(row.values()))
        book.properties.creator = ''; book.properties.lastModifiedBy = ''
        book.save(path); book.close()
    elif kind == 'xls':
        path.write_bytes(zlib.decompress(base64.b64decode(XLS_FIXTURE)))
    else:
        raise ValueError('unsupported_preflight_format')


def correct_output(path, kind):
    expected = {'resource_id': RESOURCE, 'fullname': 'X' * 11}
    if kind == 'csv':
        with path.open(encoding='utf-8', newline='') as stream:
            return list(csv.reader(stream)) == [list(expected), list(expected.values())]
    if kind == 'parquet':
        import pyarrow.parquet as pq
        return pq.read_table(path).to_pydict() == {key: [value] for key, value in expected.items()}
    if kind in {'xlsx', 'xls'}:
        from openpyxl import load_workbook
        book = load_workbook(path, read_only=True)
        values = list(book.active.values); book.close()
        return values == [tuple(expected), tuple(expected.values())]
    return False


def check_format(root, kind):
    if kind not in FORMATS:
        return {'format': kind, 'passed': False, 'error': 'unsupported_preflight_format'}
    source = root / ('synthetic.' + kind); fixture(source, kind)
    original = source.read_bytes(); out = root / ('run-' + kind)
    expected_block = kind == 'xls'
    process = run([SCRIPTS / 'scrub.py', source, '--output-dir', out])
    if process.returncode != (2 if expected_block else 0):
        return {'format': kind, 'passed': False, 'error': 'synthetic_processing_failed'}
    report = json.loads((out / 'scrub-report.json').read_text())
    record = report['files'][0]
    if not record.get('artifact') or not correct_output(out / record['artifact'], kind) or source.read_bytes() != original:
        return {'format': kind, 'passed': False, 'error': 'independent_expected_output_mismatch'}
    if expected_block and (record['processing_status'] == 'completed'
                           or record.get('output_format') != 'xlsx'
                           or not record.get('metrics', {}).get('reconstructed_values_only')
                           or record.get('metrics', {}).get('formula_inspection_complete') is not False
                           or 'legacy_excel_converted_to_xlsx' not in record.get('warnings', [])):
        return {'format': kind, 'passed': False, 'error': 'legacy_xls_limit_not_reported'}
    events = [json.loads(line) for line in (out / record['removal_location_index']).read_text().splitlines()]
    # Location comes from the parser; expected category and spans are independently
    # authored above and compared to the ledger, not accepted from its detector.
    if len(events) != 1 or events[0]['category'] != 'human_names':
        return {'format': kind, 'passed': False, 'error': 'synthetic_mask_count_mismatch'}
    event = events[0]
    if event.get('spans') != [{'start': 0, 'end': 11}]:
        return {'format': kind, 'passed': False, 'error': 'synthetic_mask_span_mismatch'}
    from review_support import COVERAGE_FIELDS
    decisions = {event['location']: {'action': 'mask', 'reason_code': 'explicit_person_name',
                    'spans': [{'start': 0, 'end': 11, 'category': 'human_names'}]}}
    # For XLS this deliberately tests that even complete synthetic span evidence
    # cannot override incomplete legacy feature inspection/source comparison.
    evidence = {'version': 2, 'run_id': report['run_id'], 'files': {
        record['file_id']: {**{key: True for key in COVERAGE_FIELDS}, 'unresolved_items': 0, 'decisions': decisions}}}
    proof = out / 'review-evidence.json'; proof.write_text(json.dumps(evidence), encoding='utf-8')
    final = run([SCRIPTS / 'finalize_report.py', out / 'scrub-report.json', '--review-evidence', proof,
                 '--source', record['file_id'] + '=' + str(source)])
    final_record = json.loads((out / 'scrub-report.json').read_text())['files'][0]
    expected_status = 'blocked' if expected_block else 'ready_for_manual_submission'
    passed = (final.returncode == (2 if expected_block else 0)
              and final_record['submission_status'] == expected_status
              and correct_output(out / final_record['artifact'], kind) and source.read_bytes() == original)
    if expected_block:
        guidance = final_record.get('chat_summary', {}).get('next_action', '')
        passed = passed and '.xlsx' in guidance and 'original' in guidance
    return {'format': kind, 'passed': passed, 'processing_and_finalization_tested': True,
            'expected_submission_status': expected_status,
            **({'legacy_conversion_only': True,
                'note': 'Pass confirms XLS conversion remains blocked; it does not qualify XLS for upload.'}
               if expected_block else {}),
            **({} if passed else {'error': 'synthetic_finalization_failed'})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--formats', nargs='+', choices=FORMATS, default=['csv'])
    args = parser.parse_args()
    os.umask(0o077)
    formats = list(dict.fromkeys(args.formats))
    dependencies = run([SCRIPTS / 'scrub.py', '--check-dependencies', '--formats', *formats])
    if dependencies.returncode:
        print(json.dumps({'passed': False, 'error': 'required_dependencies_unavailable',
                          'formats': formats})); return 2
    results = []
    with tempfile.TemporaryDirectory(prefix='matilda-preflight-') as directory:
        for kind in formats:
            try:
                results.append(check_format(Path(directory), kind))
            except Exception:
                results.append({'format': kind, 'passed': False, 'error': 'synthetic_preflight_failed'})
    passed = all(row['passed'] for row in results)
    print(json.dumps({'passed': passed, 'synthetic_only': True, 'results': results}, indent=2))
    return 0 if passed else 2


if __name__ == '__main__':
    raise SystemExit(main())
