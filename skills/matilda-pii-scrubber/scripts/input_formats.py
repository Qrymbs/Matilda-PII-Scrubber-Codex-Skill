"""Fixed intake scope and source-free guidance shared by entry points."""
from pathlib import Path

SUPPORTED_SUFFIXES = frozenset({'.csv', '.xlsx', '.xls', '.parquet'})
ARCHIVE_SUFFIXES = frozenset({
    '.zip', '.gz', '.gzip', '.tgz', '.tar', '.bz2', '.bzip2', '.tbz', '.tbz2',
    '.xz', '.txz', '.7z', '.rar', '.zst', '.zstd', '.lz', '.lzma', '.lzo', '.cab',
})

_GUIDANCE = {
    'compressed_input_extract_first': (
        'Extract or decompress the archive first, then provide the individual '
        '.csv, .xlsx, .xls, or .parquet files. The skill does not extract archives '
        'or produce a scrubbed archive.'),
    'unsupported_format': (
        'File type denied. This skill accepts only .csv, .xlsx, .xls, and '
        '.parquet. Supply an original export in an accepted format; do not '
        'rename an unsupported file extension.'),
    'unsupported_dependency_format': (
        'Only csv, xlsx, xls, and parquet are accepted format selections.'),
    'legacy_excel_converted_to_xlsx': (
        'Legacy .xls conversion cannot be approved for upload. Re-export or save '
        'the original workbook as a genuine .xlsx file, then run the skill again; '
        'do not rename the extension.'),
}


def guidance_for(code):
    """Return only maintained text, never exception strings or source values."""
    return _GUIDANCE.get(code)


def admission_error(path):
    """Reject by final suffix before parsing; detect disguised archive bytes.

    XLSX is itself a ZIP package, so its ZIP representation is left to the
    bounded OOXML parser. This is not general content-type inference: accepted
    formats still have to pass their actual parser and full verification.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in ARCHIVE_SUFFIXES:
        return 'compressed_input_extract_first'
    if suffix not in SUPPORTED_SUFFIXES:
        return 'unsupported_format'
    with path.open('rb') as stream:
        head = stream.read(8)
    compressed = (head.startswith(b'\x1f\x8b') or head.startswith(b'BZh')
                  or head.startswith(b'\xfd7zXZ\x00') or head.startswith(b'7z\xbc\xaf\x27\x1c')
                  or head.startswith(b'Rar!\x1a\x07') or head.startswith(b'\x28\xb5\x2f\xfd'))
    zipped = head.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'))
    if compressed or (zipped and suffix != '.xlsx'):
        return 'compressed_input_extract_first'
    if head.startswith(b'%PDF-'):
        return 'unsupported_format'
    return None
