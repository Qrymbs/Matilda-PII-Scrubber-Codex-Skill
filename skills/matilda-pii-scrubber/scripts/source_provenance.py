"""Private local source binding; never add digests or paths to portable reports.

This manifest detects accidental source drift and stale review decisions. It is
not a signature or an authorization boundary against a writer who can replace
both the source and the manifest. Its file is created exclusively with mode600.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from scrub_core import ScrubError

PRIVATE_NAME = '.private-source-provenance.json'
_FILE_ID = re.compile(r'file\d{4,}')
_DIGEST = re.compile(r'[0-9a-f]{64}')


class SourceBoundRecords(list):
    """Run-only state kept outside the report's serialized records."""
    def __init__(self):
        super().__init__()
        self.source_bindings = {}
        self.run_id = None


def _stat_signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fingerprint_source(path, max_bytes=2 * 1024**3):
    """Hash the entire original and reject changes during the read."""
    path = Path(path)
    if path.is_symlink():
        raise ScrubError('source_provenance_source_unsafe')
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                raise ScrubError('source_provenance_source_unsafe')
            digest = hashlib.sha256()
            length = 0
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:break
                length += len(chunk)
                if length > max_bytes:raise ScrubError('source_provenance_source_unsafe')
                digest.update(chunk)
            after = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
        if (_stat_signature(before) != _stat_signature(after)
                or _stat_signature(after) != _stat_signature(current)
                or length != before.st_size):
            raise ScrubError('source_changed_during_provenance_read')
        return {'sha256': digest.hexdigest(), 'size': length,
                'basename_sha256': hashlib.sha256(os.fsencode(path.name)).hexdigest()}
    except ScrubError:
        raise
    except (OSError, ValueError):
        raise ScrubError('source_provenance_source_unreadable') from None


def _validate_binding(binding):
    return (isinstance(binding, dict) and set(binding) == {'sha256', 'size', 'basename_sha256'}
            and type(binding['size']) is int and binding['size'] >= 0
            and isinstance(binding['sha256'], str) and bool(_DIGEST.fullmatch(binding['sha256']))
            and isinstance(binding['basename_sha256'], str) and bool(_DIGEST.fullmatch(binding['basename_sha256'])))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:raise ScrubError('source_provenance_invalid')
        result[key] = value
    return result


def load_provenance(root, run_id):
    path = Path(root) / PRIVATE_NAME
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024**2:
            raise ScrubError('source_provenance_missing_or_unsafe')
        if os.name != 'nt' and stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ScrubError('source_provenance_permissions_unsafe')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
            document = json.load(stream, object_pairs_hook=_unique)
        if (not isinstance(document, dict) or set(document) != {'version', 'run_id', 'files'}
                or type(document['version']) is not int or document['version'] != 1
                or not isinstance(run_id, str) or not run_id or document['run_id'] != run_id
                or not isinstance(document['files'], dict)
                or any(not _FILE_ID.fullmatch(file_id) or not _validate_binding(binding)
                       for file_id, binding in document['files'].items())):
            raise ScrubError('source_provenance_invalid')
        return document['files']
    except ScrubError:
        raise
    except (OSError, ValueError, TypeError):
        raise ScrubError('source_provenance_missing_or_invalid') from None


def write_provenance(root, run_id, bindings):
    """Create once; repeated identical writes are checked, never overwritten."""
    if (not isinstance(run_id, str) or not run_id
            or not isinstance(bindings, dict)
            or any(not _FILE_ID.fullmatch(file_id) or not _validate_binding(binding)
                   for file_id, binding in bindings.items())):
        raise ScrubError('source_provenance_invalid')
    path = Path(root) / PRIVATE_NAME
    document = {'version': 1, 'run_id': run_id, 'files': bindings}
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        if load_provenance(root, run_id) != bindings:
            raise ScrubError('source_provenance_overwrite_forbidden')
        return
    except OSError:
        raise ScrubError('source_provenance_write_failed') from None
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(document, stream, ensure_ascii=True, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
    except (OSError, ValueError, TypeError):
        # An incomplete private manifest must never support a ready result.
        raise ScrubError('source_provenance_write_failed') from None


def require_source_match(bindings, file_id, source, max_bytes=2 * 1024**3):
    expected = bindings.get(file_id)
    if not _validate_binding(expected):
        raise ScrubError('source_provenance_binding_missing')
    actual = fingerprint_source(source, max_bytes)
    if actual != expected:
        raise ScrubError('source_changed_since_scrub')
    return actual
