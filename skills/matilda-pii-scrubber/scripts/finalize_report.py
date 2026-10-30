#!/usr/bin/env python3
"""Finalize after source comparison, full context evidence and candidate resolution."""
import argparse
from collections import Counter
import json
import logging
from pathlib import Path, PurePosixPath
import re
import sys
import warnings
from review_support import read_json, validate_evidence
from scrub_core import ScrubError, REVIEW_REASON_CODES, _SAFE_LOCATION
from verify_outputs import verify_directory
from scrub import POLICY_VERSION, PRIVACY_SCOPE, refresh_report_summaries, render_report_markdown, safe_error

def candidate_coverage(root, record, decisions):
    review = record.get('context_review', {})
    if review.get('unused_decision_count', 0) or review.get('review_location_coverage_complete') is False:
        return False
    reference = record.get('review_location_index')
    if not reference:
        return False
    path = root / reference
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        return False
    unresolved = 0
    counts, resolved_counts = Counter(), Counter()
    events, locations, resolved_locations = set(), set(), set()
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            event = json.loads(line)
            if (not isinstance(event, dict) or set(event) != {'reason', 'location', 'count', 'resolved'}
                    or type(event['count']) is not int or event['count'] != 1
                    or type(event['resolved']) is not bool):
                return False
            reason, location = event['reason'], event['location']
            if (not isinstance(reason, str) or reason not in REVIEW_REASON_CODES
                    or not isinstance(location, str) or not _SAFE_LOCATION.fullmatch(location)
                    or (reason, location) in events):
                return False
            events.add((reason, location))
            locations.add(location)
            counts[event['reason']] += event['count']
            if event.get('resolved'):
                if event.get('location') not in decisions:
                    return False
                resolved_counts[event['reason']] += event['count']
                resolved_locations.add(location)
                continue
            location = event.get('location')
            if reason in {'protected_identifier_contains_pii','schema_label_contains_pii','type_masking_conflict','formula_pii_requires_review','unsupported_content_uninspected'}:
                unresolved += 1
                continue
            if not location or location not in decisions or event.get('count', 1) != 1:
                unresolved += event.get('count', 1)
    return (unresolved == 0 and dict(counts) == review.get('review_counts', {})
            and dict(resolved_counts) == review.get('resolved_review_counts', {})
            and len(locations) == review.get('review_occurrences', 0)
            and len(resolved_locations) == review.get('resolved_review_occurrences', 0))


def relocate_artifact(root, record, destination):
    """Move one run-owned file without overwriting or following symlinks."""
    reference = record.get("artifact")
    if reference is None:
        return
    if destination not in {"ready", "blocked"} or not isinstance(reference, str) or "\\" in reference:
        raise ScrubError("unsafe_artifact_reference")
    parts = PurePosixPath(reference)
    if (parts.is_absolute() or ".." in parts.parts or len(parts.parts) not in {2, 3}
            or parts.parts[0] not in {"artifacts", "incomplete", "blocked", "ready"}
            or len(parts.parts) == 3 and parts.parts[1] != record.get("file_id")):
        raise ScrubError("unsafe_artifact_reference")
    source = root.joinpath(*parts.parts)
    target = root.joinpath(destination, *parts.parts[1:])
    for candidate in (source, target):
        current = candidate
        while current != root:
            if current.is_symlink():
                raise ScrubError("artifact_not_regular_file")
            current = current.parent
        if not candidate.resolve().is_relative_to(root.resolve()):
            raise ScrubError("unsafe_artifact_reference")
    if not source.is_file():
        raise ScrubError("artifact_absent")
    if source == target:
        return
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.exists():
        raise ScrubError("artifact_destination_already_exists")
    source.rename(target)
    target.chmod(0o600)
    record["artifact"] = target.relative_to(root).as_posix()


def save_reports(path, report, verification):
    refresh_report_summaries(report)
    for destination, value in ((path.parent / "verification.json", verification), (path, report)):
        destination.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        destination.chmod(0o600)
    markdown = path.with_suffix(".md")
    markdown.write_text(render_report_markdown(report), encoding="utf-8")
    markdown.chmod(0o600)


def invalidate_report(path, report):
    """Revoke earlier readiness before reading new evidence or running checks."""
    report["overall_status"] = "partial_or_blocked"
    report.pop("review_note", None)
    for record in report["files"]:
        record["submission_status"] = "blocked"
        if record.get("processing_status") == "completed":
            record["privacy_status"] = "requires_context_review"
        record["local_context_review_completed"] = False
        record["local_integrity_review_completed"] = False
        record.pop("verification", None)
        record.pop("unresolved_review_items", None)
        record.pop("review_evidence_run_id", None)
    pending = {"all_artifacts_passed": False, "files": {}, "errors": ["review_not_finalized"],
               "readiness_statuses_modified": True, "context_review_still_required": True}
    # Status is durably revoked first; then formerly-ready files leave ready/.
    save_reports(path, report, pending)
    for record in report["files"]:
        relocate_artifact(path.parent, record, "blocked")
        save_reports(path, report, pending)


def main():
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings('ignore')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report')
    parser.add_argument('--review-evidence', required=True, help='Current run-scoped complete Codex review evidence; no raw values')
    parser.add_argument('--source', action='append', default=[], metavar='FILE_ID=PATH', help='Original input, used transiently for exact comparison')
    parser.add_argument('--context-reviewed', action='store_true')
    parser.add_argument('--integrity-reviewed', action='store_true')
    args = parser.parse_args()
    report = None
    path = Path(args.report).absolute()
    try:
        report = read_json(path)
        if report.get('policy_version') != POLICY_VERSION or report.get('privacy_scope') != PRIVACY_SCOPE:
            raise ScrubError('report_policy_mismatch')
        if not report.get('files'):
            raise ScrubError('empty_report')
        invalidate_report(path, report)
        reviews = validate_evidence(read_json(args.review_evidence), report)
        sources = {}
        for pair in args.source:
            file_id, separator, source = pair.partition('=')
            if not separator or not re.fullmatch(r'file\d{4,}', file_id) or file_id in sources or not source:
                raise ScrubError('invalid_source_argument')
            sources[file_id] = Path(source)
        decisions = {}
        for record in report['files']:
            fid = record['file_id']
            applied = record.get('context_review', {}).get('applied_review_decisions', {})
            if isinstance(applied, list):
                applied = {item['location']: {key: value for key, value in item.items() if key != 'location'} for item in applied}
            decisions[fid] = dict(applied)
            for location, decision in reviews[fid]['decisions'].items():
                if location in decisions[fid] and decisions[fid][location] != decision:
                    raise ScrubError('review_decision_conflict')
                decisions[fid][location] = decision
        refresh_report_summaries(report)
        verification = verify_directory(path.parent, sources=sources, require_sources=True, review_decisions=decisions)
        for record in report['files']:
            fid = record['file_id']
            review = reviews[fid]
            check = verification.get('files', {}).get(fid, {})
            covered = review['coverage_complete'] and review['unresolved_items'] == 0 and candidate_coverage(path.parent, record, decisions[fid])
            passed = all(check.get(key) is True for key in ('policy_scan_passed', 'source_comparison_passed', 'independent_candidate_scan_passed', 'semantic_mask_review_passed', 'source_provenance_passed'))
            eligible = (record.get('processing_status') == 'completed' and covered and passed
                        and record.get('matilda_compatibility') != 'not_ready' and not record.get('policy_alignment_issues'))
            record['verification'] = check
            record['submission_status'] = 'ready_for_manual_submission' if eligible else 'blocked'
            record['privacy_status'] = 'completed' if eligible else 'requires_context_review' if record.get('processing_status') == 'completed' else record.get('processing_status', 'blocked')
            record['local_context_review_completed'] = bool(covered)
            record['local_integrity_review_completed'] = bool(check.get('source_comparison_passed'))
            record['review_evidence_run_id'] = report['run_id']
            record['unresolved_review_items'] = review['unresolved_items']
        by_id = {r['file_id']: r for r in report['files']}
        for record in reversed(report['files']):
            if record.get('parent_file_id') and record['submission_status'] != 'ready_for_manual_submission':
                parent = by_id[record['parent_file_id']]
                parent['submission_status'] = 'blocked'
                parent['privacy_status'] = 'requires_context_review'
        ready = sum(r['submission_status'] == 'ready_for_manual_submission' for r in report['files'])
        report['overall_status'] = 'ready_for_manual_submission' if ready == len(report['files']) else 'partial_or_blocked'
        report['review_note'] = 'Current-run Codex evidence, candidate resolution, independent candidate scanning and complete original/output comparisons are recorded per file. A ready result is not a zero-PII or Matilda-import guarantee.'
        for record in report["files"]:
            relocate_artifact(path.parent, record,
                              "ready" if record["submission_status"] == "ready_for_manual_submission" else "blocked")
        # The standalone verifier cannot attest to context review. Finalization
        # has now evaluated that evidence, so its saved summary must reflect it.
        verification['readiness_statuses_modified'] = True
        verification['context_review_still_required'] = any(
            not record.get('local_context_review_completed')
            or not record.get('verification', {}).get('semantic_mask_review_passed')
            for record in report['files'])
        save_reports(path, report, verification)
        print(json.dumps({'status': report['overall_status'], 'ready': ready, 'blocked': len(report['files']) - ready}))
        return 0 if ready == len(report['files']) else 2
    except Exception as exc:
        code = safe_error(exc)
        if report is not None and isinstance(report.get("files"), list):
            # No exception may leave an earlier ready result authoritative.
            try:
                report["overall_status"] = "partial_or_blocked"
                report.pop("review_note", None)
                for record in report["files"]:
                    record["submission_status"] = "blocked"
                    record["local_context_review_completed"] = False
                    record["local_integrity_review_completed"] = False
                    record.pop("verification", None)
                    try:
                        relocate_artifact(path.parent, record, "blocked")
                    except Exception as move_exc:
                        record["warnings"] = sorted(set(record.get("warnings", [])) | {safe_error(move_exc)})
                save_reports(path, report, {"all_artifacts_passed": False, "files": {}, "errors": [code],
                                           "readiness_statuses_modified": True, "context_review_still_required": True})
            except Exception:
                pass
        print(json.dumps({'error': code}))
        return 2

if __name__ == '__main__':
    sys.exit(main())
