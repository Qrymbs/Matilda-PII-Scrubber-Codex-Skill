#!/usr/bin/env python3
"""Local explicit-human-PII scrubber. Never uploads or prints source data."""
from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import sys
import warnings
from uuid import uuid4
from urllib.parse import quote

from scrub_core import ScrubContext, ScrubError
from input_formats import ARCHIVE_SUFFIXES, SUPPORTED_SUFFIXES, admission_error, guidance_for
from review_support import load_plan
from source_provenance import (SourceBoundRecords, fingerprint_source, write_provenance,
                               load_provenance, require_source_match)
import scrub_structured as structured

POLICY_VERSION = "5.0-reviewed-spans"
PRIVACY_SCOPE = ["explicit_human_pii"]
SUPPORTED = SUPPORTED_SUFFIXES
DEPENDENCIES = {
    "lxml": "Required by final verification and OOXML adapters",
    "numpy": "Parquet; optional CSV acceleration",
    "pyarrow": "Parquet; optional CSV acceleration",
    "openpyxl": "XLSX preflight and test tooling",
    "xlrd": "Independent native XLS cell/type inspection",
    "olefile": "Native XLS container inspection",
}

HUMAN_REASONS = {
    "human_names": ("Human names", "An explicit person's name was present in the field or item."),
    "human_email_addresses": ("Personal email addresses", "An email address was explicitly attributable to a human."),
    "human_phone_numbers": ("Personal phone numbers", "A phone number was explicitly attributable to a human."),
    "human_government_identifiers": ("Human government identifiers", "The value explicitly identified a person's government identity record."),
    "human_usernames": ("Human usernames", "The value explicitly identified a person's user account."),
    "human_home_addresses": ("Home or personal postal addresses", "The item explicitly described a person's address."),
    "human_birth_dates": ("Personal birth dates", "The field or item explicitly described a person's birth date."),
    "human_employee_student_patient_identifiers": ("Employee, student or patient identifiers", "The identifier was explicitly associated with a human record."),
    "human_personal_financial_data": ("Personal financial records", "The field explicitly described a person's finances, rather than cloud billing."),
    "human_sensitive_personal_data": ("Sensitive personal information", "The item explicitly described private attributes or records of a human."),
    "human_personal_credentials": ("Human personal credentials", "The credential was explicitly attributable to a person's account."),
}
NON_PII_REASONS = {
    "dynamic_schema_labels": ("Schema labels", "An affected structural label was neutralized; this is reported separately from human PII values."),
    "formula_or_executable_cells": ("Formula or executable representation", "The adapter changed executable content for local format or safety handling; this is not itself confirmed human PII."),
    "document_metadata": ("Container metadata", "The adapter changed container metadata; this operation is not itself confirmed human PII."),
    "comments_and_annotations": ("Comments or annotations", "The adapter changed ancillary content; this operation is not itself confirmed human PII."),
    "embedded_objects_and_links": ("Embedded objects or links", "The adapter changed ancillary container content; this is a format or inspection limitation."),
    "workbook_structure_metadata": ("Workbook structure metadata", "The adapter changed workbook representation or metadata."),
    "hidden_sheet_state": ("Sheet visibility", "Sheet visibility changed during local reconstruction."),
    "archive_entry_names": ("Archive entry names", "Output archive members use neutral local names; original archive paths are not reproduced in reports."),
    "archive_entry_metadata": ("Archive entry metadata", "Archive timestamps and entry metadata were normalized during reconstruction."),
    "archive_comments": ("Archive comments", "Archive comments were omitted during reconstruction; not counted as confirmed human PII."),
    "compression_metadata": ("Compression header metadata", "Compression-header filename and timestamp representation was normalized."),
}
LEGACY_BROAD_REMOVALS = {
    "unrecognized_fields", "provider_catalog_identifiers", "unexpected_values_in_technical_fields",
    "customer_infrastructure_identifiers", "free_text_and_relationships", "dates_and_locations",
    "credentials_and_secrets", "personal_identifiers",
}
COMPATIBILITY_LOSS_WARNINGS = {"schema_changed", "join_keys_removed", "mandatory_fields_nulled", "nested_compatibility_conflict", "known_required_formula_cache_loss"}


def _safe_codes(values):
    """Only fixed, source-free codes may reach a generated summary."""
    if not isinstance(values, (list, tuple, set)):
        return []
    return sorted({v for v in values if isinstance(v, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,119}", v)})


def _category_summary(counts):
    human, other, unclassified = [], [], []
    for category, count in sorted(counts.items()):
        if not isinstance(category, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", category):
            category = "unclassified_change"
        count = max(0, int(count))
        if category in HUMAN_REASONS:
            label, reason = HUMAN_REASONS[category]
            target = human
        elif category.startswith("human_"):
            label, reason = "Human personal information", "Explicit human PII characters were replaced with uppercase X."
            target = human
        elif category in NON_PII_REASONS:
            label, reason = NON_PII_REASONS[category]
            target = other
        else:
            label, reason = "Unclassified adapter change", "The adapter did not provide an explicit human PII reason; review the scope before release."
            target = unclassified
        target.append({"category": category, "data_type": label, "count": count, "why": reason})
    return {"human_pii": human, "non_pii_changes": other, "unclassified_changes": unclassified}


def refresh_report_summaries(report):
    totals = {}
    limitation_totals = {}
    for record in report.get("files", []):
        next_action = None
        for code in ('compressed_input_extract_first', 'unsupported_format', 'legacy_excel_converted_to_xlsx'):
            if code in record.get('warnings', []):
                next_action = guidance_for(code)
                break
        # Historical reports may predate the intake warning codes. Preserve
        # actionable, fixed guidance when current verification rejects them.
        input_format = record.get('input_format')
        if next_action is None and isinstance(input_format, str):
            if '.' + input_format in ARCHIVE_SUFFIXES:
                next_action = guidance_for('compressed_input_extract_first')
            elif '.' + input_format not in SUPPORTED_SUFFIXES:
                next_action = guidance_for('unsupported_format')
        if record.get('input_format') == 'xls' and record.get('metrics', {}).get('format_limitations'):
            next_action = guidance_for('native_xls_inspection_incomplete')
        record['next_action'] = next_action
        counts = record.get("counts_by_category", {})
        for category, count in counts.items():
            totals[category] = totals.get(category, 0) + max(0, int(count))
        record["change_summary"] = _category_summary(counts)
        limitations = _safe_codes(record.get("metrics", {}).get("format_limitations", []))
        record["format_limitations"] = limitations
        for code in limitations:
            limitation_totals[code] = limitation_totals.get(code, 0) + 1
            record["change_summary"]["non_pii_changes"].append(_format_limitation_summary(code, 1))
        issues = sorted(set(counts) & LEGACY_BROAD_REMOVALS)
        if record["change_summary"]["unclassified_changes"]:
            issues.append("unclassified_change_reason")
        record["policy_alignment_issues"] = sorted(set(issues))
        if issues:
            record["submission_status"] = "blocked"
        check = record.get("verification", {})
        metrics = record.get("metrics", {})
        record["chat_summary"] = {
            "file_id": record["file_id"], "output_link": record.get("artifact"),
            "processing_status": record.get("processing_status"),
            "submission_status": record.get("submission_status"),
            "next_action": next_action,
            "counts_by_human_pii_type": {key: counts.get(key, 0) for key in HUMAN_REASONS},
            "category_counts_overlap": True,
            "masked_items": metrics.get("masked_items", 0),
            "masked_spans": metrics.get("masked_spans", 0),
            "masked_characters": metrics.get("masked_characters", 0),
            "representative_locations": record.get("locations", {}),
            "masking_location_ledger": record.get("removal_location_index"),
            "context_candidate_ledger": record.get("review_location_index"),
            "independent_candidate_ledger": check.get("independent_candidate_location_index"),
            "context_unresolved_items": record.get("unresolved_review_items"),
            "verifier_unresolved_candidates": check.get("unresolved_candidate_count"),
            "source_comparison_passed": check.get("source_comparison_passed", False),
            "source_provenance_passed": check.get("source_provenance_passed", False),
            "semantic_mask_review_passed": check.get("semantic_mask_review_passed", False),
            "protected_identifiers_preserved": check.get("protected_resource_identifiers_preserved", False),
            "new_resource_collisions": check.get("new_resource_key_collisions"),
            "format_limitations": limitations,
            "matilda_import_acceptance": "unverified",
        }
    report["counts_by_category"] = totals
    report["change_summary"] = _category_summary(totals)
    report["change_summary"]["non_pii_changes"].extend(_format_limitation_summary(code, count) for code, count in sorted(limitation_totals.items()))
    report["count_basis"] = "masked_items_including_metadata_not_unique_people; categories_may_overlap"
    return report


def _format_limitation_summary(code, count):
    data_type = ("PDF representation" if "pdf" in code else "Word document representation" if "docx" in code
                 else "Workbook representation" if "workbook" in code or "excel" in code or "xlsx" in code
                 else "File or container representation")
    return {"category": code, "data_type": data_type, "count": count, "count_basis": "affected_files",
            "why": "Format or inspection limitation: " + code.replace("_", " ") + ". This is not a confirmed human PII finding."}


def render_report_markdown(report):
    lines = ["# Human PII scrubbing report", "", "Original files preserved. Processing was local; no external upload performed.",
             "", f"Status: **{report['overall_status']}**", "",
             "Scope: explicit human PII only. Unique machine/resource identifiers remain unchanged. Explicit human PII within a protected identifier is retained and blocks release pending resolution; other human PII is masked.", "",
             "Each character in an identified human PII span becomes one uppercase X. Other characters, cells, items and resource identifiers remain unchanged. Safe source filenames receive _SCRUBBED before the extension; format/safety losses are reported separately.", ""]
    reviewed = bool(report.get("review_note"))
    lines += ["A local review attempt is recorded; see each file's coverage and verification results. No Matilda upload was performed." if reviewed else
              "Codex context review is required. The script does not certify absence of human PII or Matilda import acceptance.", "",
              "| File | Format | Content review | Submission | Compatibility | Artifact |",
              "|---|---|---|---|---|---|"]
    for r in report.get("files", []):
        artifact = "[Open copy](" + quote(r["artifact"], safe="/") + ")" if r.get("artifact") else "none"
        lines.append(f"| {r['file_id']} | {r['input_format']} | {r['privacy_status']} | {r['submission_status']} | {r['matilda_compatibility']} | {artifact} |")
    summary = report.get("change_summary", {})
    for key, title in (("human_pii", "Human PII masked"), ("non_pii_changes", "Non-PII format/safety changes and limitations"), ("unclassified_changes", "Changes requiring scope review")):
        lines += ["", "## " + title, ""]
        rows = summary.get(key, [])
        if rows:
            lines += ["| Data type | Count | Why |", "|---|---:|---|"]
            lines += [f"| {r['data_type']} | {r['count']}{' file(s)' if r.get('count_basis') == 'affected_files' else ''} | {r['why']} |" for r in rows]
        else:
            lines.append("No explicit human PII matches were reported." if key == "human_pii" else "None reported.")
    lines += ["", "Counts describe affected items, not unique people; categories can overlap. Format limitations explicitly count affected files. Artifact links retain safe supplied basenames; original PII values, original full paths and identity mappings are excluded.", "", "## File details", ""]
    for r in report.get("files", []):
        fallback_action = ('Local checks and review passed. Any Matilda upload is a separate manual action; import acceptance remains unverified.'
                           if r.get('submission_status') == 'ready_for_manual_submission'
                           else 'Complete the required context review and verification.')
        lines += [f"### {r['file_id']}", "", "Warnings: " + (", ".join(_safe_codes(r.get("warnings", []))) or "none"), "",
                  "Next action: " + (r.get('next_action') or fallback_action), "",
                  "Format limitations: " + (", ".join(r.get("format_limitations", [])) or "none reported"), "",
                  "Scope-review issues: " + (", ".join(r.get("policy_alignment_issues", [])) or "none"), "",
                  "Initial unresolved review occurrences: " + str(r.get("context_review", {}).get("unresolved_review_occurrences", 0)) + ". These are not confirmed PII masks; later review decisions may resolve them.", "",
                  "Final context review complete: " + str(r.get("local_context_review_completed", False)) + "; unresolved items reported by review: " + str(r.get("unresolved_review_items", "not yet reviewed")) + ".", "",
                  "Complete location ledgers: " + str(r.get("removal_location_index", "unavailable")) + " / " + str(r.get("review_location_index", "unavailable")) + ".", "",
                  "Independent candidate ledger: " + str(r.get("verification", {}).get("independent_candidate_location_index", "not yet generated")) + ".", "",
                  "Preparedness: " + str(r.get("submission_status", "blocked")) + "; Matilda import acceptance: unverified. A _SCRUBBED filename does not establish readiness.", "",
                  "Required per-file chat summary data: `" + json.dumps(r.get("chat_summary", {}), sort_keys=True) + "`", "",
                  "Metrics: `" + json.dumps(r.get("metrics", {}), sort_keys=True) + "`", ""]
    if reviewed:
        lines += ["## Local output verification", "", "| File | Policy scan | Original comparison | Independent candidate scan | Reviewed mask spans | Errors |", "|---|---|---|---|---|---|"]
        for r in report.get("files", []):
            check = r.get("verification", {})
            errors = _safe_codes(check.get("errors", []))
            states = ['passed' if check.get(key) is True else 'failed/incomplete' for key in ('policy_scan_passed', 'source_comparison_passed', 'independent_candidate_scan_passed', 'semantic_mask_review_passed')]
            lines.append(f"| {r['file_id']} | {' | '.join(states)} | {', '.join(errors) or 'none'} |")
    return "\n".join(lines) + "\n"


def dependency_status(formats=None):
    """Check the actual imports for selected formats without loading customer data."""
    selected = sorted(set(formats or []))
    if any(not isinstance(fmt, str) or "." + fmt not in SUPPORTED for fmt in selected):
        raise ScrubError("unsupported_dependency_format")
    required = {"lxml"}
    if "parquet" in selected:
        required.update({"numpy", "pyarrow"})
    if "xls" in selected:
        required.update({"xlrd", "olefile"})
    modules = {}
    for key, purpose in DEPENDENCIES.items():
        try:
            available = importlib.util.find_spec(key) is not None
        except (ImportError, ValueError, AttributeError):
            available = False
        modules[key] = {"available": available, "required": key in required, "purpose": purpose}
    missing = sorted(key for key in required if not modules[key]["available"])
    return {"selected_formats": selected, "modules": modules,
            "missing_required": missing, "ready": not missing,
            "note": "Parser presence is not an execution test or submission approval."}


def safe_error(exc):
    """Never include exception text: parsers often put raw values and paths in it."""
    if isinstance(exc, ScrubError):
        return getattr(exc, "code", "processing_failed")
    if isinstance(exc, ModuleNotFoundError):
        return "dependency_unavailable"
    if isinstance(exc, MemoryError):
        return "memory_limit_exceeded"
    return "processing_failed"


class Runner:
    def __init__(self, out, max_bytes, max_total_bytes, max_entries, max_depth, review_decisions=None, prior_report=None, prior_source_bindings=None):
        self.out = out
        self.max_bytes = max_bytes
        self.max_total_bytes = max_total_bytes
        self.max_entries = max_entries
        self.max_depth = max_depth
        self.total_bytes = 0
        self.records = SourceBoundRecords()
        self.prior_source_bindings = prior_source_bindings
        self.serial = 0
        self.source_paths = {}
        self.review_decisions = review_decisions or {}
        self.prior_records = {r['file_id']: r for r in (prior_report or {}).get('files', [])}
        (self.out / 'review-candidates').mkdir(exist_ok=True, mode=0o700)
        (self.out / 'removal-locations').mkdir(exist_ok=True, mode=0o700)

    def artifact_path(self, src, record, extension, ctx):
        if extension.casefold() == src.suffix.casefold():
            extension = src.suffix
        masked_stem = ctx.scrub(src.stem, field='filename', location='filename')
        name = masked_stem + '_SCRUBBED' + extension
        if record['parent_file_id']:
            name = record['file_id'] + '_SCRUBBED' + extension
        if any(ord(c) < 32 for c in name) or len(name.encode('utf-8')) > 240:
            name = record['file_id'] + '_SCRUBBED' + extension
            ctx.warn('filename_representation_changed')
        path = self.out / 'artifacts' / name
        if path.exists() or (self.out / 'incomplete' / name).exists():
            path = self.out / 'artifacts' / record['file_id'] / name
            path.parent.mkdir(mode=0o700)
        return path

    def copy_bounded(self, stream, dst):
        size = 0
        with dst.open("wb") as writer:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                self.total_bytes += len(chunk)
                if size > self.max_bytes or self.total_bytes > self.max_total_bytes:
                    raise ScrubError("expanded_size_limit")
                writer.write(chunk)
        return size

    def new_record(self, src, parent):
        self.serial += 1
        suffix = src.suffix.lower()
        # Only extensions from our fixed allowlist can reach report/file names.
        fmt = suffix[1:] if suffix in SUPPORTED else "unsupported"
        return {"file_id": f"file{self.serial:04d}", "parent_file_id": parent,
                "input_format": fmt, "output_format": None,
                "processing_status": "blocked",
                "privacy_status": "blocked", "submission_status": "blocked",
                "matilda_compatibility": "unverified", "artifact": None,
                "counts_by_category": {}, "locations": {}, "warnings": [], "metrics": {}}

    def run_file(self, src, parent=None, depth=0):
        if len(self.records) >= self.max_entries:
            raise ScrubError("file_count_limit")
        record = self.new_record(src, parent)
        self.records.append(record)
        self.source_paths[record['file_id']] = src
        ctx = ScrubContext(review_decisions=self.review_decisions.get(record['file_id'], {}))
        artifact = None
        review_path = self.out / 'review-candidates' / (record['file_id'] + '.jsonl')
        removal_path = self.out / 'removal-locations' / (record['file_id'] + '.jsonl')
        review_stream = review_path.open('w', encoding='utf-8')
        removal_stream = removal_path.open('w', encoding='utf-8')
        ctx.review_location_sink = lambda event: review_stream.write(json.dumps(event, ensure_ascii=True) + '\n')
        ctx.removal_location_sink = lambda event: removal_stream.write(json.dumps(event, ensure_ascii=True) + '\n')
        try:
            if src.is_symlink():
                raise ScrubError("symlink_not_processed")
            if not src.is_file():
                raise ScrubError("not_a_regular_file")
            if src.stat().st_size > self.max_bytes:
                raise ScrubError("file_size_limit")
            if depth > self.max_depth:
                raise ScrubError("archive_depth_limit")
            suffix = src.suffix.lower()
            intake_error = admission_error(src)
            if intake_error:
                raise ScrubError(intake_error)
            binding = fingerprint_source(src, self.max_bytes)
            self.records.source_bindings[record['file_id']] = binding
            if self.prior_records:
                if self.prior_source_bindings is None:
                    raise ScrubError('review_plan_source_provenance_missing')
                require_source_match(self.prior_source_bindings, record['file_id'], src, self.max_bytes)
            out_suffix = suffix
            artifact = self.artifact_path(src, record, out_suffix, ctx)
            if suffix == ".csv":
                metrics = structured.scrub_csv(src, artifact, ctx)
            elif suffix == ".parquet":
                metrics = structured.scrub_parquet(src, artifact, ctx)
            elif suffix == ".xlsx":
                metrics = structured.scrub_xlsx(src, artifact, ctx)
            elif suffix == ".xls":
                adapter = getattr(structured, "scrub_xls", None)
                if adapter is None:
                    raise ScrubError("legacy_excel_adapter_unavailable")
                metrics = adapter(src, artifact, ctx)
            else:
                raise ScrubError('unsupported_format')
            if fingerprint_source(src, self.max_bytes) != binding:
                raise ScrubError('source_changed_during_scrub')
            record["metrics"] = metrics or {}
            record["counts_by_category"] = dict(ctx.counts)
            record["locations"] = {str(k): list(v) for k, v in getattr(ctx, "locations", {}).items()}
            record["warnings"] = sorted(set(record["warnings"]) | set(ctx.warnings))
            incomplete = bool(record["metrics"].get("incomplete", False))
            if record["metrics"].get("blocked", False):
                record["processing_status"] = "blocked"
            else:
                record["processing_status"] = "partial" if incomplete else "completed"
            record['privacy_status'] = 'requires_context_review' if record['processing_status'] == 'completed' else record['processing_status']
            if artifact.exists():
                # Incomplete outputs are quarantined and never mixed with completed copies.
                if record["processing_status"] != "completed":
                    quarantine = self.out / "incomplete" / artifact.relative_to(self.out / 'artifacts')
                    quarantine.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    artifact.replace(quarantine)
                    artifact = quarantine
                os.chmod(artifact, 0o600)
                record["artifact"] = artifact.relative_to(self.out).as_posix()
                record["output_format"] = artifact.suffix.lstrip(".").lower()
            if record["processing_status"] == "completed":
                record["submission_status"] = "requires_context_review"
            record["metrics"]["inspected_values"] = ctx.inspected
            record["metrics"]["retained_values"] = ctx.retained
            record["metrics"]["masking_actions"] = ctx.changed
            record["metrics"]["masked_items"] = ctx.changed
            record["metrics"]["masked_spans"] = ctx.masked_spans
            record["metrics"]["masked_characters"] = ctx.masked_characters
            record["metrics"]["containers_cleared"] = getattr(ctx, "containers_cleared", 0)
            record["metrics"]["leaf_values_cleared"] = getattr(ctx, "leaf_values_cleared", 0)
            if COMPATIBILITY_LOSS_WARNINGS.intersection(record["warnings"]):
                record["matilda_compatibility"] = "not_ready"
            prior = self.prior_records.get(record['file_id'])
            if prior:
                same = prior['input_format'] == record['input_format']
                for key in ('input_rows', 'rows', 'columns', 'sheets'):
                    if key in prior.get('metrics', {}):
                        same &= prior['metrics'][key] == record['metrics'].get(key)
                if not same:
                    raise ScrubError('review_plan_source_structure_mismatch')
        except Exception as exc:
            record["warnings"] = sorted(set(record["warnings"]) | {safe_error(exc)})
            # A partial writer must not leave a file looking like a usable deliverable.
            if artifact is not None and artifact.is_file() and artifact.resolve().is_relative_to(self.out.resolve()):
                artifact.unlink()
            record['artifact'] = None
            record["counts_by_category"] = dict(ctx.counts)
            record["privacy_status"] = "blocked"
            record['processing_status'] = 'blocked'
            record["submission_status"] = "blocked"
        finally:
            review_stream.close()
            removal_stream.close()
            record['context_review'] = ctx.safe_report()
            record['review_location_index'] = review_path.relative_to(self.out).as_posix()
            record['removal_location_index'] = removal_path.relative_to(self.out).as_posix()
            applied = getattr(ctx, 'applied_review_decisions', {})
            applied_locations = set(applied) if isinstance(applied, dict) else {r['location'] for r in applied}
            unused = set(self.review_decisions.get(record['file_id'], {})) - applied_locations
            if unused:
                record['warnings'] = sorted(set(record['warnings']) | {'unused_context_review_decisions'})
                record['context_review']['unused_decision_count'] = len(unused)
        return record

def write_report(out, records, run_id=None, source_run_id=None):
    run_id = run_id or getattr(records, 'run_id', None) or str(uuid4())
    if isinstance(records, SourceBoundRecords):
        if records.run_id is not None and records.run_id != run_id:
            raise ScrubError('source_provenance_run_mismatch')
        records.run_id = run_id
        write_provenance(out, run_id, records.source_bindings)
    report = {"policy_version": POLICY_VERSION, 'run_id': run_id, 'review_source_run_id': source_run_id, "originals_modified": False,
              "external_uploads_performed": False,
              "privacy_scope": list(PRIVACY_SCOPE),
              "preserved_scope": ["infrastructure_identifiers_addresses_paths_domains", "cloud_accounts_projects_and_customer_companies", "billing_cost_usage_and_catalog_values", "unknown_fields_and_free_text_without_explicit_human_pii"],
              "replacement": "one_uppercase_X_per_original_PII_codepoint; protected_resource_identifiers_unchanged",
              "overall_status": "requires_context_review" if all(r.get('processing_status') == "completed" for r in records) else "partial_or_blocked",
              "matilda_acceptance_tested": False,
              "files": records,
              "limits": ["Detection targets explicit human PII only and cannot prove its complete absence.",
                         "Resource identifiers remain exact even when human PII is suspected; explicit human PII inside one blocks release rather than changing it.",
                         "Codex must review all retained content and contextual combinations before handoff.",
                         "Matilda importer compatibility remains unverified; no uploads are performed."]}
    refresh_report_summaries(report)
    if any(r.get("policy_alignment_issues") for r in records):
        report["overall_status"] = "partial_or_blocked"
    (out / "scrub-report.json").write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    (out / "scrub-report.md").write_text(render_report_markdown(report), encoding="utf-8")
    for p in (out / "scrub-report.json", out / "scrub-report.md"):
        os.chmod(p, 0o600)
    return report


def main():
    # Warnings/diagnostic loggers in third-party parsers can echo source values.
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*")
    parser.add_argument("--output-dir")
    parser.add_argument("--check-dependencies", action="store_true")
    parser.add_argument("--formats", nargs="+", help="Formats selected for dependency checks, for example csv parquet xlsx")
    parser.add_argument('--review-plan', help='Neutral coordinate decisions from this input set and a prior run; no source values')
    parser.add_argument("--max-file-mib", type=int, default=2048)
    parser.add_argument("--max-expanded-mib", type=int, default=8192)
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-depth", type=int, default=4)
    args = parser.parse_args()
    if args.check_dependencies:
        try:
            status = dependency_status(args.formats)
        except Exception as exc:
            code = safe_error(exc)
            print(json.dumps({"error": code, "next_action": guidance_for(code)}))
            return 2
        print(json.dumps(status, indent=2))
        return 0 if status["ready"] else 2
    if args.formats:
        parser.error("--formats requires --check-dependencies")
    if not args.inputs or not args.output_dir:
        parser.error("inputs and --output-dir are required")
    decisions, prior_report, prior_source_bindings = {}, None, None
    if args.review_plan:
        try:
            decisions, prior_report = load_plan(args.review_plan)
            prior_source_bindings = load_provenance(Path(args.review_plan).parent, prior_report['run_id'])
        except Exception as exc:
            print(json.dumps({'error': safe_error(exc)}))
            return 2
    os.umask(0o077)
    out = Path(args.output_dir).absolute()
    if out.exists():
        print(json.dumps({"error": "output_directory_already_exists"}))
        return 2
    sources = []
    for name in args.inputs:
        p = Path(name).absolute()
        if p.is_dir() and not p.is_symlink():
            for root, dirs, files in os.walk(p, followlinks=False):
                dirs.sort()
                # A symlink directory is a blocked input, never followed.
                for d in list(dirs):
                    if (Path(root) / d).is_symlink():
                        sources.append(Path(root) / d)
                        dirs.remove(d)
                sources.extend(Path(root) / f for f in sorted(files))
        else:
            sources.append(p)
    if len(sources) > args.max_files:
        print(json.dumps({"error": "file_count_limit"}))
        return 2
    out.mkdir(parents=True, mode=0o700)
    (out / "artifacts").mkdir(mode=0o700)
    (out / "incomplete").mkdir(mode=0o700)
    runner = Runner(out, args.max_file_mib * 1024 ** 2, args.max_expanded_mib * 1024 ** 2, args.max_files, args.max_depth, decisions, prior_report, prior_source_bindings)
    run_id = str(uuid4())
    source_run_id = prior_report.get('run_id') if prior_report else None
    try:
        for source in sources:
            runner.run_file(source)
        if prior_report and set(runner.prior_records) != {r['file_id'] for r in runner.records}:
            raise ScrubError('review_plan_inventory_mismatch')
        report = write_report(out, runner.records, run_id, source_run_id)
    except Exception as exc:
        # Still write a report for unaffected files; never display source exception messages.
        for record in runner.records:
            record['warnings'] = sorted(set(record.get('warnings', [])) | {safe_error(exc)})
            record['processing_status'] = 'blocked'
            record['submission_status'] = 'blocked'
        write_report(out, runner.records, run_id, source_run_id)
        print(json.dumps({"error": safe_error(exc), "report": "scrub-report.json"}))
        return 2
    print(json.dumps({"status": report["overall_status"], "files": len(runner.records), "report": "scrub-report.json",
                      "file_actions": [{"file_id": row['file_id'], "next_action": row['next_action'],
                                        "artifact_produced": row.get('artifact') is not None}
                                       for row in report['files'] if row.get('next_action')]}))
    return 0 if report["overall_status"] == "requires_context_review" else 2


if __name__ == "__main__":
    sys.exit(main())
