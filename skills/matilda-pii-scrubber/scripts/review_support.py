"""Validate value-free, run-scoped Codex review evidence; never store source values."""
from __future__ import annotations
import json
from pathlib import Path
import re
from scrub_core import ScrubError, _GROUPS, _SAFE_LOCATION

REVIEW_VERSION = 2
COVERAGE_FIELDS = ('complete_source_review', 'complete_retained_review',
                   'all_changed_values_reviewed', 'metadata_and_hidden_content_reviewed',
                   'independent_candidate_review')
REASONS = {'named_person_email', 'explicit_person_name', 'explicit_person_identifier',
           'human_author_metadata', 'corroborated_personal_path', 'personal_contact_record',
           'personal_sensitive_record', 'shared_organizational_mailbox', 'machine_identity',
           'organization_or_project_label', 'technical_description', 'billing_or_infrastructure_value'}
_ID = re.compile(r'file\d{4,}')
_RETAIN_REASONS = {'shared_organizational_mailbox', 'machine_identity',
                   'organization_or_project_label', 'technical_description', 'billing_or_infrastructure_value'}

def read_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024**2:
        raise ScrubError('invalid_review_document')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ScrubError('duplicate_review_keys')
            result[key] = value
        return result
    try:
        value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)
    except ScrubError:
        raise
    except Exception:
        raise ScrubError('invalid_review_document') from None
    if not isinstance(value, dict):
        raise ScrubError('invalid_review_document')
    return value

def validate_decisions(decisions):
    if not isinstance(decisions,dict):raise ScrubError('invalid_review_decisions')
    result={}
    for location,choice in decisions.items():
        if not isinstance(location,str) or len(location)>2048 or not _SAFE_LOCATION.fullmatch(location) or not isinstance(choice,dict):raise ScrubError('invalid_review_decision_location')
        if set(choice)-{'action','categories','reason_code','spans','residual_reason_code'}:raise ScrubError('review_decision_extra_content')
        action,reason=choice.get('action'),choice.get('reason_code')
        if action not in ('retain','mask') or reason not in REASONS:raise ScrubError('invalid_review_decision_reason')
        if (action=='retain') != (reason in _RETAIN_REASONS):raise ScrubError('review_decision_reason_action_mismatch')
        residual=choice.get('residual_reason_code')
        if residual is not None and (action!='mask' or residual not in _RETAIN_REASONS):raise ScrubError('invalid_residual_review_reason')
        spans=choice.get('spans',[])
        if not isinstance(spans,list) or action=='mask' and not spans or action=='retain' and spans:raise ScrubError('invalid_mask_spans')
        for span in spans:
            if not isinstance(span,dict) or set(span)!={'start','end','category'} or type(span['start']) is not int or type(span['end']) is not int or not 0<=span['start']<span['end'] or span['category'] not in _GROUPS:raise ScrubError('invalid_mask_span')
        categories=sorted({s['category'] for s in spans})
        if 'categories' in choice and choice['categories']!=categories:raise ScrubError('invalid_review_decision_category')
        result[location]={'action':action,'categories':categories,'reason_code':reason}
        if action=='mask':result[location]['spans']=spans
        if residual is not None:result[location]['residual_reason_code']=residual
    return result

def load_plan(path):
    plan = read_json(path)
    if set(plan) - {'version', 'source_run_id', 'files'}:
        raise ScrubError('review_plan_extra_content')
    prior = read_json(Path(path).parent / 'scrub-report.json')
    if (plan.get('version') != REVIEW_VERSION or not prior.get('run_id')
            or plan.get('source_run_id') != prior.get('run_id') or not isinstance(plan.get('files'), dict)):
        raise ScrubError('review_plan_run_mismatch')
    inventory = {row['file_id']: row for row in prior.get('files', [])}
    result = {}
    for file_id, review in plan['files'].items():
        if not _ID.fullmatch(file_id) or file_id not in inventory or not isinstance(review, dict):
            raise ScrubError('invalid_review_file_id')
        if set(review) - {'decisions'}:
            raise ScrubError('review_plan_extra_content')
        result[file_id] = validate_decisions(review.get('decisions', {}))
    return result, prior

def validate_evidence(evidence, report):
    if (evidence.get('version') != REVIEW_VERSION or evidence.get('run_id') != report.get('run_id')
            or not report.get('run_id') or not isinstance(evidence.get('files'), dict)):
        raise ScrubError('review_evidence_run_mismatch')
    if set(evidence) - {'version', 'run_id', 'files'}:
        raise ScrubError('review_evidence_extra_content')
    results = {}
    inventory = {row['file_id']: row for row in report.get('files', [])}
    if set(evidence['files']) != set(inventory):
        raise ScrubError('review_evidence_inventory_mismatch')
    for file_id, review in evidence['files'].items():
        if not isinstance(review, dict) or set(review) - set(COVERAGE_FIELDS) - {'unresolved_items', 'decisions'}:
            raise ScrubError('review_evidence_extra_content')
        if any(type(review.get(field)) is not bool for field in COVERAGE_FIELDS):
            raise ScrubError('invalid_review_coverage_flag')
        complete = all(review[field] for field in COVERAGE_FIELDS)
        unresolved = review.get('unresolved_items')
        if type(unresolved) is not int or unresolved < 0:
            raise ScrubError('invalid_unresolved_review_count')
        decisions = validate_decisions(review.get('decisions', {}))
        results[file_id] = {'coverage_complete': complete, 'unresolved_items': unresolved, 'decisions': decisions}
    return results
