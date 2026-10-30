# Context decisions and release evidence

Read this for each run. The user authorized local Codex inspection of supplied originals. Read only what is necessary to determine actual context; bounded distinct-value views and cross-field/metadata corroboration can avoid repeatedly displaying the same data. Keep candidate values in RAM and out of persistent reports, reusable code, test fixtures and final summaries. Never send them to search or external services.

## Three outcomes

1. **Confirmed human:** mask only the exact human PII spans in the affected item, unless it is a protected resource identifier or structural/type conflict (preserve and block) and count its actual human category. Evidence can be an explicitly personal field, a named-person address, a human contact record, personal credentials, or an author identity corroborated across metadata/path attributes.
2. **Established nonpersonal:** preserve exactly. Evidence can be an organization/team/project/application mailbox, documented machine identity, provider catalog description, infrastructure identifier or organization owner label. An identity-like wrapper does not itself establish human or nonhuman ownership.
3. **Unresolved candidate:** preserve, record safe coordinates/reason and review locally. Short email aliases, compact owner handles, numeric actor IDs and name-shaped text need context. Do not label them people merely to produce a mask. Do not report them as cleared or confidently nonpersonal while material uncertainty remains. An unresolved inspection/privacy concern blocks the affected artifact's ready status; it need not block unrelated files.

For emails, inspect the actual address after extracting it from wrappers and decoding common URL/HTML/JSON encodings. Do not test the entire ARN or role string against a shared-mailbox allowlist. Conversely, neither corporate email syntax nor an unknown local part establishes a person. Review every address in a multi-contact item: mask only each confirmed personal address; all-shared contact lists stay intact. A substring such as `admin` is not a blanket exception.

For names, ownership context can support a person classification, but a generic `Name`, `Owner`, `Creator` or `user_name` tag may identify a resource, service or organization. Distinguish a technical cloud-function description from human attribution. Do not use customer-specific name dictionaries in the skill. Inspect operational attributions such as a given name followed by a date, a note about who uses a VM, and names between adjacent contact/department fields. Bare names and dated product labels require context; do not automatically mask them. When a masked note contains both a name and phone number, count both categories while counting the whole item once.

For metadata, inspect every supported XML element text and attribute, including `refreshedBy`, saved-file/profile paths, custom properties, comments, relationships and hidden sheets/caches. Corroborate a personal path against original author/last-modifier metadata in RAM when available. Generic system profiles (`Public`, `Default`, machine accounts) and application paths are not automatically personal. Unsupported opaque content must be explicitly reported and cannot silently pass coverage review.

## Review plan for corrections

The initial script run creates a `run_id`, per-file `context_review`, `review-candidates/fileNNNN.jsonl` and `removal-locations/fileNNNN.jsonl`. These ledgers contain safe exact coordinates and codes, never original values. Read all candidate events and review **all actual changes** as well as retained content. Count reconciliation alone does not establish that the masked values were personal.

If contextual corrections are necessary, save `review-plan.json` **beside that run's `scrub-report.json`**. Use only the current input inventory. Do not reuse a plan on unrelated or changed originals. Example structure (coordinates below are illustrative, not decisions about any supplied customer file):

```json
{
  "version": 2,
  "source_run_id": "COPY_THE_INITIAL_RUN_ID",
  "files": {
    "file0001": {
      "decisions": {
        "r2.c3": {"action": "retain", "reason_code": "shared_organizational_mailbox"},
        "r7.c3": {"action": "mask", "reason_code": "explicit_person_name", "spans": [{"start": 9, "end": 20, "category": "human_names"}]}
      }
    }
  }
}
```

Use the engine's **actual emitted coordinates**, not invented examples or batch markers. CSV rows include the header. Parquet rows have no header; `.kN` identifies the 1-based map entry within that parent record. XML locators refer to the actual package part/element/attribute. Never include matched values, hashes, source names or lookup mappings in decisions.

Rerun the same originals, same order and same inventory into a new output directory:

```bash
python3 SKILL_DIR/scripts/scrub.py INPUT_1 INPUT_2 \
  --output-dir NEW_OUTPUT_DIR --review-plan PRIOR_OUTPUT_DIR/review-plan.json
```

The plan is checked against its prior run/inventory and source structure; those checks do not replace fresh source review. Each exact decision applies to one coordinate. Do not create broad field/domain/prefix exemptions, silently force a whole unknown column, or mutate verification code for one customer. An unused decision or changed source structure requires investigation before release.

Allowed reason codes are in `scripts/review_support.py`: named-person email, explicit person name/identifier, human author, corroborated personal path, personal contact/sensitive record, shared organizational mailbox, machine identity, organization/project label, technical description, billing/infrastructure value. Use `action: mask` with nonempty exact `spans` containing `start`, `end`, `category`; offsets are 0-based half-open Unicode codepoints within the original scalar. Each position becomes X; do not include source text. Use no spans/categories for `retain`. Version 1 / `clear` plans are rejected. A mask cannot override protected resource, schema or type rules.

## Independent review and evidence

Review both directions:

- **Retained → missed PII:** inspect all content with an independently broader candidate search, not just the masking detector. Check encoded/wrapped emails, person context, nested map entries, free text and all supported hidden/metadata parts. Distinct-value inventories may stay in RAM, with full occurrence coverage.
- **Changed → false positives:** inspect every distinct masked value in source context and verify all actual locations/counts. Organizational mailboxes, technical descriptions and ambiguous labels must not be called human merely because the first pass masked them. Correct mistakes using the originals.
- **Integrity:** compare the entire original/output representation, including exact X positions, retained values, rows/order, schema/types, map keys/ordinals, formulas and caches. For Parquet, review the actual footer key/value metadata separately from embedded Arrow schema metadata; matching one does not establish preservation of the other. Flag unexplained mutations and inspection losses. Source paths are passed transiently to the verifier, never saved in the portable report.

Write `review-evidence.json` for the **current output run ID** only after doing the work. Include every file ID, even zero-removal and blocked files. Coverage flags are factual attestations, not a shortcut around inspection. For an incomplete review, use false coverage and a nonzero unresolved count.

```json
{
  "version": 2,
  "run_id": "COPY_THE_CURRENT_RUN_ID",
  "files": {
    "file0001": {
      "complete_source_review": true,
      "complete_retained_review": true,
      "all_changed_values_reviewed": true,
      "metadata_and_hidden_content_reviewed": true,
      "independent_candidate_review": true,
      "unresolved_items": 0,
      "decisions": {}
    }
  }
}
```

The empty `decisions` example is valid only when there are no changed scalars or unresolved candidates requiring decisions. Every changed scalar, including an automatically masked value or filename, needs an explicit, independently reviewed `mask` decision with its exact spans. Use the same decision schema as the correction-plan example. The masking ledger alone cannot establish that an entire value is personal. Review its original context and every character being removed; mixed labels and technical suffixes must remain intact. Decisions already applied through the current run's correction plan count toward this requirement. Additional independently found candidates need exact, reasoned resolutions too. A mask decision requires the output to contain precisely those X positions and its report reconciled; rerun with a correction plan if needed. Conflicting, stale, incomplete or unused decisions cannot support readiness.

The verifier reconstructs expected edits from recorded offsets rather than asking the masking detector to generate its own expected answer. This proves mechanical preservation. `semantic_mask_review_passed` separately requires explicit context decisions for changed values. Neither check proves the other. Synthetic regression tests use independently authored expected text and spans.

Source bytes must still match the run's private local provenance record. A source change, missing provenance, or an edited output requires a new run and fresh review. Do not copy evidence from a prior run or change provenance to make stale evidence pass. Private provenance is used only for local integrity checking; never share it or include it in portable reports.

## Complete candidate inventory and repeated values

Run the verifier once to generate the independent candidate ledger, even if the run is still blocked:

```bash
python3 SKILL_DIR/scripts/verify_outputs.py OUTPUT_DIR \
  --source "file0001=/absolute/path/to/original.csv"
python3 SKILL_DIR/scripts/group_review.py OUTPUT_DIR/scrub-report.json \
  --source "file0001=/absolute/path/to/original.csv" \
  --output OUTPUT_DIR/review-groups.json
```

The first command may exit 2 because review is incomplete; inspect its results. Read the complete `review-candidates/`, `removal-locations/` and `independent-candidates/` JSONL ledgers, not only report samples. Independent ledger rows include exact coordinates and resolved status. Grouping supports CSV; supply every CSV file ID in a mixed batch. The helper groups equal values from the same column using source values only in RAM. Its output contains coordinates and counts, no raw values or fingerprints. Review every occurrence's surrounding context before expanding a decision to each coordinate. A group is a review aid, never automatic clearance, a column exemption or evidence of personhood. Other formats require their own complete location review.

If identity remains unknown, leave the value unchanged, mark coverage truthfully, retain unresolved counts, finalize as blocked and deliver the processed copy with its summary/status in chat. Do not withhold an otherwise producible copy while waiting for a ready outcome.

## Finalization

Finalize:

```bash
python3 SKILL_DIR/scripts/finalize_report.py OUTPUT_DIR/scrub-report.json \
  --review-evidence OUTPUT_DIR/review-evidence.json \
  --source "file0001=/absolute/path/to/original.csv"
```

Supply the needed original source for each file ID. Archive children require supported original/archive source comparison; if that comparison is unavailable, report the limit instead of declaring success. The finalizer requires actual source comparison and independent candidate checks as well as evidence. Boolean review flags alone are insufficient. A ready result describes this completed local review, not guaranteed absence of all possible PII or guaranteed Matilda acceptance.

If an automatic approval review blocks a necessary inspection, do not bypass it. Complete allowed checks, disclose the exact gap and keep the affected classification unresolved. Do not silently convert unavailable validation into a successful review.

Protected identifier/schema/type/formula/unsupported-content conflicts cannot be waived by a retain decision. Inspect the real source schema to identify custom resource keys before transformation. Exact protected key and reference equality must be proven across every record; preserving only distinct counts is insufficient.

## Mixed masked and retained content

If a correctly masked item still triggers an independent candidate on a confirmed shared mailbox or technical phrase, add `residual_reason_code` to its exact `mask` decision, using a fixed nonpersonal reason such as `shared_organizational_mailbox` or `technical_description`. Keep the exact source mask spans in that same decision. This attests only to the remaining unmasked characters after source-proven masking, and cannot waive a confirmed remaining human PII finding or protected/schema/type conflict. Never use a whole-item `retain` decision for an item whose PII spans must change. Decisions target scalar coordinates only, never entire objects/arrays.
