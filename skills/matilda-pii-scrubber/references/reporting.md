# Required per-document summary

For rejected archives, state **Blocked — no scrubbed file produced**, instruct the user to extract/decompress first and supply individual CSV/XLSX/XLS/Parquet files. For any other denied format, state the same no-file status and list the four accepted extensions. Use the report's fixed `next_action` guidance. Do not claim to have inspected rejected contents or invent an output link. For legacy XLS conversion, link the blocked XLSX copy if produced, disclose the conversion and direct the user to supply a fresh genuine XLSX export of the original.

For Parquet metadata, `root.kN` identifies embedded Arrow schema metadata and `footer.kN` identifies physical footer key/value metadata. Each ordinal follows its original metadata map; footer ordinals exclude the outer `ARROW:schema` envelope, which is regenerated when present. A same-named key inside schema or field metadata is ordinary content and must still be inspected. Nested field metadata retains its `root.cN...kN` coordinates. Review both stored copies when a value occurs in both maps. Without an embedded schema, the inferred schema metadata aliases the footer: count and review it only at `footer.kN`. Counts represent affected stored items, not unique people.

After every run, deliver the actual scrubbed-file links, detailed per-file summaries, and explicit Matilda upload-preparedness statuses directly in the final Codex chat response as well as saved reports. The user must not need to open a report to discover whether a file is blocked. Links alone are insufficient, and summaries alone do not replace actual file delivery. Include every supplied file, even zero-mask, failed and blocked files. Use safe original filenames for identification; mask human filename components as necessary.

Use this structure for each supplied file (substitute verified values; never leave placeholders):

**Safe filename — Ready for manual Matilda upload / Blocked — do not upload**
- **File:** clickable absolute local link to the finalized copy, including blocked processed copies; or "No scrubbed file produced" with the reason.
- **Summary:** counts by human PII category, why masked, affected items/spans/characters, fields and exact representative coordinates. Explicitly state zero counts when none.
- **Preservation and verification:** source/output comparison, protected identifiers, collisions, exact mask review and complete candidate review outcome.
- **Remaining findings:** uncertainty, unsupported inspection or format losses; include what must happen next when blocked.
- **Matilda acceptance:** unverified; no upload performed.

Link the Markdown report, JSON report and verification JSON once per batch. A successful batch must not hide blocked members. Reports may supply `chat_summary` values, but Codex must translate safe coordinates to source field names where verified and write readable prose without quoting PII. Folder/suffix alone is never clearance.

For each file report:
- The output link, processing status and whether it is ready for manual submission or blocked.
- Counts by human PII type and the evidence/reason for that category, without quoting original PII.
- Total affected items, disjoint mask spans and masked original characters. Category counts overlap and are not counts of unique people. Do not report the whole cell as removed.
- Per-column/field counts and exact representative locations: safe column names, sheet names, cells, contiguous ranges, nested records or metadata properties. Label examples as examples; do not imply a range was continuous if gaps exist.
- Protected resource identifiers preserved, exact-equality check results and new collisions (must be zero). Explicit human PII retained inside a protected identifier is a separate blocked conflict, never a completed mask.
- Unresolved candidates, unsupported inspection and format/compatibility losses, separately from confirmed human masks.

CSV coordinates count original CSV records, not physical newline characters inside quoted cells. Normally row 1 is the header and data starts at row 2. For a supported AWS legacy export with one informational record, row 1 is metadata, row 2 is the header and data starts at row 3. Use the reported `header_row`/`preamble_rows`. Parquet uses 1-based data record numbers without a header. Map entry `.kN` is the ordinal within that parent record. OOXML locators refer to the actual package part/element/attribute; translate to safe workbook coordinates when possible. Never substitute a batch marker for an actual cell/record.

`removal-locations/fileNNNN.jsonl` is the legacy directory name for the complete **masking** ledger. Each event records category, coordinate, count=1, normalized per-category character spans and character count. Offsets are 0-based half-open Unicode codepoint ranges within the original scalar; filename offsets refer to the stem, not extension. Per-category spans merge overlap/touching; total spans/characters use the union across categories. `review-candidates/` records separate unresolved/resolved reasons. Capped report samples never replace the complete ledgers.

Reconcile all events with actual original/output differences. The verifier's `independent-candidates/fileNNNN.jsonl` records every candidate, its exact coordinate and resolution; `independent_candidate_location_index` links it in verification. Keep its counts distinct from initial detector candidates and confirmed masks. Never report an unresolved candidate count as confirmed PII or unique people. No deletions/nulls are permitted for new PII actions. Legacy `removed_items` in context reports aliases `masked_items`; `containers_cleared` and `leaf_values_cleared` must remain zero. Summaries use masking terminology.

Saved reports use neutral file IDs and source-free codes/coordinates; no raw values, original full paths, excerpts, fingerprints or identity dictionaries. Artifact links may use safe requested basenames. Deliver `scrub-report.md`, `scrub-report.json`, `verification.json` and supported scrubbed copies. Finalization moves eligible copies to `ready/` and other produced copies to `blocked/`; before revalidation it revokes earlier readiness and relocates prior ready copies to blocked. Pending initial outputs under `artifacts/` or `incomplete/` are not ready for upload. Never present a prior report as current after an artifact, source or review decision changes: rerun complete verification.
