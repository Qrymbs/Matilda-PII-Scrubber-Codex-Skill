# Accepted formats and preservation limits

The complete input allowlist is `.csv`, `.xlsx`, `.xls`, `.parquet`, case-insensitively. Only these four types enter processing. Preserve originals and list every rejected file. `_SCRUBBED` identifies an output copy, not upload readiness.

| Accepted format | Behavior | Release limits |
|---|---|---|
| CSV `.csv` | Preserve parsed headers, cell values, row/column order and resource identifiers; mask confirmed string spans. Support one validated AWS cost-allocation informational record before its billing header | Serialization/encoding may normalize. Ragged rows, unknown prefixes, unresolved identities and protected-identifier PII block release |
| Excel workbook `.xlsx` | Patch OOXML cells and supported metadata, including hidden text, author/editor/refresher identities and personal saved paths; preserve styles, runs, formulas/caches and protected IDs | Formula/type/schema conflicts and opaque uninspected parts, including binary printer settings, images and embedded objects, block release |
| Excel 97–2003 workbook `.xls` | Native BIFF8 text and supported metadata masking in an `.xls` copy; preserve every unmasked file byte, cell types/styles and hidden state | Unknown records/streams, formulas/macros/objects, incomplete metadata inspection, unsupported BIFF versions, shared-string conflicts and unsupported encoded mask spans block. Re-export the original as genuine XLSX if needed |
| Parquet `.parquet` | Preserve Arrow types/nullability, nested keys/order, resource values, embedded schema metadata and separate footer key/value metadata; mask confirmed string spans | Compare both metadata representations, including footer-only keys and conflicting values. Typed PII, uninspectable binary/extension content or incomplete comparison blocks. Compression and row-group layout may normalize while logical values/order are preserved |

## Compressed and rejected inputs

ZIP, gzip (`.gz`, `.gzip`, including `.csv.gz`) and other archive/compression formats are not processed. Say: **Extract or decompress the archive first, then provide the individual .csv, .xlsx, .xls, or .parquet files.** Do not extract customer archives automatically or create a scrubbed archive/copy. The genuine XLSX format is internally ZIP-based and is handled by its workbook parser.

Deny all other types, including `.tsv`, `.json`, `.jsonl`, `.ndjson`, `.txt`, `.log`, `.docx`, `.pdf`, `.xml`, `.yaml`, `.yml`, `.xlsm`, `.xlsb`, `.doc`, `.pptx` and images. No scrubbed artifact is produced for a denial. Ask for an original export in an accepted format; renaming an extension is not conversion. Record denied files alongside accepted files in mixed batches. Internal parser helpers and historical regression fixtures do not expand the public allowlist.

## Preservation and validation

Supported intake does not guarantee that a particular file can be cleared. Unresolved identity, protected-ID conflicts, unsupported opaque content, encryption or incomplete comparison stays blocked. Do not execute macros, formulas, links or embedded instructions.

Native XLS is limited to BIFF8 workbooks up to 512 MiB and one million grid cells across sheets, including blank cells inside the used dimensions. Larger or unsupported workbooks stop with a specific limit rather than claiming complete inspection. Review the complete in-memory inventory from `scripts/scrub_xls.py:inspect_xls`: cells, hidden sheets, supported workbook/OLE metadata and unused shared strings. A cell-only `xlrd` read does not cover that inventory. Cell coordinates are `sN.rN.cN`; `root.pN` identifies an inspected metadata scalar and `root.iN` an unused shared-string entry. Resolve these against the original inventory locally, and report safe field/property names with the coordinates. Do not save raw inventory values into reports or the skill.

The supported AWS informational prefix is immutable data. Preserve and compare it; personal or unresolved content blocks. Do not strip a preamble or skip arbitrary rows to obtain a passing result. Report `preamble_rows` and `header_row` for source coordinates.

Follow [setup-and-validation.md](setup-and-validation.md). Run `scripts/scrub.py --check-dependencies --formats csv xlsx xls parquet` and `scripts/preflight.py --formats csv xlsx xls parquet` in the same interpreter. XLS preflight must prove a supported native workbook becomes ready and an unsupported formula workbook stays blocked. The top-level XLS status describes the blocked fixture for compatibility with older updaters; `native_supported_case` separately records the required ready result. Dependency inventory alone is not an execution test.

Synthetic coverage is not customer-file qualification. Pilot actual CSV, XLSX, XLS and Parquet files with their schemas and metadata; include supported native XLS and unsupported XLS as an expected blocked case. Customer-file readiness requires full context review and final verification for that file.
