# Setup, validation and customer pilot

Use this for a new installation/runtime, a dependency change, or team rollout. Keep the complete skill folder tree. Back up an installed version outside the active skills directory before replacement. Never bundle customer files, raw examples, output runs, runtime environments or caches with the skill.

## Runtime

Install through the private [GitHub repository's README and managed installer](https://github.com/Qrymbs/Matilda-PII-Scrubber-Codex-Skill#install). GitHub Version 1.0.0 follows internal development build 5.1.0; the numbering restart is intentional. The installer validates the complete release and creates its dedicated runtime before activation. New installations use `~/.agents/skills/matilda-pii-scrubber/`; a sole legacy installation under `~/.codex/skills/` can be adopted with a backup. Resolve duplicate active installations before continuing. Codex detects local skill changes; restart it if the update does not appear. See the official [local skill installation guidance](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills).

Run `python3.12 ~/.local/share/matilda-pii-scrubber/manage_skill.py status` and use the exact `python` interpreter and `skill_dir` it reports for every processing, verification and finalization command. The update command is `python3.12 ~/.local/share/matilda-pii-scrubber/manage_skill.py update`. Manager validation covers synthetic release checks only; each customer's file still needs its complete independent review. Keep customer data outside the installed skill and manager state directories.

The release was tested with Python 3.12 on macOS ARM64. Other runtime/platform combinations require their own preflight and regression checks. The managed installer performs the following runtime setup and checks automatically. For a separately validated development environment, resolve `SKILL_DIR` to the skill folder and `VENV_DIR` to a new dedicated environment folder; do not modify system Python:

```bash
python3.12 -m venv VENV_DIR
VENV_DIR/bin/python -m pip install -r SKILL_DIR/scripts/requirements-tested.txt
VENV_DIR/bin/python SKILL_DIR/scripts/scrub.py --check-dependencies --formats csv xlsx xls parquet
VENV_DIR/bin/python SKILL_DIR/scripts/preflight.py --formats csv xlsx xls parquet
```

Use the same interpreter for processing, verification and finalization. `--formats` accepts only `csv`, `xlsx`, `xls`, `parquet`. The preflight creates only synthetic inputs, checks independently authored expected outputs, supplies synthetic exact-span review evidence and runs finalization. CSV, XLSX, Parquet and the supported native XLS fixture must reach ready status. A separate XLS formula fixture must stay blocked even with complete review evidence. The top-level XLS row retains the blocked-fixture status for compatibility with Version 1.0 updaters; `native_supported_case` proves native readiness. Both XLS cases must pass. It does not inspect customer files or replace their review. Keep the result with local release evidence. If preflight fails, repair the installation or report the affected workflow blocked; do not waive the check.

`requirements-tested.txt` pins the tested runtime packages and their transitive dependencies. `requirements.txt` lists supported ranges for an independently validated alternative environment. The full synthetic suite additionally needs `requirements-dev.txt`:

```bash
VENV_DIR/bin/python -m pip install -r SKILL_DIR/scripts/requirements-dev.txt
VENV_DIR/bin/python -m unittest discover -s SKILL_DIR/scripts -p '*test*.py' -v
```

Include all test filenames matching `*test*.py`, not just the default `test*.py`. Re-run relevant regression tests after a change, plus full release tests before distributing a changed package. Record version, environment, test counts/failures/skips and supported scope. Do not treat a skipped adapter as validated.

## Customer-file pilot before routine use

After upgrading from internal development build 5.0.1 or earlier, reprocess Parquet originals into a new run and review/finalize again. These internal build numbers precede the GitHub Version 1.0 release. Earlier runs did not reliably preserve and verify separate footer metadata; their readiness status is not sufficient for this release.

1. Start with authorized copies of representative customer CSV, RVTools/XLSX, native XLS and Parquet exports from multiple customers. Include large/repeated-value files, zero-PII files, mixed free text, multilingual/encoded text, shared mailboxes and unfamiliar identity fields. Include workbook metadata/hidden sheets and both Parquet schema and footer metadata. Do not distribute raw customer examples with feedback.
2. Have a reviewer familiar with each customer's schema identify resource keys and expected human PII locally. Compare every original/output value and every masked span. Review retained content too; a small sample does not qualify a file. Independently check costs, quantities, types, row/order/schema, IDs/references and relevant metadata.
3. Confirm the chat delivers every processed copy, a readable per-file summary and its readiness status. Exercise blocked cases deliberately: unknown identity, PII embedded in a resource key, missing review, opaque content, changed source/output and XLS formulas or other unsupported content. ZIP/gzip inputs must return extraction instructions without an output copy; other disallowed types must be denied without a copy. None may become ready, while independent accepted files in a mixed batch can still complete.
4. Record only safe feedback: skill version, file ID/format, row/column counts, coordinates, expected/actual behavior, elapsed time, unresolved counts and import outcome if separately authorized. Report missed PII and over-masking privately using approved customer-data handling, without placing raw values in shared tickets or the skill.
5. Fix defects with general rules and synthetic regression fixtures, then repeat the affected pilot cases. Release each format for routine use only after reviewers confirm no missed confirmed PII or unjustified changes in the pilot, all structural/protected-ID checks pass, and operational review effort is acceptable. These criteria qualify the pilot cases, not every future file.

Matilda import testing is a separate manually authorized step using only locally ready files. Record acceptance or rejection independently. The skill never uploads. Any unresolved classification, uninspected content or preservation failure stays blocked; do not rename a file or edit a status to bypass it.

## Private run evidence

Run directories are private local working data. In addition to value-free reports and coordinate ledgers, a private provenance record binds source bytes to the run so changed originals cannot reuse stale review. It contains fingerprints for integrity only, never source text. Keep it local with the run, protect its permissions, and exclude it from team feedback, distribution archives, portable reports and uploads. Preserve it while re-verification is needed; deleting it blocks further finalization. This exception does not authorize customer value dictionaries, raw snippets, reusable identities or fingerprints in reports.
