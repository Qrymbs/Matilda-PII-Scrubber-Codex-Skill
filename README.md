# Matilda PII Scrubber Codex Skill

**Version 1.0.0 · Private team distribution**

A Codex skill for reviewing and masking confirmed human PII in customer billing and RVTools files before a separate manual Matilda upload. It preserves originals, billing data and resource identifiers. Every run returns

1. The processed file links
2. A per-file summary
3. An explicit upload-preparedness status directly in chat.

## Supported scope

| Input | Behavior |
| --- | --- |
| `.csv` | Can qualify for manual upload after all per-file checks and review pass. |
| `.xlsx` | Can qualify after all checks, including inspectable workbook metadata and hidden content. Unsupported/opaque content blocks readiness. |
| `.parquet` | Can qualify after typed data, schema, protected identifiers and separate schema/footer metadata checks pass. |
| `.xls` | Best-effort conversion to a scrubbed `.xlsx` copy only. **Always blocked for upload.** Save/export the original as a genuine `.xlsx` and submit that new original for review. |
| ZIP, gzip and other archives | Rejected. Extract/decompress first and provide individual supported files. |
| Everything else | Denied; no scrubbed copy is produced. Renaming an extension does not make a file supported. |

This skill follows a **human-PII-only** policy. It preserves organizations, cloud accounts, projects, technical labels, costs and infrastructure identifiers. Confirmed human PII spans become one uppercase `X` per original character. PII inside a protected resource identifier is retained and blocks upload. Unknown identity, type/schema conflicts, incomplete inspection and failed comparisons also block upload.

The `_SCRUBBED` filename does not establish readiness. Only the finalized status `ready_for_manual_submission` permits the message **“Ready for manual Matilda upload — local checks passed; Matilda import acceptance unverified.”** This does not certify legal anonymization, zero residual PII or Matilda importer acceptance.

## Install

1. Obtain access to this private repository from its owner and accept the GitHub invitation. Each teammate uses their own GitHub account.
2. Use Codex desktop with local-file access, Git, GitHub CLI (`gh`) and **Python 3.12**. The release workflow is validated on macOS; other platforms need their own checks. On a Mac with Homebrew, missing prerequisites can be installed with `brew install git gh python@3.12`. Confirm `python3.12 --version` and `gh --version`.
3. Sign in and install from the Version 1.0 bootstrap. Run these commands in a suitable local software folder, outside customer-data folders:

```bash
gh auth login --hostname github.com --web --git-protocol https
gh repo clone Qrymbs/Matilda-PII-Scrubber-Codex-Skill -- --branch v1.0.0 --depth 1
cd Matilda-PII-Scrubber-Codex-Skill
python3.12 tools/manage_skill.py install
```

The installer fetches the latest published stable release from this private repository, checks its version and immutable commit, creates a dedicated Python environment, installs pinned dependencies, and runs the full synthetic test suite plus CSV/XLSX/XLS/Parquet preflight **before activation**. Internet access is needed for GitHub and Python dependencies. Keep the command's final result; a failed install is not ready for use.

New installations use `~/.agents/skills/matilda-pii-scrubber`. A single existing legacy installation at `~/.codex/skills/matilda-pii-scrubber` is backed up and adopted. If both locations contain a copy, the installer stops: resolve the duplicate before continuing. Do not maintain two active skills with the same name.

The manager, runtime, validation evidence and backups live outside the skill at `~/.local/share/matilda-pii-scrubber`. Its `status` command reports the installed version, actual skill path and Python interpreter. Codex should discover the skill; restart Codex if it does not appear. [Official skill-loading guidance](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)

```bash
python3.12 ~/.local/share/matilda-pii-scrubber/manage_skill.py status
```

You can also ask Codex: “Install the latest stable release of the private Qrymbs/Matilda-PII-Scrubber-Codex-Skill repository using its README and installer. Use my GitHub access, run all installation checks, and report the installed version and result. Ask me to complete sign-in if needed.”

## Use it

Start a local Codex chat, attach or provide the absolute paths to authorized customer files, and say:

> Use $matilda-pii-scrubber on these files. Return every processed file as a clickable link, a per-file PII summary and the final Matilda upload-preparedness status directly in this chat. Preserve the originals and do not upload anything.

Codex must use the managed Python interpreter reported by `status` for processing, verification and finalization. Answer any identity/context questions based on evidence. If you do not know, say so; the file stays blocked.

Review the file link, summary and verification report. A processed but blocked file is still delivered and labeled **“Blocked — do not upload.”** If no safe output can be produced, the chat explains why. Upload only a file whose final checks pass, through your normal separately authorized Matilda process. Treat import acceptance as a separate result.

Keep originals, outputs and run evidence in approved private customer-data locations, outside this repository and the installed skill. Codex use must follow your team's approved customer-data handling. Do not commit customer files or raw PII examples, or put them into shared feedback.

## Update with one command

```bash
python3.12 ~/.local/share/matilda-pii-scrubber/manage_skill.py update
```

The updater checks published stable GitHub releases, not unreleased changes on `main`. It validates a candidate in a new environment before replacing the active skill, keeps a backup, and restores the prior installation if activation fails. An unchanged release is a no-op. Local edits, moved tags, downgrades, missing access or failed checks stop the update rather than silently replacing the working skill. Resolve failures and retry; do not bypass validation or hand-edit readiness reports.

Backups and candidate environments are retained locally; clean up old ones only after confirming the installed release works. Do not edit a managed installation directly—propose general fixes in the repository, using synthetic fixtures.

## Set up a weekly update task in Codex

After a successful install, run the update command once in an ordinary local chat to verify access. Then send Codex this prompt on **each teammate's own computer**:

> Create a standalone local scheduled task named “Update Matilda PII Scrubber” for every Monday at 9:00 AM in my local timezone, with a new chat for each run. Run `python3.12 ~/.local/share/matilda-pii-scrubber/manage_skill.py update` using my existing GitHub authentication. Install only the latest stable release from Qrymbs/Matilda-PII-Scrubber-Codex-Skill through that manager and its validation checks. Do not process customer files. Report a successful version change, failed update or required action; keep the current working installation when validation fails. If it is already current, do not send an update notification.

Use a **local** scheduled task associated with a local project/folder, not a cloud task or a fresh worktree. Review the schedule Codex creates and test its first run. Local scheduled work requires the computer to be powered on and Codex desktop running. Authentication, network access or execution approval may need attention; scheduling does not bypass those requirements. The repository cannot enable a task on someone else's computer. [Official automation guidance](https://learn.chatgpt.com/docs/automations)

## Customer-file pilot before routine use

Have each teammate test representative authorized files from their own customer work before relying on the skill routinely:

1. Include CSV billing files, RVTools/XLSX, Parquet, zero-PII examples, free text, repeated values, workbook metadata/hidden content and Parquet footer/schema metadata where available.
2. Review both masked and retained content locally. Verify costs, quantities, types, row counts, formulas, schema and resource identifiers against the original. Confirm every identified personal span was correctly handled; a small sample alone does not clear a file.
3. Exercise blocked cases: an unresolved identity, personal information inside a protected resource name, legacy XLS, ZIP/gzip and an unsupported type. They must not be reported ready.
4. Confirm chat delivery includes the processed files, summaries, exact useful locations, verification reports and readiness for every supplied file. Zero masks is a valid outcome only when review is complete.
5. Report the version, format, safe file ID, coordinates, expected/actual behavior and import outcome if separately authorized. Share suspected misses or over-masking privately through approved channels, without raw PII in GitHub issues or team messages. Fix defects with general rules and synthetic tests, then repeat affected cases.

Parquet files processed by **internal build 5.0.1 or earlier** must be reprocessed from the originals and reviewed again; older readiness results did not reliably cover separate footer metadata.

## Maintainer release procedure

1. Change code and synthetic tests together. Run the root updater tests and the full skill suite, then four-format preflight. CI runs these checks on pushes and pull requests. Do not use customer files in CI.
2. Increment root `VERSION` and `skills/matilda-pii-scrubber/SKILL.md` together. Publish an immutable matching `vX.Y.Z` tag and a non-draft, non-prerelease GitHub release only after validation. Do not move a released tag or mark an older release as latest.
3. Test the published release with an isolated fresh install and an update from the preceding release. Record the exact commit, platform, test counts, failures/skips and preflight result. Publishing a release makes it eligible for teammates' next update.
4. Keep repository access limited to intended teammates. The owner adds them in GitHub **Settings → Collaborators**, using their GitHub usernames; each must accept the invitation.

Developer checks (in an isolated Python 3.12 environment with `requirements-dev.txt` installed):

```bash
python -B -m unittest discover -s tests -p 'test*.py' -v
python -B -m unittest discover -s skills/matilda-pii-scrubber/scripts -p '*test*.py' -v
python -B skills/matilda-pii-scrubber/scripts/preflight.py --formats csv xlsx xls parquet
```

See the skill's [setup and pilot details](skills/matilda-pii-scrubber/references/setup-and-validation.md) and [format limitations](skills/matilda-pii-scrubber/references/formats.md). Customer readiness is always a per-file decision, separate from software release validation.
