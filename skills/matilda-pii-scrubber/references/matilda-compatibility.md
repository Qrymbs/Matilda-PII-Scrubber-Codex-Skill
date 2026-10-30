# Matilda compatibility and release

Resource identifiers, repeated references, schemas, native data types, formulas/caches, billing values and row order must retain their meaning. Exact original/output equality for protected machine keys is mandatory; check all occurrences, not only cardinality or a sample. Do not remove or mask a key because it contains a person's name. Explicit human PII embedded in a protected key remains unchanged and blocks privacy release.

X spans preserve surrounding technical text but do not guarantee importer acceptance. X strings can fail email/type validators; masking human contact join fields can collapse non-resource values, which the user accepts. Resource collisions are never accepted. A required typed value that cannot hold X is retained and flagged; never coerce types to force a clean scan.

Keep three states separate: processing completed, locally reviewed and ready for manual submission, and Matilda import acceptance. No tool upload or acceptance test is part of this skill. `ready_for_manual_submission` requires unchanged source provenance, full current-run context review, explicit reviewed spans for every changed scalar, complete original/output comparison, exact masking ledger reconciliation, complete independent candidate checks and no unresolved conflicts. No filename, boolean flag or clean regex result substitutes for this evidence.

Finalized copies are separated into `ready/` and `blocked/`. Re-finalizing first revokes previous ready status. Deliver actual processed copies with clickable links, per-file summaries and explicit statuses directly in chat, including blocked copies. A failed or incomplete input must be listed even when no scrubbed copy is possible. Ready means local checks passed and is never a claim of Matilda importer acceptance.

Rejected archives and other denied formats produce no artifact. Unsupported XLS content, embedded images/objects or incomplete comparisons keep an accepted input blocked. Other independent files may still complete. Do not infer that passing synthetic tests establishes zero residual PII, legal anonymization or universal file support.
