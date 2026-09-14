# ADR 0002: Finding model and stable IDs

- Status: Accepted

## Context

MailAuthProbe is used both interactively and in automation (CI gates, SOC
enrichment). Automation needs to suppress, route or count specific problems
across releases. Free-text messages are not a usable key, and severities alone
do not say *why* something matters: a DMARC record with `p=none` is perfectly
valid but offers no protection, while a record with a duplicated `p` tag is
invalid.

## Decision

1. Every observation is a `Finding` with the fields `id`, `severity`,
   `category`, `component`, `title`, `subject`, `description`, `evidence`,
   `recommendation` and `references`.
2. Findings are created from `Rule` values registered in a single catalog
   (`internal/findings/catalog.go`). The rule owns the ID, title, default
   severity, category, recommendation and references; the instance adds the
   subject, description and evidence.
3. IDs have the form `MAIL-<COMPONENT>-<NNN>` and are never renumbered or
   reused. Removing a rule means keeping it in the catalog as deprecated.
4. Severities are `critical`, `high`, `medium`, `low`, `info` and `pass`.
   Passing checks are findings too, so reports can show what *was* verified.
5. Categories separate the nature of a finding from its severity:
   `standard-violation`, `security-weakness`, `hardening`, `informational`.
6. A rule defines a default severity. Callers may override it when context
   changes the risk (for example a missing `all` term is worse when the domain
   also has no DMARC record).
7. `docs/findings.md` is generated from the catalog and a test fails when the
   two diverge, so every ID change is visible in code review.

## Consequences

- Adding a check requires registering a rule; ID collisions panic at start-up
  and are caught by the unit tests.
- Severity overrides mean `--fail-on` operates on instance severity, not the
  catalog default. The JSON report always contains the effective severity.
- The central catalog creates a small amount of coupling between protocol
  packages and `findings`, which is acceptable because `findings` has no
  dependencies of its own.
