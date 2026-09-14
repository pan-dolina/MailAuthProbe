# ADR 0005: Versioned JSON report

- Status: Accepted

## Context

`mailauthprobe --json` feeds CI gates, SIEM pipelines and ticketing
automation. Those consumers break silently when output changes shape, and
they need to know which fields they can rely on.

## Decision

1. Every JSON report carries `"schema_version": "1"`. The version changes only
   for incompatible changes (removing or renaming a field, changing a type or
   the meaning of a value). Adding fields is compatible and does not bump the
   version; consumers must ignore unknown properties.
2. The stable contract is the top level (`schema_version`, `tool`, `kind`,
   `target`, `summary`, `findings`, `errors`) and the finding object. It is
   described in `docs/schema/report-v1.schema.json` and checked by tests.
3. The `domain` and `message` objects expose detailed intermediate results
   (SPF tree, DKIM verification details, Received hops). They are documented
   as informational: fields may be added, and automation should key on
   finding IDs rather than on these details.
4. Output is deterministic for identical input and DNS data: findings are
   sorted by severity, ID, subject and description; maps are encoded with
   sorted keys; the report contains no generation timestamp or random
   identifiers. Times that come from the analysed data (Received dates,
   certificate expiry) are included as they are.
5. `findings` and `errors` are always arrays, never `null`.
6. Values that carry provenance (Received hop fields, SPF inputs) include
   their source (`stated`/`inferred`, `flag`/`received`/`return-path`).

## Consequences

- Golden-file tests compare full JSON output for fixtures, so any change in
  output shows up in review.
- A generation timestamp, if needed, has to be added by the consumer.
- Introducing schema version 2 requires a new schema file and a documented
  migration; version 1 output stays available for at least one minor
  release.
