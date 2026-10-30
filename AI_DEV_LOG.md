# AI development log

Built in one session with Claude as the coding assistant. Christian Kouadio Kouassi is the author and owner of every commit.

## What the assistant generated

The Python source, tests, synthetic data, the threat model, runbooks, scenarios, control library, the in-process API and its seeded flaws, the report generator, the deck and this log.

## What was checked, and how

- **Real reference data.** Every ATT&CK, NIST and FHIR identifier used is resolved against the downloaded catalogs by tests; the report shows 0 unverified citations.
- **Every incident has a failing test first**, run in clean worktrees by `scripts/verify_incidents.py` (10 of 10).
- **Found, not planned.** INC-2 (runbook preservation), INC-3 (empty population), INC-4 (choice types), INC-5 and INC-6 (de-identification leaks) came from running the tools against fixtures and edge cases. INC-7 to INC-10 are seeded API flaws with exploit tests.
- **Wrong first attempts.** One YAML file did not parse (an unquoted `value[x]`). A search-leak test and a scope-type test passed at once because the INC-7 fix already covered them, so they are logged as regression tests rather than separate incidents. The first de-identification commit had a failing test and was rebuilt as a proper reproduce and fix sequence before delivery.

## What was not verified

- No live AWS, SIEM, EHR or auditor, and no real Rezilient architecture.
- Framework citations are from my knowledge of public frameworks; confirm against current text before use in a real audit.
- The tabletop scores scripted plays, not people.
- Safe Harbor coverage is limited to the fields in the fixtures.
