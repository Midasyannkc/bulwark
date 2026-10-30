# Architecture

```
data/raw        real: NIST 800-53 rev5, MITRE ATT&CK, FHIR R4 element definitions (trimmed, hashed)
data/model|ir|snapshots|fhir   invented inputs
bulwark/
  threatmodel/  YAML data-flow model -> STRIDE threats with ATT&CK and NIST citations
  ir/           runbook linter, HIPAA breach deadlines, tabletop scoring
  evidence/     15 collectors, control library, hashed evidence package, freshness, baseline coverage
  fhir/         R4 validator, Safe Harbor de-identification, in-process API, partner assessment
  refs.py       lookups against the real catalogs
  report.py     runs everything, writes out/report.json and docs/REPORT.md
```

Rules that run through every module:

1. **Cite only what resolves.** Every ATT&CK, NIST and FHIR reference is checked against the real data.
2. **Nothing to test is not a pass.** Empty populations are `untestable`.
3. **Evidence is hashed and expires.** A stale or altered artifact is reported, not trusted.
4. **Every fix is two commits.** `scripts/verify_incidents.py` re-runs both in scratch worktrees.
