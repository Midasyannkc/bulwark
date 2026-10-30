# Data sources

## Real (downloaded by scripts/fetch_data.py, trimmed, hashes in data/raw/MANIFEST.json)

| File | Source | Used for |
| --- | --- | --- |
| data/raw/nist80053.json | NIST OSCAL SP 800-53 rev5 catalog and Moderate baseline profile, usnistgov/oscal-content | every control ID referenced in threat models and evidence maps is checked against it; baseline coverage is computed from it |
| data/raw/attack_techniques.json | MITRE ATT&CK enterprise, mitre/cti (non-revoked, non-deprecated techniques) | every technique ID in a threat or scenario is checked against it |
| data/raw/fhir_r4_elements.json | HL7 FHIR R4 StructureDefinitions via HAPI validation resources (15 resources) | every element path in a synthetic FHIR resource is checked against the real specification |

## Invented (disclosed)

- The CloudClinic architecture model, runbooks, tabletop scenarios and cloud configuration snapshots. Rezilient's real architecture is not public and nothing here describes it.
- All FHIR resources and patients. They are fictional; element paths are real, values are made up.
- The in-process FHIR API under test and its seeded flaws.

## Not done

- No live AWS account, SIEM, EHR, identity provider or auditor. Collectors read JSON snapshots shaped like AWS API output, not the API.
- HIPAA, SOC 2 and HITRUST criteria are cited by ID from public frameworks as I know them; HITRUST CSF text is licensed and not reproduced.
- Detections, runbooks and scoring are original work, not vendor content.
