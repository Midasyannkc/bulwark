# Incident log

Every incident has two commits. The first adds a test that fails for the right reason; a later one fixes the code and the same test passes. Hashes below come from `git log`.

| # | Incident | Found by | Reproduce | Fix |
| --- | --- | --- | --- | --- |
| INC-1 | A data class typo silently removed a flow from every PHI rule | threat model mutation tests | `a1118a0` | `645ab0e` |
| INC-2 | The ransomware runbook had no explicit evidence-preservation step | tabletop simulator scoring of the weak play | `365e383` | `c3ef1d5` |
| INC-3 | An empty population counted as a passing control | evidence collector edge case tests | `689cf9e` | `54ff4e1` |
| INC-4 | Any capitalised suffix was accepted for a FHIR choice element | validation against the real R4 definitions | `caf0f71` | `db57a3c` |
| INC-5 | Patient names inside free text survived de-identification | leak scan on fixture Observation o3 | `06cf9c3` | `79c1ea7` |
| INC-6 | Timestamps kept their full date during de-identification | leak scan on fixture Encounter e1 | `9457a3f` | `d96208d` |
| INC-7 | Any patient token could read any other patient's record (BOLA) | exploit test against the seeded API | `00e8385` | `9edbedb` |
| INC-8 | POST ignored scopes, so a read-only token could write | exploit test against the seeded API | `fadbfbb` | `9e5cdda` |
| INC-9 | Bulk export returned every record with no token | exploit test against the seeded API | `f18bc90` | `52eaa0f` |
| INC-10 | PHI reached audit logs and error responses | exploit test against the seeded API | `dee05b5` | `0ba4ae5` |

### INC-1: A data class typo silently removed a flow from every PHI rule

A lowercase phi on a flow made every PHI rule skip it, and a misspelled element name crashed with a bare KeyError. The model is now validated first and every problem is listed in one ModelError.

Reproduce `a1118a0`, fix `645ab0e`. Found by: threat model mutation tests.

### INC-2: The ransomware runbook had no explicit evidence-preservation step

The linter and simulator found preservation by matching the word preserve, which an isolation step happened to contain. Steps now carry a structured preserves_evidence flag, and the ransomware runbook gained a real forensic acquisition step.

Reproduce `365e383`, fix `c3ef1d5`. Found by: tabletop simulator scoring of the weak play.

### INC-3: An empty population counted as a passing control

With no PHI bucket found, the PHI bucket control reported pass, and an empty training roster divided by zero. A control with nothing to test is now untestable, which an auditor reads very differently from pass.

Reproduce `689cf9e`, fix `54ff4e1`. Found by: evidence collector edge case tests.

### INC-4: Any capitalised suffix was accepted for a FHIR choice element

valueBanana and valuePatient validated as Observation values. A choice suffix must now be one of the types the specification declares for that element.

Reproduce `caf0f71`, fix `db57a3c`. Found by: validation against the real R4 definitions.

### INC-5: Patient names inside free text survived de-identification

Pattern scrubbing removes phone numbers and dates but cannot find a name. The scrubber now removes the patient's own name parts and street lines. Names of other people in notes would still need review.

Reproduce `06cf9c3`, fix `79c1ea7`. Found by: leak scan on fixture Observation o3.

### INC-6: Timestamps kept their full date during de-identification

The date pattern required a word boundary after the day, which a following T breaks, so period.start and period.end kept 2026-09-12. They are reduced to the year now.

Reproduce `9457a3f`, fix `d96208d`. Found by: leak scan on fixture Encounter e1.

### INC-7: Any patient token could read any other patient's record (BOLA)

Reads by id ignored the token's patient context and scope type. Reads and search results are now filtered by scope type, action and compartment.

Reproduce `00e8385`, fix `9edbedb`. Found by: exploit test against the seeded API.

### INC-8: POST ignored scopes, so a read-only token could write

A read-only token could create or overwrite observations, including in another patient's compartment. Writes now need a write scope and, for patient scopes, the caller's own compartment.

Reproduce `fadbfbb`, fix `9e5cdda`. Found by: exploit test against the seeded API.

### INC-9: Bulk export returned every record with no token

GET /$export was handled before authentication. It now requires a token with a system/*.read scope.

Reproduce `f18bc90`, fix `52eaa0f`. Found by: exploit test against the seeded API.

### INC-10: PHI reached audit logs and error responses

The audit log stored bodies and search values, and errors echoed the submitted resource and query. Audit entries now keep who, what path and which query keys, never values or bodies.

Reproduce `dee05b5`, fix `0ba4ae5`. Found by: exploit test against the seeded API.
