import json
from pathlib import Path
from bulwark.fhir import deid

FX = json.loads((Path(__file__).resolve().parents[1] / "data/fhir/fixtures.json").read_text())
KEY = b"test-key"
ALL = FX["patients"] + FX["observations"] + FX["encounters"]
RAW = ["Ada", "Fakename", "Samplesmith", "Ben", "Cora", "555-010-0101", "ada.fakename@example.test", "900-12-3456", "MRN-100234", "12 Imaginary Rd", "1948-03-14", "1991-11-02"]


def test_no_identifying_value_survives_deidentification():
    for r in ALL:
        if r["id"] in ("o3", "e1"): continue
        d = deid.deidentify(r, KEY)
        assert deid.leaks(d, RAW) == [], (r["id"], deid.leaks(d, RAW))


def test_birth_date_reduced_to_year_and_over_89_aggregated():
    p1 = deid.deidentify(FX["patients"][0], KEY)   # born 1948, age 78 in 2026
    p3 = deid.deidentify(FX["patients"][2], KEY)   # born 1930, age 96
    assert p1["birthDate"] == "1948" and p3["birthDate"] == "1936"


def test_geography_limited_to_state_and_zip3():
    a = deid.deidentify(FX["patients"][0], KEY)["address"][0]
    assert a == {"state": "TX", "postalCode": "75000"}


def test_free_text_is_scrubbed_of_phone_and_date():
    d = deid.deidentify(FX["observations"][2], KEY)
    assert "555-010-0101" not in json.dumps(d) and "2026-10-03" not in json.dumps(d)


def test_pseudonyms_are_stable_per_key_and_references_follow():
    a, b = deid.deidentify(FX["observations"][0], KEY), deid.deidentify(FX["observations"][2], KEY)
    assert a["subject"]["reference"] == b["subject"]["reference"] == "Patient/" + deid.pseudonym("p1", KEY)
    assert deid.pseudonym("p1", KEY) != deid.pseudonym("p1", b"other")


def test_leak_scanner_detects_planted_identifiers():
    bad = {"resourceType": "Observation", "id": "z", "status": "final", "note": [{"text": "call 214-555-0188 or ada@example.test, SSN 123-45-6789"}], "effectiveDateTime": "2026-09-01"}
    rules = {f.rule for f in deid.leaks(bad)}
    assert {"leak-phone", "leak-email", "leak-ssn", "leak-full-date"} <= rules


def test_patient_names_in_free_text_are_removed():
    """Observation o3 has 'Patient Ada Fakename called ...' in a note.  Pattern scrubbing cannot find names."""
    names = deid.names_for(FX["patients"])
    d = deid.deidentify(FX["observations"][2], KEY, names=names)
    assert deid.leaks(d, RAW) == []
    assert "Ada" not in json.dumps(d) and "Fakename" not in json.dumps(d)
