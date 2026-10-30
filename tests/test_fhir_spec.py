import json
from pathlib import Path
from bulwark.fhir import spec

FX = json.loads((Path(__file__).resolve().parents[1] / "data/fhir/fixtures.json").read_text())
ALL = FX["patients"] + FX["observations"] + FX["encounters"]


def test_every_fixture_validates_against_real_r4_definitions():
    for r in ALL:
        assert spec.validate(r) == [], (r["id"], spec.validate(r))


def test_unknown_element_and_bad_cardinality_are_found():
    r = dict(FX["patients"][0]); r["firstName"] = "Ada"; r["name"] = {"family": "x"}
    rules = {(f.rule) for f in spec.validate(r)}
    assert {"unknown-element", "cardinality"} <= rules


def test_required_elements_enforced():
    o = dict(FX["observations"][0]); del o["status"]
    assert any(f.rule == "missing-required" and "status" in f.title for f in spec.validate(o))
    e = dict(FX["encounters"][0]); del e["class"]
    assert any(f.rule == "missing-required" for f in spec.validate(e))



def test_choice_type_value_x_accepted_and_wrong_suffix_rejected():
    o = dict(FX["observations"][0])
    assert spec.validate(o) == []
    o["valueBanana"] = 1
    assert any(f.rule == "unknown-element" for f in spec.validate(o))


def test_choice_type_suffix_must_be_an_allowed_type():
    o = dict(FX["observations"][0]); del o["valueQuantity"]
    for good in ("valueString", "valueBoolean", "valueCodeableConcept", "valueDateTime", "valueInteger"):
        assert not [f for f in spec.validate({**o, good: 1}) if f.rule == "unknown-element"], good
    for bad in ("valueBanana", "valuePatient", "valueQuantityX"):
        assert any(f.rule == "unknown-element" for f in spec.validate({**o, bad: 1})), bad
