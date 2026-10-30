import copy
from pathlib import Path
import pytest
from bulwark.threatmodel import engine as E
from bulwark import refs

MODEL = E.load(Path(__file__).resolve().parents[1] / "data/model/cloudclinic.yml")


def rules(m): return {(f.rule, f.location) for f in E.analyze(m)}


def test_baseline_model_has_expected_findings():
    r = rules(MODEL)
    assert ("phi-to-partner-unminimized", "F5 fhir_adapter->ehr_partner") in r
    assert not [x for x in r if x[0] in ("flow-no-tls", "store-unencrypted", "unauthenticated-inbound")]


def test_all_cited_references_exist_in_real_catalogs():
    assert E.validate_refs(E.analyze(MODEL)) == []
    # also check every rule's refs by forcing each one to fire
    m = copy.deepcopy(MODEL)
    for f in m["flows"]: f["tls"] = False
    for e in m["elements"].values():
        if e["kind"] == "store": e["encrypted_at_rest"] = False; e["append_only"] = False
    assert E.validate_refs(E.analyze(m)) == []


def test_real_catalog_lookups():
    assert refs.attack_ok("T1078") and not refs.attack_ok("T9999")
    assert refs.nist_ok("sc-8") and refs.nist_ok("au-9.2") and not refs.nist_ok("zz-1")


@pytest.mark.parametrize("fid", [f["id"] for f in MODEL["flows"]])
def test_removing_tls_from_any_flow_with_sensitive_data_is_flagged(fid):
    m = copy.deepcopy(MODEL)
    flow = next(f for f in m["flows"] if f["id"] == fid); flow["tls"] = False
    assert any(r[0] == "flow-no-tls" and r[1].startswith(fid + " ") for r in rules(m)), flow


def test_unencrypted_phi_store_flagged_for_each_store():
    for name, e in MODEL["elements"].items():
        if e["kind"] != "store": continue
        m = copy.deepcopy(MODEL); m["elements"][name]["encrypted_at_rest"] = False
        assert ("store-unencrypted", name) in rules(m), name


def test_audit_log_mutable_flagged():
    m = copy.deepcopy(MODEL); m["elements"]["audit_log"]["append_only"] = False
    assert ("audit-mutable", "audit_log") in rules(m)


def test_removing_authn_from_gateway_is_flagged():
    m = copy.deepcopy(MODEL); del m["elements"]["api_gateway"]["authn"]
    assert any(r[0] == "unauthenticated-inbound" and "api_gateway" in r[1] for r in rules(m))


def test_output_is_deterministic():
    assert [f.to_dict() for f in E.analyze(MODEL)] == [f.to_dict() for f in E.analyze(copy.deepcopy(MODEL))]


def test_data_class_typo_must_not_silently_drop_a_threat():
    """'phi' is not 'PHI'.  A lowercase typo used to remove the flow from every PHI rule."""
    m = copy.deepcopy(MODEL)
    next(f for f in m["flows"] if f["id"] == "F4")["data"] = ["phi"]
    next(f for f in m["flows"] if f["id"] == "F4")["tls"] = False
    with pytest.raises(E.ModelError):
        E.analyze(m)


def test_unknown_element_in_flow_is_a_model_error_not_a_keyerror():
    m = copy.deepcopy(MODEL); m["flows"][0]["dst"] = "api_gatway"
    with pytest.raises(E.ModelError):
        E.analyze(m)
