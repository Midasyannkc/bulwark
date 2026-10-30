import copy, json
import pytest
from bulwark.fhir import api

P1 = {"scope": "patient/Patient.read patient/Observation.read", "patient": "p1", "sub": "pt-1"}


def call(method, path, token=P1, query=None, body=None):
    return api.handle({"method": method, "path": path, "query": query or {}, "token": token, "body": body})


@pytest.fixture(autouse=True)
def fresh():
    snap = copy.deepcopy(api.STORE); api.AUDIT.clear()
    yield
    api.STORE.clear(); api.STORE.update(snap)


def test_patient_reads_own_record_and_observations():
    assert call("GET", "/Patient/p1")[0] == 200
    s, b = call("GET", "/Observation", query={"patient": "p1"})
    assert s == 200 and b["total"] == 2


def test_metadata_is_public_and_requests_without_token_are_401():
    assert call("GET", "/metadata", token=None)[0] == 200
    assert call("GET", "/Patient/p1", token=None)[0] == 401


def test_scope_parser():
    assert api.parse_scope("patient/Observation.read") == ("patient", "Observation", "read")
    assert api.parse_scope("user/*.*") == ("user", "*", "*")
    assert api.parse_scope("patient/observation.read") is None and api.parse_scope("admin/*.*") is None


def test_patient_token_cannot_read_another_patients_record():
    for path in ("/Patient/p2", "/Observation/o2", "/Encounter/e1"):
        assert call("GET", path, token={**P1, "scope": "patient/*.read"})[0] in (403, 404), path
    s, b = call("GET", "/Observation", query={"patient": "p2"})
    assert s == 403 or b["total"] == 0


def test_read_only_scope_cannot_write_or_overwrite():
    new = {"resourceType": "Observation", "id": "o9", "status": "final", "code": {"text": "x"}, "subject": {"reference": "Patient/p1"}}
    assert call("POST", "/Observation", body=new)[0] == 403
    assert "o9" not in api.STORE["Observation"]
    clobber = {"resourceType": "Observation", "id": "o1", "status": "final", "code": {"text": "tampered"}, "subject": {"reference": "Patient/p1"}}
    assert call("POST", "/Observation", token={**P1, "scope": "patient/Observation.read"}, body=clobber)[0] == 403
    assert api.STORE["Observation"]["o1"]["code"]["text"] == "Systolic blood pressure"


def test_writer_cannot_write_into_another_patients_compartment():
    tok = {**P1, "scope": "patient/Observation.write"}
    other = {"resourceType": "Observation", "id": "o8", "status": "final", "code": {"text": "x"}, "subject": {"reference": "Patient/p2"}}
    assert call("POST", "/Observation", token=tok, body=other)[0] == 403
    mine = {**other, "id": "o7", "subject": {"reference": "Patient/p1"}}
    assert call("POST", "/Observation", token=tok, body=mine)[0] == 201


def test_name_search_does_not_reveal_other_patients_to_a_patient_token():
    s, b = call("GET", "/Patient", query={"name": "Fakename"})    # matches p1 (self) and p3 (stranger)
    ids = sorted(e["resource"]["id"] for e in b["entry"])
    assert ids == ["p1"], ids
    s, b = call("GET", "/Patient", query={"name": "Samplesmith"})
    assert b["total"] == 0


def test_unfiltered_search_is_limited_to_the_callers_compartment():
    s, b = call("GET", "/Observation")
    assert sorted(e["resource"]["id"] for e in b["entry"]) == ["o1", "o3"]


def test_practitioner_user_scope_may_search_across_patients():
    tok = {"scope": "user/Patient.read user/Observation.read", "sub": "dr-1"}
    assert call("GET", "/Patient", token=tok, query={"name": "Fakename"})[1]["total"] == 2


SYS = {"scope": "system/*.read", "sub": "svc-export"}


def test_bulk_export_requires_a_system_scope():
    assert call("GET", "/$export", token=None)[0] == 401
    assert call("GET", "/$export", token=P1)[0] == 403
    assert call("GET", "/$export", token={"scope": "user/Patient.read", "sub": "dr"})[0] == 403
    s, b = call("GET", "/$export", token=SYS)
    assert s == 200 and len(b["entry"]) == 7


def test_audit_log_and_errors_do_not_contain_phi():
    api.AUDIT.clear()
    bad = {"resourceType": "Patient", "id": "zz", "name": [{"family": "Secretname"}]}
    s, b = call("POST", "/Observation", token={**P1, "scope": "patient/Observation.write"}, body=bad)
    call("GET", "/Patient", query={"name": "Fakename"})
    call("GET", "/Nonexistent", query={"name": "Samplesmith"})
    s2, b2 = call("GET", "/Nonexistent", query={"name": "Samplesmith"})
    blob = json.dumps(api.AUDIT) + json.dumps(b) + json.dumps(b2)
    for secret in ("Secretname", "Fakename", "Samplesmith"):
        assert secret not in blob, secret
    assert all("body" not in a for a in api.AUDIT) and all(a["sub"] for a in api.AUDIT)
