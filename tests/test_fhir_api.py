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
