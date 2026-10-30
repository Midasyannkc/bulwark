"""A tiny in-process FHIR-style API with SMART on FHIR v1 style scopes.  It is the target under test.
No network, no web framework: handle(request) takes a dict and returns (status, body)."""
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FX = json.loads((ROOT / "data/fhir/fixtures.json").read_text())
STORE = {"Patient": {p["id"]: p for p in FX["patients"]}, "Observation": {o["id"]: o for o in FX["observations"]}, "Encounter": {e["id"]: e for e in FX["encounters"]}}
AUDIT = []


def parse_scope(sc):
    m = re.fullmatch(r"(patient|user|system)/(\*|[A-Z][A-Za-z]+)\.(read|write|\*)", sc)
    return m.groups() if m else None


def patient_of(res):
    if res["resourceType"] == "Patient":
        return res["id"]
    ref = (res.get("subject") or res.get("patient") or {}).get("reference", "")
    return ref.split("/")[-1] if ref else None


def may(scopes, tok, rtype, action, res=None):
    """True if some scope grants action on rtype, and a patient-level scope also matches the token's patient compartment."""
    for sc in scopes:
        if not sc: continue
        level, t, a = sc
        if t not in ("*", rtype) or a not in ("*", action): continue
        if level == "patient" and res is not None and patient_of(res) != tok.get("patient"): continue
        return True
    return False


def outcome(sev, code, diag):
    return {"resourceType": "OperationOutcome", "issue": [{"severity": sev, "code": code, "diagnostics": diag}]}


def handle(req):
    """req: {method, path, query, token: {scope: 'a b', patient: 'p1', sub: 'u1'} or None, body}"""
    method, path, q, tok = req["method"], req["path"], req.get("query", {}), req.get("token")
    AUDIT.append({"method": method, "path": path, "query_keys": sorted(q), "sub": (tok or {}).get("sub") or "anonymous"})
    if path == "/metadata":
        return 200, {"resourceType": "CapabilityStatement", "status": "active", "kind": "instance", "fhirVersion": "4.0.1", "format": ["json"]}
    if tok is None:
        return 401, outcome("error", "login", "token required")
    scopes = [parse_scope(s) for s in tok["scope"].split()]
    if path == "/$export":
        if not any(sc and sc[0] == "system" and sc[1] == "*" and sc[2] in ("*", "read") for sc in scopes):
            return 403, outcome("error", "forbidden", "system/*.read required")
        return 200, {"resourceType": "Bundle", "type": "collection", "entry": [{"resource": r} for t in STORE.values() for r in t.values()]}
    m = re.fullmatch(r"/([A-Za-z]+)(?:/([\w-]+))?", path)
    if not m or m.group(1) not in STORE:
        return 404, outcome("error", "not-found", "no such resource type or route")
    rtype, rid = m.groups()
    if method == "GET" and rid:
        res = STORE[rtype].get(rid)
        if not res or not may(scopes, tok, rtype, "read", res):
            return 404, outcome("error", "not-found", f"{rtype}/{rid} not found")
        return 200, res
    if method == "GET":
        out = list(STORE[rtype].values())
        if "name" in q and rtype == "Patient":
            out = [p for p in out if any(q["name"].lower() in (n.get("family", "") + " ".join(n.get("given", []))).lower() for n in p.get("name", []))]
        if "patient" in q:
            out = [r for r in out if patient_of(r) == q["patient"]]
        out = [r for r in out if may(scopes, tok, rtype, "read", r)]
        return 200, {"resourceType": "Bundle", "type": "searchset", "total": len(out), "entry": [{"resource": r} for r in out]}
    if method == "POST":
        body = req.get("body") or {}
        if not may(scopes, tok, rtype, "write", body if body.get("resourceType") == rtype else None):
            return 403, outcome("error", "forbidden", "insufficient scope")
        if body.get("resourceType") != rtype:
            return 400, outcome("error", "invalid", "resource type does not match the endpoint")
        STORE[rtype][body["id"]] = body
        return 201, body
    return 405, outcome("error", "not-supported", "method not allowed")
